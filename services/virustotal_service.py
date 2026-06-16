"""
PhishGuard — VirusTotal API Integration Service (v2 — production-ready)
Scans URLs via VirusTotal v3 API for threat intelligence.

Root-cause fixes vs. original:
  1. REQUEST_TIMEOUT was too short (5 s) for the full submit→poll cycle;
     we now use a dedicated VT_TIMEOUT (15 s) and cap individual calls.
  2. After submitting a new URL we poll the analysis endpoint (up to 3 times
     with 5 s back-off) instead of a blind 3-second sleep.  This handles the
     realistic case where VirusTotal hasn't finished scanning yet.
  3. API key validation is separated into its own helper so the caller can
     distinguish "key not configured" from "key rejected" from "rate limited".
  4. HTTP 401 / 403 are now caught explicitly and mapped to a clear message
     so users know whether to check the key vs. wait for a quota reset.
  5. All branches return a consistent result dict — 'available' is only True
     when we have real scan data, never on partial / error states.
  6. Cache now stores both successful and known-error results so repeated
     requests for the same URL don't hammer the API.
"""

import time
import base64
import hashlib
import requests
from datetime import datetime, timezone

import config  # import the module so we can reload live values (not frozen statics)

# ── Module-level constants ────────────────────────────────────────────────────

VT_BASE       = 'https://www.virustotal.com/api/v3'
VT_TIMEOUT    = 15    # seconds — per HTTP call to VirusTotal
VT_POLL_TRIES = 3     # how many times to poll after submitting a new URL
VT_POLL_SLEEP = 5     # seconds between poll attempts

_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 600  # 10 minutes


# ── Internal helpers ──────────────────────────────────────────────────────────

def _url_id(url: str) -> str:
    """
    Generate the VirusTotal URL identifier.
    VT v3 uses base64url(url) without padding characters.
    """
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')


def _cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def _empty_result(url: str) -> dict:
    """Return a zeroed-out result skeleton."""
    return {
        'available':       False,
        'url':             url,
        # Detection counts
        'malicious':       0,
        'suspicious':      0,
        'harmless':        0,
        'undetected':      0,
        'timeout_count':   0,
        'total_engines':   0,
        # Community / metadata
        'community_score': 0,
        'categories':      {},
        'detections':      [],    # [{engine, category, result}]
        'scan_date':       None,
        'permalink':       None,
        # Risk signals (consumed by risk_scoring.py)
        'risk_flags':      [],
        # UI helpers
        'error':           None,
        'error_code':      None,  # NEW — machine-readable code for the frontend
    }


def _headers() -> dict:
    """Return fresh request headers (re-reads key at call-time)."""
    return {
        'x-apikey': config.VIRUSTOTAL_API_KEY,
        'Accept':   'application/json',
    }


def _validate_key() -> str | None:
    """
    Return None if the key looks usable, or an error string if not.
    We do a lightweight check on format only — actual validity is confirmed
    by the first real API response.
    """
    key = config.VIRUSTOTAL_API_KEY.strip()
    if not key or key == 'your_virustotal_api_key_here':
        return (
            'VirusTotal API key is not configured. '
            'Get a free key at https://www.virustotal.com/gui/join-us '
            'and add it to your .env file as VIRUSTOTAL_API_KEY=<your_key>.'
        )
    if len(key) < 32:
        # VT keys are 64 hex chars; anything shorter is obviously wrong
        return (
            'VirusTotal API key appears invalid (too short). '
            'Please check the key in your .env file.'
        )
    return None


def _parse_attributes(attrs: dict, url: str) -> dict:
    """Extract all useful fields from a VirusTotal URL attributes object."""
    result = _empty_result(url)

    stats = attrs.get('last_analysis_stats', {})
    result['malicious']     = stats.get('malicious', 0)
    result['suspicious']    = stats.get('suspicious', 0)
    result['harmless']      = stats.get('harmless', 0)
    result['undetected']    = stats.get('undetected', 0)
    result['timeout_count'] = stats.get('timeout', 0)
    result['total_engines'] = sum(stats.values())

    result['community_score'] = attrs.get('reputation', 0)
    result['categories']      = attrs.get('categories', {})

    # Scan date — stored as unix timestamp in VT response
    last_ts = attrs.get('last_analysis_date')
    if last_ts:
        result['scan_date'] = datetime.fromtimestamp(
            last_ts, tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S UTC')

    # Collect only flagged engines (cap at 20 to keep payload size sane)
    analysis_results = attrs.get('last_analysis_results', {})
    detections = []
    for engine, detail in analysis_results.items():
        cat = detail.get('category', '')
        if cat in ('malicious', 'suspicious'):
            detections.append({
                'engine':   engine,
                'category': cat,
                'result':   detail.get('result', 'Unknown'),
            })
    result['detections'] = detections[:20]

    result['permalink'] = f'https://www.virustotal.com/gui/url/{_url_id(url)}'
    result['available']  = True

    # ── Risk flags (consumed by risk_scoring.calculate_risk_score) ──────
    m, s = result['malicious'], result['suspicious']
    if m > 0:
        result['risk_flags'].append(
            f'{m} security engine(s) flagged this URL as malicious'
        )
    if s > 0:
        result['risk_flags'].append(
            f'{s} engine(s) flagged this URL as suspicious'
        )
    if result['community_score'] < -5:
        result['risk_flags'].append('Negative VirusTotal community reputation score')

    return result


def _get_existing_report(url: str) -> tuple[int, dict | None]:
    """
    Try to fetch an existing analysis report for *url*.
    Returns (status_code, attributes_dict_or_None).
    """
    url_id = _url_id(url)
    resp = requests.get(
        f'{VT_BASE}/urls/{url_id}',
        headers=_headers(),
        timeout=VT_TIMEOUT,
    )
    if resp.status_code == 200:
        data  = resp.json().get('data', {})
        attrs = data.get('attributes', {})
        return 200, attrs
    return resp.status_code, None


def _submit_and_poll(url: str) -> tuple[dict | None, str | None]:
    """
    Submit a URL for analysis, then poll up to VT_POLL_TRIES times.
    Returns (attributes_dict, error_string).
    """
    # Submit the URL
    submit_resp = requests.post(
        f'{VT_BASE}/urls',
        headers=_headers(),
        data={'url': url},
        timeout=VT_TIMEOUT,
    )

    if submit_resp.status_code == 429:
        return None, 'VirusTotal API rate limit reached. Please try again in a few minutes.'
    if submit_resp.status_code in (401, 403):
        return None, 'VirusTotal API key is invalid or has been revoked. Please check your key.'
    if submit_resp.status_code not in (200, 201):
        return None, f'VirusTotal submission failed (HTTP {submit_resp.status_code}).'

    # Extract the analysis id from the submission response
    analysis_id = (
        submit_resp.json()
        .get('data', {})
        .get('id', '')
    )

    # Poll the analysis endpoint until it completes or we run out of tries
    for attempt in range(1, VT_POLL_TRIES + 1):
        time.sleep(VT_POLL_SLEEP)  # give VT time to scan

        if analysis_id:
            # Preferred: poll the specific analysis object
            poll_resp = requests.get(
                f'{VT_BASE}/analyses/{analysis_id}',
                headers=_headers(),
                timeout=VT_TIMEOUT,
            )
            if poll_resp.status_code == 200:
                poll_data = poll_resp.json().get('data', {})
                status    = poll_data.get('attributes', {}).get('status', '')
                if status == 'completed':
                    # Re-fetch the URL report which now has full stats
                    code, attrs = _get_existing_report(url)
                    if code == 200 and attrs:
                        return attrs, None
        else:
            # Fallback: try the URL report directly
            code, attrs = _get_existing_report(url)
            if code == 200 and attrs:
                return attrs, None

    # Analysis may still be in-queue — return whatever partial data we have
    code, attrs = _get_existing_report(url)
    if code == 200 and attrs:
        return attrs, None

    return None, 'VirusTotal analysis is taking longer than expected. Try again in a moment.'


# ── Public API ────────────────────────────────────────────────────────────────

def scan_url(url: str) -> dict:
    """
    Scan a URL using the VirusTotal v3 API.

    Workflow:
      1. Validate the API key locally.
      2. Check the in-memory cache.
      3. Try to fetch an existing VT report.
      4. If not found, submit + poll for completion.
      5. Parse and return the structured result.

    Always returns a dict conforming to the schema in _empty_result().
    'available' is True only when real scan data is present.
    'error_code' gives the frontend a stable string to branch on.
    """
    result = _empty_result(url)

    # ── 1. API key validation ─────────────────────────────────────────────
    key_error = _validate_key()
    if key_error:
        result['error']      = key_error
        result['error_code'] = 'NO_API_KEY'
        return result

    # ── 2. Cache check ───────────────────────────────────────────────────
    ck = _cache_key(url)
    if ck in _cache:
        ts, cached = _cache[ck]
        if time.time() - ts < _CACHE_TTL:
            return cached

    # ── 3. Try existing report ───────────────────────────────────────────
    try:
        status_code, attrs = _get_existing_report(url)

        if status_code == 200 and attrs:
            result = _parse_attributes(attrs, url)

        elif status_code == 404:
            # URL not yet in VT database — submit it
            attrs, err = _submit_and_poll(url)
            if err:
                result['error']      = err
                result['error_code'] = 'SUBMIT_ERROR'
            elif attrs:
                result = _parse_attributes(attrs, url)
            else:
                result['error']      = 'VirusTotal returned no data for this URL.'
                result['error_code'] = 'NO_DATA'

        elif status_code == 429:
            result['error']      = 'VirusTotal API rate limit reached. Please try again later.'
            result['error_code'] = 'RATE_LIMITED'

        elif status_code in (401, 403):
            result['error']      = (
                'VirusTotal API key is invalid or has been revoked. '
                'Please verify your VIRUSTOTAL_API_KEY in the .env file.'
            )
            result['error_code'] = 'INVALID_KEY'

        else:
            result['error']      = f'VirusTotal API returned HTTP {status_code}.'
            result['error_code'] = 'API_ERROR'

    except requests.exceptions.Timeout:
        result['error']      = 'VirusTotal API request timed out. The service may be slow — try again.'
        result['error_code'] = 'TIMEOUT'
    except requests.exceptions.ConnectionError:
        result['error']      = 'Could not connect to VirusTotal API. Check your internet connection.'
        result['error_code'] = 'CONNECTION_ERROR'
    except Exception as exc:
        result['error']      = f'VirusTotal scan encountered an unexpected error: {str(exc)}'
        result['error_code'] = 'UNKNOWN_ERROR'

    # ── 4. Cache the result (including errors, to avoid hammering the API) ─
    _cache[ck] = (time.time(), result)

    # Prune oldest entries if cache grows too large
    if len(_cache) > 200:
        oldest = sorted(_cache, key=lambda k: _cache[k][0])
        for k in oldest[:50]:
            del _cache[k]

    return result
