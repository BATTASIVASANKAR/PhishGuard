"""
PhishGuard — DNS & Hosting Information Service (v2 — production-ready)
Fetches comprehensive DNS records, IP geolocation, and hosting provider data.

Root-cause fixes vs. original:
  1. 'socket' import was imported but never used — removed.
  2. Python 3.10-only union syntax (str | None) replaced with Optional[str]
     from typing so the service runs on Python 3.8 / 3.9 as well.
  3. DMARC sub-domain query now runs inside the same ThreadPoolExecutor as
     all other record types — eliminating a serial delay at the end.
  4. Timeout increased: 5 s per-query / 10 s lifetime.
  5. Retry logic: 3 attempts with 0.5 s back-off on transient timeouts.
  6. Every record type always present in the result dict with 'Not Found'
     fallback so the frontend never receives a KeyError.
  7. Partial-error dict exposes per-type failure reasons to the UI.
"""

import time
import requests
import dns.resolver
import dns.reversename
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from config import REQUEST_TIMEOUT

# ── Constants ────────────────────────────────────────────────────────────────

DNS_TIMEOUT  = 5   # per-query timeout in seconds
DNS_LIFETIME = 10  # total resolver lifetime in seconds
DNS_RETRIES  = 3   # number of retry attempts per record type

# Record types to fetch and expose in the result
RECORD_TYPES = ('A', 'AAAA', 'MX', 'NS', 'TXT')


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_resolver() -> dns.resolver.Resolver:
    """Return a pre-configured dns.resolver.Resolver instance."""
    resolver = dns.resolver.Resolver()
    resolver.timeout  = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    # Use reliable public DNS servers as fallback
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
    return resolver


def _query_with_retry(
    resolver: dns.resolver.Resolver,
    qname: str,
    rdtype: str,
    retries: int = DNS_RETRIES,
) -> Tuple[List, Optional[str]]:
    """
    Query *qname* for *rdtype* with up to *retries* attempts.

    Returns (records_list, error_message).
    records_list is [] when nothing was found or an error occurred.
    error_message is None on success, or a short human-readable string.
    """
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            answers = resolver.resolve(qname, rdtype)
            return list(answers), None

        except dns.resolver.NXDOMAIN:
            return [], "Domain does not exist (NXDOMAIN)"

        except dns.resolver.NoAnswer:
            # Record type simply not published — not an error worth retrying
            return [], None

        except dns.resolver.NoNameservers:
            last_error = "No authoritative nameservers responded"
            # No point retrying if there are literally no nameservers
            break

        except dns.exception.Timeout:
            last_error = f"DNS query timed out (attempt {attempt}/{retries})"
            if attempt < retries:
                time.sleep(0.5)  # brief back-off before retry

        except Exception as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(0.3)

    return [], last_error


# ── Public API ───────────────────────────────────────────────────────────────

def get_dns_info(domain: str) -> dict:
    """Fetch comprehensive DNS and hosting information for a domain.

    Returns IP addresses, DNS records (A, AAAA, MX, NS, TXT), SPF/DMARC,
    hosting provider info, and server geolocation.

    Every record section is always present in the result dict.  If a record
    type could not be fetched it will be an empty list / None value, never
    absent, so the frontend can safely display "Not Found".
    """
    result = {
        'available': False,
        'domain': domain,

        # A / AAAA
        'ip_addresses':  [],      # A  records
        'ipv6_addresses': [],     # AAAA records
        'a_status':   'Not Found',
        'aaaa_status': 'Not Found',

        # Mail / Auth
        'mx_records':   [],
        'mx_status':    'Not Found',
        'spf_record':   None,
        'dmarc_record': None,

        # Name-servers
        'ns_records':   [],
        'ns_status':    'Not Found',

        # TXT (raw)
        'txt_records':  [],
        'txt_status':   'Not Found',

        # CNAME (queried on a best-effort basis, not always present)
        'cname_records': [],

        # Hosting / Geo
        'hosting_provider': None,
        'server_location':  None,
        'asn_info':         None,
        'reverse_dns':      None,

        # Risk signals
        'risk_flags': [],

        # Errors
        'error': None,
        'partial_errors': {},   # per-record-type errors for the UI
    }

    if not domain:
        result['error'] = 'No domain provided.'
        return result

    resolver = _make_resolver()

    # ── Query all record types concurrently (including DMARC sub-domain) ──────
    # DMARC is queried here in the pool rather than serially after the pool
    # closes — this saves up to DNS_LIFETIME seconds on slow nameservers.
    ALL_QUERIES = list(RECORD_TYPES) + ['DMARC']  # DMARC handled specially below

    def fetch(rdtype: str) -> Tuple[str, List, Optional[str]]:
        if rdtype == 'DMARC':
            # DMARC lives under _dmarc.<domain> as a TXT record
            records, err = _query_with_retry(resolver, f'_dmarc.{domain}', 'TXT')
        else:
            records, err = _query_with_retry(resolver, domain, rdtype)
        return rdtype, records, err

    raw: Dict[str, Tuple[List, Optional[str]]] = {}
    with ThreadPoolExecutor(max_workers=len(ALL_QUERIES)) as pool:
        futures = {pool.submit(fetch, rt): rt for rt in ALL_QUERIES}
        for future in as_completed(futures):
            try:
                rdtype, records, err = future.result()
                raw[rdtype] = (records, err)
            except Exception as exc:
                rt = futures[future]
                raw[rt] = ([], str(exc))

    # ── A Records ────────────────────────────────────────────────────────────
    a_records, a_err = raw.get('A', ([], 'Query not executed'))
    if a_records:
        result['ip_addresses'] = [str(r) for r in a_records]
        result['a_status'] = f"{len(a_records)} record(s) found"
        result['available'] = True
    else:
        result['a_status'] = 'Not Found'
        if a_err:
            result['partial_errors']['A'] = a_err

    # ── AAAA Records ─────────────────────────────────────────────────────────
    aaaa_records, aaaa_err = raw.get('AAAA', ([], None))
    if aaaa_records:
        result['ipv6_addresses'] = [str(r) for r in aaaa_records]
        result['aaaa_status'] = f"{len(aaaa_records)} record(s) found"
        result['available'] = True
    else:
        result['aaaa_status'] = 'Not Found'
        if aaaa_err:
            result['partial_errors']['AAAA'] = aaaa_err

    # ── MX Records ───────────────────────────────────────────────────────────
    mx_records, mx_err = raw.get('MX', ([], None))
    if mx_records:
        result['mx_records'] = [
            {'priority': r.preference, 'host': str(r.exchange).rstrip('.')}
            for r in mx_records
        ]
        result['mx_status'] = f"{len(mx_records)} record(s) found"
    else:
        result['mx_status'] = 'Not Found'
        result['risk_flags'].append('No MX records — domain may not handle email')
        if mx_err:
            result['partial_errors']['MX'] = mx_err

    # ── NS Records ───────────────────────────────────────────────────────────
    ns_records, ns_err = raw.get('NS', ([], None))
    if ns_records:
        result['ns_records'] = [str(r).rstrip('.') for r in ns_records]
        result['ns_status'] = f"{len(ns_records)} record(s) found"
    else:
        result['ns_status'] = 'Not Found'
        result['risk_flags'].append('No authoritative nameservers found')
        if ns_err:
            result['partial_errors']['NS'] = ns_err

    # ── TXT Records (+ SPF extraction) ───────────────────────────────────────
    txt_records, txt_err = raw.get('TXT', ([], None))
    if txt_records:
        result['txt_records'] = [str(r).strip('"') for r in txt_records]
        result['txt_status'] = f"{len(txt_records)} record(s) found"

        for txt in result['txt_records']:
            if txt.lower().startswith('v=spf1'):
                result['spf_record'] = txt
                break

        if not result['spf_record']:
            result['risk_flags'].append('No SPF record — email spoofing possible')
    else:
        result['txt_status'] = 'Not Found'
        result['risk_flags'].append('No TXT records found')
        if txt_err:
            result['partial_errors']['TXT'] = txt_err

    # ── DMARC — already fetched concurrently above ───────────────────────────
    dmarc_rrs, _ = raw.get('DMARC', ([], None))
    for r in dmarc_rrs:
        txt = str(r).strip('"')
        if txt.lower().startswith('v=dmarc1'):
            result['dmarc_record'] = txt
            break

    # ── CNAME (best-effort — many apex domains won't have one) ───────────────
    cname_rrs, _ = _query_with_retry(resolver, domain, 'CNAME', retries=1)
    result['cname_records'] = [str(r).rstrip('.') for r in cname_rrs]

    # ── Reverse DNS ──────────────────────────────────────────────────────────
    if result['ip_addresses']:
        try:
            primary_ip = result['ip_addresses'][0]
            rev_name   = dns.reversename.from_address(primary_ip)
            ptr_rrs, _ = _query_with_retry(resolver, str(rev_name), 'PTR', retries=2)
            if ptr_rrs:
                result['reverse_dns'] = str(ptr_rrs[0]).rstrip('.')
        except Exception:
            pass  # reverse DNS is purely informational

    # ── IP Geolocation & Hosting Provider ────────────────────────────────────
    if result['ip_addresses']:
        try:
            primary_ip = result['ip_addresses'][0]
            geo_resp = requests.get(
                f'http://ip-api.com/json/{primary_ip}',
                timeout=min(REQUEST_TIMEOUT, 5),
                params={
                    'fields': 'status,country,countryCode,regionName,city,isp,org,as,hosting'
                },
            )
            if geo_resp.status_code == 200:
                geo = geo_resp.json()
                if geo.get('status') == 'success':
                    result['server_location'] = {
                        'country':      geo.get('country', 'Unknown'),
                        'country_code': geo.get('countryCode', ''),
                        'region':       geo.get('regionName', ''),
                        'city':         geo.get('city', ''),
                    }
                    result['hosting_provider'] = geo.get('isp', 'Unknown')
                    result['asn_info'] = {
                        'asn':        geo.get('as', ''),
                        'org':        geo.get('org', ''),
                        'is_hosting': geo.get('hosting', False),
                    }

                    if geo.get('hosting'):
                        result['risk_flags'].append(
                            'Server is in a hosting / datacenter environment'
                        )
        except requests.exceptions.Timeout:
            result['partial_errors']['geo'] = 'Geolocation lookup timed out'
        except Exception as exc:
            result['partial_errors']['geo'] = f'Geolocation error: {str(exc)}'

    # ── Final error message if nothing at all was resolved ───────────────────
    if not result['available']:
        # Build a concise, readable error for the dashboard
        primary_cause = (
            result['partial_errors'].get('A')
            or result['partial_errors'].get('AAAA')
            or 'Could not resolve any DNS records for this domain.'
        )
        result['error'] = primary_cause

    return result
