"""
PhishGuard — Flask Web Application for Phishing Detection & Website Intelligence
Uses ML model for URL scanning, heuristic analysis for email scanning,
and integrates WHOIS, SSL, DNS, VirusTotal, and tech detection services.
Enhanced with composite risk scoring and PDF report generation.
"""

import os
import uuid
import pickle
import re
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

import numpy as np
from flask import Flask, render_template, request, jsonify, send_file

import config
from services.whois_service import get_whois_info
from services.ssl_service import get_ssl_info
from services.virustotal_service import scan_url as vt_scan_url
from services.dns_service import get_dns_info
from services.tech_detect_service import detect_technologies
from services.risk_scoring import calculate_risk_score
from services.pdf_report import generate_report

# ── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Load ML model
try:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _base_dir = os.getcwd()
MODEL_PATH = os.path.join(_base_dir, 'model.pkl')
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

# In-memory scan result cache for PDF report generation
_scan_cache: dict[str, dict] = {}
_SCAN_CACHE_MAX = config.SCAN_CACHE_MAX_SIZE


# ── URL Validation ──────────────────────────────────────────────────────────

_URL_REGEX = re.compile(
    r'^https?://'                       # scheme
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*'  # subdomains
    r'(?:[A-Za-z]{2,}|'                 # TLD  OR
    r'\d{1,3}(?:\.\d{1,3}){3})'         # IPv4
    r'(?::\d+)?'                        # optional port
    r'(?:/[^\s]*)?$',                   # path
    re.IGNORECASE,
)


def validate_url(url: str) -> tuple[bool, str]:
    """Return (is_valid, error_message)."""
    if not url:
        return False, 'Please enter a URL to scan.'

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    if not _URL_REGEX.match(url):
        return False, 'Invalid URL format. Please enter a valid website URL (e.g. https://example.com).'

    return True, ''


# ── Feature Extraction (URL) ────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm',
    'password', 'signin', 'credential', 'suspend', 'alert', 'expire',
    'unusual', 'restrict', 'wallet', 'paypal', 'ebay', 'apple', 'microsoft'
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy'
]


def extract_features(url: str) -> list:
    """Extract numeric features from a URL string."""
    url_lower = url.lower()

    features = [
        len(url),                                                               # 0: length
        url_lower.count('.'),                                                   # 1: dot count
        url_lower.count('-'),                                                   # 2: dash count
        url_lower.count('@'),                                                   # 3: @ symbol
        url_lower.count('//'),                                                  # 4: double-slash count
        1 if 'https' in url_lower else 0,                                       # 5: has https
        1 if any(c.isdigit() for c in url_lower.split('/')[2]                   # 6: digits in domain
              if len(url_lower.split('/')) > 2) else 0,
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),               # 7: suspicious keywords
        1 if any(sd in url_lower for sd in SHORTENER_DOMAINS) else 0,           # 8: shortener
        url_lower.count('/'),                                                   # 9: slash count
        url_lower.count('?'),                                                   # 10: query params
        url_lower.count('='),                                                   # 11: equals signs
        len(url_lower.split('/')[2]) if len(url_lower.split('/')) > 2           # 12: domain length
            else len(url_lower),
        1 if url_lower.count('.') > 4 else 0,                                  # 13: many subdomains
    ]
    return features


# ── URL Pattern Analysis ────────────────────────────────────────────────────

_IP_DOMAIN_RE = re.compile(r'^https?://\d{1,3}(\.\d{1,3}){3}', re.IGNORECASE)


def analyze_url_patterns(url: str, https_enabled: bool = None) -> dict:
    """Detect suspicious URL patterns and compute a heuristic risk score."""
    url_lower = url.lower()
    findings = []
    score = 0

    # 1. IP-based URL
    if _IP_DOMAIN_RE.match(url):
        findings.append('IP address used instead of domain name')
        score += 3

    # 2. Very long URL (>75 chars)
    if len(url) > 75:
        findings.append(f'Unusually long URL ({len(url)} characters)')
        score += 2

    # 3. @ symbol in URL (credential trick)
    if '@' in url:
        findings.append('"@" symbol detected — may redirect to a different site')
        score += 3

    # 4. Excessive dashes in domain
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    if hostname.count('-') >= 3:
        findings.append(f'Excessive dashes in domain ({hostname.count("-")} found)')
        score += 2

    # 5. Many subdomains (>3 dots in hostname)
    if hostname.count('.') > 3:
        findings.append(f'Excessive subdomains ({hostname.count(".") + 1} levels)')
        score += 2

    # 6. URL shortener
    if any(sd in url_lower for sd in SHORTENER_DOMAINS):
        findings.append('URL shortener detected — destination is hidden')
        score += 2

    # 7. HTTPS / SSL status
    if https_enabled is None:
        https_enabled = url_lower.startswith('https://')

    if https_enabled:
        findings.append('HTTPS encryption enabled')
        findings.append('Secure SSL/TLS connection detected')
    else:
        findings.append('No HTTPS encryption — connection is not secure')
        score += 1

    # 8. Suspicious keywords in URL
    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_kw:
        findings.append(f'Suspicious keywords: {", ".join(matched_kw)}')
        score += min(len(matched_kw), 3)

    # 9. Suspicious characters
    special_chars = url_lower.count('%') + url_lower.count('~') + url_lower.count('^')
    if special_chars > 2:
        findings.append('Unusual encoded or special characters detected')
        score += 1

    return {'findings': findings, 'score': min(score, 10)}


def compute_url_risk(ml_phishing: bool, pattern_score: int) -> tuple[str, str]:
    """Combine ML prediction with pattern score to produce risk level and explanation."""
    if ml_phishing and pattern_score >= 4:
        return 'High', (
            'Both the ML model and pattern analysis flagged this URL as highly suspicious. '
            'Multiple phishing indicators were detected. Avoid visiting this site.'
        )
    if ml_phishing:
        return 'High', (
            'The ML model identified this URL as a phishing attempt. '
            'Exercise extreme caution and do not enter any personal information.'
        )
    if pattern_score >= 6:
        return 'High', (
            'Multiple suspicious patterns were detected in this URL. '
            'Although the ML model did not flag it, the URL exhibits high-risk characteristics.'
        )
    if pattern_score >= 3:
        return 'Medium', (
            'Some suspicious patterns were found in this URL. '
            'Proceed with caution and verify the site\'s legitimacy before entering any data.'
        )
    if pattern_score >= 1:
        return 'Low', (
            'Minor concerns were noted but the URL appears mostly safe. '
            'Always verify the source before sharing personal information.'
        )
    return 'Low', (
        'No significant threats were detected. '
        'This URL appears to be legitimate based on our analysis.'
    )


# ── Email Intelligence & Phishing Detection ─────────────────────────────────

# Known companies: keyword -> (official_domain, company_name, website_url)
KNOWN_COMPANIES = {
    'microsoft': ('microsoft.com', 'Microsoft', 'https://www.microsoft.com'),
    'google': ('google.com', 'Google', 'https://www.google.com'),
    'gmail': ('google.com', 'Google', 'https://www.google.com'),
    'paypal': ('paypal.com', 'PayPal', 'https://www.paypal.com'),
    'amazon': ('amazon.com', 'Amazon', 'https://www.amazon.com'),
    'apple': ('apple.com', 'Apple', 'https://www.apple.com'),
    'icloud': ('apple.com', 'Apple', 'https://www.apple.com'),
    'facebook': ('facebook.com', 'Meta (Facebook)', 'https://www.facebook.com'),
    'meta': ('meta.com', 'Meta', 'https://www.meta.com'),
    'instagram': ('instagram.com', 'Instagram (Meta)', 'https://www.instagram.com'),
    'whatsapp': ('whatsapp.com', 'WhatsApp (Meta)', 'https://www.whatsapp.com'),
    'netflix': ('netflix.com', 'Netflix', 'https://www.netflix.com'),
    'twitter': ('twitter.com', 'Twitter / X', 'https://www.twitter.com'),
    'linkedin': ('linkedin.com', 'LinkedIn', 'https://www.linkedin.com'),
    'dropbox': ('dropbox.com', 'Dropbox', 'https://www.dropbox.com'),
    'spotify': ('spotify.com', 'Spotify', 'https://www.spotify.com'),
    'adobe': ('adobe.com', 'Adobe', 'https://www.adobe.com'),
    'salesforce': ('salesforce.com', 'Salesforce', 'https://www.salesforce.com'),
    'oracle': ('oracle.com', 'Oracle', 'https://www.oracle.com'),
    'cisco': ('cisco.com', 'Cisco', 'https://www.cisco.com'),
    'intel': ('intel.com', 'Intel', 'https://www.intel.com'),
    'ibm': ('ibm.com', 'IBM', 'https://www.ibm.com'),
    'samsung': ('samsung.com', 'Samsung', 'https://www.samsung.com'),
    'sony': ('sony.com', 'Sony', 'https://www.sony.com'),
    'nvidia': ('nvidia.com', 'NVIDIA', 'https://www.nvidia.com'),
    'tesla': ('tesla.com', 'Tesla', 'https://www.tesla.com'),
    'uber': ('uber.com', 'Uber', 'https://www.uber.com'),
    'airbnb': ('airbnb.com', 'Airbnb', 'https://www.airbnb.com'),
    'zoom': ('zoom.us', 'Zoom', 'https://www.zoom.us'),
    'slack': ('slack.com', 'Slack', 'https://www.slack.com'),
    'github': ('github.com', 'GitHub', 'https://www.github.com'),
    'stripe': ('stripe.com', 'Stripe', 'https://www.stripe.com'),
    'shopify': ('shopify.com', 'Shopify', 'https://www.shopify.com'),
    'ebay': ('ebay.com', 'eBay', 'https://www.ebay.com'),
    'walmart': ('walmart.com', 'Walmart', 'https://www.walmart.com'),
    'target': ('target.com', 'Target', 'https://www.target.com'),
    'chase': ('chase.com', 'Chase Bank', 'https://www.chase.com'),
    'wellsfargo': ('wellsfargo.com', 'Wells Fargo', 'https://www.wellsfargo.com'),
    'bankofamerica': ('bankofamerica.com', 'Bank of America', 'https://www.bankofamerica.com'),
    'citibank': ('citibank.com', 'Citibank', 'https://www.citibank.com'),
    'hsbc': ('hsbc.com', 'HSBC', 'https://www.hsbc.com'),
    'barclays': ('barclays.com', 'Barclays', 'https://www.barclays.com'),
    'americanexpress': ('americanexpress.com', 'American Express', 'https://www.americanexpress.com'),
    'amex': ('americanexpress.com', 'American Express', 'https://www.americanexpress.com'),
    'visa': ('visa.com', 'Visa', 'https://www.visa.com'),
    'mastercard': ('mastercard.com', 'Mastercard', 'https://www.mastercard.com'),
    'dhl': ('dhl.com', 'DHL', 'https://www.dhl.com'),
    'fedex': ('fedex.com', 'FedEx', 'https://www.fedex.com'),
    'ups': ('ups.com', 'UPS', 'https://www.ups.com'),
    'twitch': ('twitch.tv', 'Twitch', 'https://www.twitch.tv'),
    'discord': ('discord.com', 'Discord', 'https://www.discord.com'),
    'tiktok': ('tiktok.com', 'TikTok', 'https://www.tiktok.com'),
    'snapchat': ('snapchat.com', 'Snapchat', 'https://www.snapchat.com'),
    'pinterest': ('pinterest.com', 'Pinterest', 'https://www.pinterest.com'),
    'reddit': ('reddit.com', 'Reddit', 'https://www.reddit.com'),
    'yahoo': ('yahoo.com', 'Yahoo', 'https://www.yahoo.com'),
    'outlook': ('microsoft.com', 'Microsoft', 'https://www.microsoft.com'),
    'hotmail': ('microsoft.com', 'Microsoft', 'https://www.microsoft.com'),
    'live': ('microsoft.com', 'Microsoft', 'https://www.microsoft.com'),
}

PUBLIC_EMAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.in',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'protonmail.com', 'proton.me', 'aol.com', 'icloud.com',
    'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru',
    'gmx.com', 'gmx.net', 'tutanota.com', 'fastmail.com',
    'inbox.com', 'rediffmail.com', 'mail.ru',
}

# Common character substitutions used in typo-squatting
TYPO_SUBSTITUTIONS = {
    'rn': 'm', '0': 'o', '1': 'l', 'vv': 'w', '5': 's',
    'ii': 'u', 'cl': 'd', 'nn': 'm', 'l': 'i', 'i': 'l',
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _apply_typo_corrections(text: str) -> str:
    """Apply known typo-squatting character substitutions to normalise text."""
    corrected = text.lower()
    # Apply multi-char substitutions first (order matters)
    for fake, real in sorted(TYPO_SUBSTITUTIONS.items(), key=lambda x: -len(x[0])):
        corrected = corrected.replace(fake, real)
    return corrected


def parse_email_address(email: str) -> tuple[bool, str, str, str]:
    """Validate and parse an email address.
    Returns (is_valid, error_msg, username, domain).
    """
    email = email.strip().lower()
    email_regex = re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    )
    if not email_regex.match(email):
        return False, 'Invalid email format. Please enter a valid email address (e.g. user@example.com).', '', ''
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    return True, '', username, domain


def detect_typo_squatting(text: str) -> dict | None:
    """Check if text resembles a known company via typo-squatting.
    Returns match info dict or None.
    """
    text_lower = text.lower()
    corrected = _apply_typo_corrections(text_lower)

    best_match = None
    best_distance = float('inf')

    for keyword, (official_domain, company_name, website) in KNOWN_COMPANIES.items():
        # Skip very short keywords to avoid false positives
        if len(keyword) < 4:
            continue

        # Only match if the original text is NOT an exact match
        # (exact match is handled by direct lookup)
        if text_lower == keyword:
            continue

        # Length ratio check: reject if lengths differ too much
        len_ratio = len(text_lower) / len(keyword) if len(keyword) > 0 else 0
        if len_ratio < 0.7 or len_ratio > 1.4:
            continue

        # Check corrected text
        dist_corrected = _levenshtein_distance(corrected, keyword)
        dist_original = _levenshtein_distance(text_lower, keyword)

        # Adaptive threshold: stricter for short keywords
        if len(keyword) <= 5:
            threshold = 1
            # For short keywords, only match via char substitution correction
            if dist_corrected != 0 and dist_original > 1:
                continue
        else:
            threshold = 2

        # Match if corrected text matches exactly, or distance is within threshold
        if dist_corrected == 0 or dist_original <= threshold:
            effective_dist = min(dist_corrected, dist_original)
            if effective_dist < best_distance:
                best_distance = effective_dist
                best_match = {
                    'target_company': company_name,
                    'official_domain': official_domain,
                    'website': website,
                    'similarity_type': 'character_substitution' if dist_corrected == 0 else 'typo_squatting',
                    'original_text': text_lower,
                    'matched_keyword': keyword,
                }

    return best_match


def analyze_email_address(email: str) -> dict:
    """Full email address intelligence analysis."""
    is_valid, error_msg, username, domain = parse_email_address(email)
    if not is_valid:
        return {'error': error_msg}

    # Determine provider
    is_public = domain in PUBLIC_EMAIL_PROVIDERS
    if is_public:
        provider_names = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'yahoo.co.uk': 'Yahoo Mail',
            'yahoo.co.in': 'Yahoo Mail',
            'outlook.com': 'Outlook',
            'hotmail.com': 'Hotmail (Microsoft)',
            'live.com': 'Live (Microsoft)',
            'msn.com': 'MSN (Microsoft)',
            'protonmail.com': 'ProtonMail',
            'proton.me': 'Proton Mail',
            'aol.com': 'AOL',
            'icloud.com': 'iCloud (Apple)',
            'mail.com': 'Mail.com',
            'zoho.com': 'Zoho Mail',
            'yandex.com': 'Yandex Mail',
            'yandex.ru': 'Yandex Mail',
            'gmx.com': 'GMX Mail',
            'gmx.net': 'GMX Mail',
            'tutanota.com': 'Tutanota',
            'fastmail.com': 'Fastmail',
            'rediffmail.com': 'Rediffmail',
            'mail.ru': 'Mail.ru',
        }
        provider = provider_names.get(domain, domain.split('.')[0].title())
    else:
        provider = domain.split('.')[0].title()

    # Get Domain Creation Date using WHOIS
    whois_info = get_whois_info(domain)
    creation_date = whois_info.get('creation_date') or 'Not Available'

    result = {
        'email': f'{username}@{domain}',
        'username': username,
        'provider': provider,
        'creation_date': creation_date,
    }

    return result


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    """Render the homepage."""
    return render_template('index.html')


@app.route('/url-scanner')
def url_scanner():
    """Render the URL scanner page."""
    return render_template('url_scanner.html')


@app.route('/scan-url', methods=['POST'])
def scan_url():
    """Legacy: Scan a URL for phishing indicators using ML model + pattern analysis."""
    url = request.form.get('url', '').strip()

    # ── Validation ──
    if not url:
        return render_template('url_scanner.html', error='Please enter a URL to scan.')

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    is_valid, error_msg = validate_url(url)
    if not is_valid:
        return render_template('url_scanner.html', error=error_msg)

    # ── Analysis ──
    try:
        # ML prediction
        features = extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        ml_phishing = bool(prediction == 1)

        # Pattern analysis
        patterns = analyze_url_patterns(url)
        pattern_score = patterns['score']
        findings = patterns['findings']

        # Combined risk assessment
        is_phishing = ml_phishing or pattern_score >= 6
        risk_level, explanation = compute_url_risk(ml_phishing, pattern_score)

    except Exception as e:
        return render_template(
            'url_scanner.html',
            error=f'An error occurred while scanning the URL. Please try again.'
        )

    return render_template(
        'result.html',
        url=url,
        is_phishing=is_phishing,
        risk_level=risk_level,
        explanation=explanation,
        findings=findings,
    )


# ── New API Endpoints ────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Full website intelligence scan. Runs all services concurrently and
    returns a comprehensive JSON report.
    """
    try:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'Please provide a URL to scan.'}), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        is_valid, error_msg = validate_url(url)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        # Extract domain/hostname
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        domain = hostname

        # ── ML Analysis ──────────────────────────────────────────────────────
        try:
            features = extract_features(url)
            features_array = np.array(features).reshape(1, -1)
            prediction = model.predict(features_array)[0]
            ml_phishing = bool(prediction == 1)
        except Exception:
            ml_phishing = False

        # ── Pattern Analysis ─────────────────────────────────────────────────
        patterns = analyze_url_patterns(url)

        # ── Run Intelligence Services Concurrently ───────────────────────────
        results = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(get_whois_info, domain): 'whois',
                executor.submit(get_ssl_info, hostname): 'ssl',
                executor.submit(vt_scan_url, url): 'virustotal',
                executor.submit(get_dns_info, domain): 'dns',
                executor.submit(detect_technologies, url): 'technologies',
            }

            done, not_done = wait(futures.keys(), timeout=min(config.REQUEST_TIMEOUT * 2, 12))

            for future in done:
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    results[key] = {'available': False, 'error': str(e)}

        # Fill in any missing results
        for key in ('whois', 'ssl', 'virustotal', 'dns', 'technologies'):
            if key not in results:
                results[key] = {'available': False, 'error': 'Service timed out'}

        # ── Determine HTTPS Status & Enforce Consistency ─────────────────────
        ssl_data = results.get('ssl', {})
        tech_data = results.get('technologies', {})

        # Check if SSL connection was successful
        ssl_success = ssl_data.get('available', False) and ssl_data.get('status') != 'no_ssl'

        # Check if HTTPS was detected by tech service
        tech_https = False
        if tech_data.get('available'):
            tech_https = any(t.get('name') == 'HTTPS' for t in tech_data.get('technologies', []))

        # Check if initial URL started with https://
        url_https = url.lower().startswith('https://')

        # Unified HTTPS enabled status
        https_enabled = url_https or ssl_success or tech_https

        # Alignment 1: Technology Stack
        if tech_data.get('available'):
            tech_list = tech_data.setdefault('technologies', [])
            has_https_tech = any(t.get('name') == 'HTTPS' for t in tech_list)
            
            if https_enabled and not has_https_tech:
                # Add HTTPS
                tech_list.append({'name': 'HTTPS', 'category': 'Security'})
                # Re-sort technologies by category order
                category_order = [
                    'Web Server', 'CDN', 'Language', 'Framework', 'CMS',
                    'E-Commerce', 'Website Builder', 'Static Site Generator',
                    'JS Framework', 'JS Library', 'CSS Framework', 'Icon Library',
                    'Analytics', 'Security', 'Hosting', 'Platform',
                ]
                order_map = {c: i for i, c in enumerate(category_order)}
                tech_list.sort(key=lambda t: order_map.get(t['category'], 99))
            elif not https_enabled and has_https_tech:
                # Remove HTTPS
                tech_data['technologies'] = [t for t in tech_list if t.get('name') != 'HTTPS']

        # Alignment 2: SSL Certificate Status
        if not https_enabled:
            # Enforce that no_ssl is set if HTTPS is not enabled
            results['ssl']['available'] = False
            results['ssl']['status'] = 'no_ssl'
            results['ssl']['is_valid'] = False
        else:
            # Enforce that status is not no_ssl if HTTPS is enabled
            if results['ssl'].get('status') == 'no_ssl' or not results['ssl'].get('available'):
                results['ssl']['available'] = True
                results['ssl']['status'] = 'invalid'
                results['ssl']['error'] = results['ssl'].get('error') or 'SSL certificate could not be fully verified.'

        # Re-run pattern analysis with the consolidated HTTPS status
        patterns = analyze_url_patterns(url, https_enabled=https_enabled)

        # ── Risk Score ───────────────────────────────────────────────────────
        risk_score = calculate_risk_score(
            ml_phishing=ml_phishing,
            pattern_score=patterns['score'],
            whois_data=results['whois'],
            ssl_data=results['ssl'],
            vt_data=results['virustotal'],
            dns_data=results['dns'],
        )

        # ── Build Response ───────────────────────────────────────────────────
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        response = {
            'url': url,
            'domain': domain,
            'timestamp': timestamp,
            'scan_id': scan_id,
            'ml_analysis': {
                'is_phishing': ml_phishing,
                'features': features,
            },
            'url_patterns': patterns,
            'whois': results['whois'],
            'ssl': results['ssl'],
            'virustotal': results['virustotal'],
            'dns': results['dns'],
            'technologies': results['technologies'],
            'risk_score': risk_score,
        }

        # Cache for PDF generation
        _scan_cache[scan_id] = response
        # Prune cache
        if len(_scan_cache) > _SCAN_CACHE_MAX:
            oldest_keys = list(_scan_cache.keys())[: len(_scan_cache) - _SCAN_CACHE_MAX]
            for k in oldest_keys:
                del _scan_cache[k]

        return jsonify(response)
    except Exception as e:
        return jsonify({'error': f"Internal Server Error: {str(e)}"}), 500


@app.route('/api/report/<scan_id>')
def api_report(scan_id):
    """Generate and download a PDF security report for a completed scan."""
    scan_data = _scan_cache.get(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan result not found. Please run a new scan.'}), 404

    try:
        pdf_buffer = generate_report(scan_data)
        domain = scan_data.get('domain', 'unknown')
        filename = f'PhishGuard_Report_{domain}_{scan_id[:8]}.pdf'

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500


@app.route('/email-scanner')
def email_scanner():
    """Render the email scanner page."""
    return render_template('email_scanner.html')


@app.route('/scan-email', methods=['POST'])
def scan_email():
    """Analyze an email address for phishing indicators and brand impersonation."""
    email_addr = request.form.get('email_address', '').strip()

    if not email_addr:
        return render_template('email_scanner.html', error='Please enter an email address to analyze.')

    try:
        result = analyze_email_address(email_addr)
    except Exception as e:
        return render_template(
            'email_scanner.html',
            error='An error occurred while analyzing the email address. Please try again.'
        )

    if 'error' in result:
        return render_template('email_scanner.html', error=result['error'])

    return render_template('email_result.html', result=result)


@app.route('/help')
def help_page():
    """Render the help page."""
    return render_template('help.html')


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
