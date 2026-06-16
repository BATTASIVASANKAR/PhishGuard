"""
PhishGuard — Technology Stack Detection Service
Detects web technologies by analyzing HTTP headers, HTML content, and response patterns.
No external API required — pure HTTP + pattern matching.
"""

import re
import requests
from config import REQUEST_TIMEOUT


# ── Technology Fingerprints ──────────────────────────────────────────────────

HEADER_FINGERPRINTS = {
    # Server headers
    'server': {
        'apache':  {'name': 'Apache', 'category': 'Web Server'},
        'nginx':   {'name': 'Nginx', 'category': 'Web Server'},
        'iis':     {'name': 'Microsoft IIS', 'category': 'Web Server'},
        'litespeed': {'name': 'LiteSpeed', 'category': 'Web Server'},
        'cloudflare': {'name': 'Cloudflare', 'category': 'CDN'},
        'gws':     {'name': 'Google Web Server', 'category': 'Web Server'},
        'openresty': {'name': 'OpenResty', 'category': 'Web Server'},
        'gunicorn': {'name': 'Gunicorn', 'category': 'Web Server'},
        'uvicorn': {'name': 'Uvicorn', 'category': 'Web Server'},
        'caddy':   {'name': 'Caddy', 'category': 'Web Server'},
    },
    # X-Powered-By
    'x-powered-by': {
        'php':      {'name': 'PHP', 'category': 'Language'},
        'asp.net':  {'name': 'ASP.NET', 'category': 'Framework'},
        'express':  {'name': 'Express.js', 'category': 'Framework'},
        'next.js':  {'name': 'Next.js', 'category': 'Framework'},
        'flask':    {'name': 'Flask', 'category': 'Framework'},
        'django':   {'name': 'Django', 'category': 'Framework'},
        'ruby':     {'name': 'Ruby', 'category': 'Language'},
        'servlet':  {'name': 'Java Servlet', 'category': 'Framework'},
        'wp engine': {'name': 'WP Engine', 'category': 'Hosting'},
        'plesk':    {'name': 'Plesk', 'category': 'Hosting'},
    },
}

HTML_FINGERPRINTS = [
    # CMS
    {'pattern': r'wp-content|wp-includes|wordpress', 'name': 'WordPress', 'category': 'CMS'},
    {'pattern': r'Joomla!?|/components/com_', 'name': 'Joomla', 'category': 'CMS'},
    {'pattern': r'Drupal\.settings|drupal\.js', 'name': 'Drupal', 'category': 'CMS'},
    {'pattern': r'content="Shopify"', 'name': 'Shopify', 'category': 'E-Commerce'},
    {'pattern': r'content="Wix\.com', 'name': 'Wix', 'category': 'Website Builder'},
    {'pattern': r'squarespace\.com|squarespace-cdn', 'name': 'Squarespace', 'category': 'Website Builder'},
    {'pattern': r'ghost\.io|ghost-portal', 'name': 'Ghost', 'category': 'CMS'},

    # JS Frameworks
    {'pattern': r'react(?:\.production|dom|\.min\.js|__fiber)', 'name': 'React', 'category': 'JS Framework'},
    {'pattern': r'__NEXT_DATA__|_next/static', 'name': 'Next.js', 'category': 'JS Framework'},
    {'pattern': r'ng-version|angular(?:\.min)?\.js|ng-app', 'name': 'Angular', 'category': 'JS Framework'},
    {'pattern': r'Vue\.js|vue(?:\.min)?\.js|v-bind:|v-if=|__vue__', 'name': 'Vue.js', 'category': 'JS Framework'},
    {'pattern': r'svelte|__svelte', 'name': 'Svelte', 'category': 'JS Framework'},
    {'pattern': r'ember(?:\.min)?\.js|ember-cli', 'name': 'Ember.js', 'category': 'JS Framework'},

    # JS Libraries
    {'pattern': r'jquery(?:\.min)?\.js|jQuery\s*v', 'name': 'jQuery', 'category': 'JS Library'},
    {'pattern': r'bootstrap(?:\.min)?\.(?:js|css)', 'name': 'Bootstrap', 'category': 'CSS Framework'},
    {'pattern': r'tailwindcss|tailwind\.min\.css', 'name': 'Tailwind CSS', 'category': 'CSS Framework'},
    {'pattern': r'materialize(?:\.min)?\.(?:js|css)', 'name': 'Materialize', 'category': 'CSS Framework'},
    {'pattern': r'font-awesome|fontawesome', 'name': 'Font Awesome', 'category': 'Icon Library'},
    {'pattern': r'lodash(?:\.min)?\.js', 'name': 'Lodash', 'category': 'JS Library'},
    {'pattern': r'moment(?:\.min)?\.js', 'name': 'Moment.js', 'category': 'JS Library'},
    {'pattern': r'axios(?:\.min)?\.js', 'name': 'Axios', 'category': 'JS Library'},

    # Analytics & Marketing
    {'pattern': r'google-analytics\.com|gtag|GoogleAnalyticsObject|ga\.js', 'name': 'Google Analytics', 'category': 'Analytics'},
    {'pattern': r'googletagmanager\.com|gtm\.js', 'name': 'Google Tag Manager', 'category': 'Analytics'},
    {'pattern': r'facebook\.net/.*fbevents|fbq\(', 'name': 'Facebook Pixel', 'category': 'Analytics'},
    {'pattern': r'hotjar\.com|hj\.js', 'name': 'Hotjar', 'category': 'Analytics'},
    {'pattern': r'clarity\.ms', 'name': 'Microsoft Clarity', 'category': 'Analytics'},

    # CDN / Infrastructure
    {'pattern': r'cdnjs\.cloudflare\.com', 'name': 'cdnjs', 'category': 'CDN'},
    {'pattern': r'cdn\.jsdelivr\.net', 'name': 'jsDelivr', 'category': 'CDN'},
    {'pattern': r'unpkg\.com', 'name': 'unpkg', 'category': 'CDN'},
    {'pattern': r'maxcdn\.bootstrapcdn', 'name': 'BootstrapCDN', 'category': 'CDN'},

    # Security
    {'pattern': r'recaptcha|grecaptcha', 'name': 'reCAPTCHA', 'category': 'Security'},
    {'pattern': r'hcaptcha\.com', 'name': 'hCaptcha', 'category': 'Security'},
    {'pattern': r'cloudflare', 'name': 'Cloudflare', 'category': 'CDN'},
]

COOKIE_FINGERPRINTS = {
    'phpsessid':    {'name': 'PHP', 'category': 'Language'},
    'asp.net':      {'name': 'ASP.NET', 'category': 'Framework'},
    'jsessionid':   {'name': 'Java', 'category': 'Language'},
    'laravel_session': {'name': 'Laravel', 'category': 'Framework'},
    'csrftoken':    {'name': 'Django', 'category': 'Framework'},
    '_gh_sess':     {'name': 'GitHub', 'category': 'Platform'},
    'wp-settings':  {'name': 'WordPress', 'category': 'CMS'},
}

META_GENERATOR_MAP = {
    'wordpress':    {'name': 'WordPress', 'category': 'CMS'},
    'joomla':       {'name': 'Joomla', 'category': 'CMS'},
    'drupal':       {'name': 'Drupal', 'category': 'CMS'},
    'wix.com':      {'name': 'Wix', 'category': 'Website Builder'},
    'squarespace':  {'name': 'Squarespace', 'category': 'Website Builder'},
    'blogger':      {'name': 'Blogger', 'category': 'CMS'},
    'ghost':        {'name': 'Ghost', 'category': 'CMS'},
    'hugo':         {'name': 'Hugo', 'category': 'Static Site Generator'},
    'jekyll':       {'name': 'Jekyll', 'category': 'Static Site Generator'},
    'gatsby':       {'name': 'Gatsby', 'category': 'Static Site Generator'},
    'webflow':      {'name': 'Webflow', 'category': 'Website Builder'},
}


def detect_technologies(url: str) -> dict:
    """Detect technologies used by a website.

    Analyzes HTTP headers, HTML content, cookies, and meta tags
    to identify server software, frameworks, CMS, JS libraries, etc.
    """
    result = {
        'available': False,
        'technologies': [],
        'error': None,
    }

    seen = set()  # Avoid duplicate tech entries

    def add_tech(name: str, category: str):
        if name not in seen:
            seen.add(name)
            result['technologies'].append({'name': name, 'category': category})

    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                              '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            },
            allow_redirects=True,
            verify=False,
        )

        result['available'] = True

        # ── Analyze Headers ──────────────────────────────────────────────
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for header_name, patterns in HEADER_FINGERPRINTS.items():
            header_val = headers_lower.get(header_name, '')
            if header_val:
                for keyword, tech in patterns.items():
                    if keyword in header_val:
                        add_tech(tech['name'], tech['category'])

        # Detect HTTPS
        if url.startswith('https://') or resp.url.startswith('https://'):
            add_tech('HTTPS', 'Security')

        # HSTS header
        if 'strict-transport-security' in headers_lower:
            add_tech('HSTS', 'Security')

        # Content Security Policy
        if 'content-security-policy' in headers_lower:
            add_tech('Content Security Policy', 'Security')

        # ── Analyze Cookies ──────────────────────────────────────────────
        cookie_str = '; '.join(
            f'{k}={v}' for k, v in resp.cookies.items()
        ).lower()
        for cookie_key, tech in COOKIE_FINGERPRINTS.items():
            if cookie_key in cookie_str:
                add_tech(tech['name'], tech['category'])

        # ── Analyze HTML Body ────────────────────────────────────────────
        html = resp.text[:200000]  # Cap at 200KB to avoid memory issues

        # Meta generator tag
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', html, re.I)
        if not gen_match:
            gen_match = re.search(r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']generator["\']', html, re.I)
        if gen_match:
            gen_value = gen_match.group(1).lower()
            for keyword, tech in META_GENERATOR_MAP.items():
                if keyword in gen_value:
                    add_tech(tech['name'], tech['category'])
                    break

        # HTML pattern fingerprints
        for fp in HTML_FINGERPRINTS:
            if re.search(fp['pattern'], html, re.IGNORECASE):
                add_tech(fp['name'], fp['category'])

        # ── Sort by category ─────────────────────────────────────────────
        category_order = [
            'Web Server', 'CDN', 'Language', 'Framework', 'CMS',
            'E-Commerce', 'Website Builder', 'Static Site Generator',
            'JS Framework', 'JS Library', 'CSS Framework', 'Icon Library',
            'Analytics', 'Security', 'Hosting', 'Platform',
        ]
        order_map = {c: i for i, c in enumerate(category_order)}
        result['technologies'].sort(key=lambda t: order_map.get(t['category'], 99))

    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out while fetching the website.'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to the website.'
    except Exception as e:
        result['error'] = f'Technology detection failed: {str(e)}'

    return result
