"""
PhishGuard — Real-Time Vulnerability Intelligence Service
Queries the CIRCL CVE Search API (https://cve.circl.lu/api/) — free, no API key required.
Fetches recent CVEs for technologies detected on the scanned website.
"""

import requests
from config import REQUEST_TIMEOUT

# CIRCL CVE Search base URL
CIRCL_BASE = 'https://cve.circl.lu/api'

# Map technology names to (vendor, product) tuples for the CIRCL API
TECH_CVE_MAP = {
    'WordPress':        ('wordpress', 'wordpress'),
    'Joomla':           ('joomla', 'joomla!'),
    'Drupal':           ('drupal', 'drupal'),
    'Apache':           ('apache', 'http_server'),
    'Nginx':            ('nginx', 'nginx'),
    'Microsoft IIS':    ('microsoft', 'internet_information_services'),
    'PHP':              ('php', 'php'),
    'ASP.NET':          ('microsoft', 'asp.net'),
    'Django':           ('djangoproject', 'django'),
    'Flask':            ('palletsprojects', 'flask'),
    'Laravel':          ('laravel', 'laravel'),
    'OpenSSL':          ('openssl', 'openssl'),
    'jQuery':           ('jquery', 'jquery'),
    'Bootstrap':        ('getbootstrap', 'bootstrap'),
    'React':            ('facebook', 'react'),
    'Angular':          ('google', 'angular'),
    'Next.js':          ('vercel', 'next.js'),
    'Express.js':       ('expressjs', 'express'),
    'Shopify':          ('shopify', 'shopify'),
    'LiteSpeed':        ('litespeedtech', 'litespeed_web_server'),
    'OpenResty':        ('openresty', 'openresty'),
}

# Max number of technologies to look up (to keep response fast)
MAX_TECH_LOOKUPS = 4
# Max CVEs to return per technology
MAX_CVES_PER_TECH = 5


def get_vulnerabilities(technologies: list) -> dict:
    """Fetch recent CVEs for the detected web technologies.

    Args:
        technologies: List of technology dicts from tech_detect_service,
                      each with 'name' and 'category' keys.

    Returns:
        Dict with:
          - available (bool)
          - results (list of {tech_name, cves: [{id, summary, cvss, published}]})
          - error (str or None)
    """
    result = {
        'available': False,
        'results': [],
        'error': None,
    }

    if not technologies:
        result['error'] = 'No technologies detected to look up.'
        return result

    # Filter to only technologies we have CVE mappings for
    matchable = [
        t for t in technologies
        if t.get('name') in TECH_CVE_MAP
    ][:MAX_TECH_LOOKUPS]

    if not matchable:
        result['error'] = 'No CVE mappings available for detected technologies.'
        return result

    session = requests.Session()
    session.headers.update({'User-Agent': 'PhishGuard/1.0 CVE-Lookup'})

    fetch_timeout = min(REQUEST_TIMEOUT, 8)

    for tech in matchable:
        tech_name = tech['name']
        vendor, product = TECH_CVE_MAP[tech_name]

        try:
            resp = session.get(
                f'{CIRCL_BASE}/search/{vendor}/{product}',
                timeout=fetch_timeout,
            )

            if resp.status_code != 200:
                continue

            cve_list = resp.json()
            if not isinstance(cve_list, list):
                continue

            # Sort by published date descending (most recent first)
            # CIRCL returns newest last — reverse the list
            recent = list(reversed(cve_list))[:MAX_CVES_PER_TECH]

            parsed_cves = []
            for cve in recent:
                cve_id = cve.get('id') or cve.get('CVE ID', 'Unknown')
                summary = cve.get('summary', 'No description available.')
                # Truncate long summaries
                if len(summary) > 300:
                    summary = summary[:297] + '...'
                cvss = cve.get('cvss') or cve.get('cvss3') or 'N/A'
                published = cve.get('Published') or cve.get('published', 'Unknown')
                if published and len(published) > 10:
                    published = published[:10]  # Keep YYYY-MM-DD only

                parsed_cves.append({
                    'id': cve_id,
                    'summary': summary,
                    'cvss': cvss,
                    'published': published,
                })

            if parsed_cves:
                result['results'].append({
                    'tech_name': tech_name,
                    'cves': parsed_cves,
                })
                result['available'] = True

        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue

    if not result['available']:
        result['error'] = 'Could not retrieve vulnerability data at this time.'

    return result
