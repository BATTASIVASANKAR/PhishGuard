"""
PhishGuard — Data Breach Intelligence Service
Uses the Have I Been Pwned (HIBP) public breach API to check if a domain
has appeared in any publicly known data breaches.

Endpoint: GET https://haveibeenpwned.com/api/v3/breaches?domain=<domain>
No API key required for domain-level breach listing.
"""

import requests
from config import REQUEST_TIMEOUT

HIBP_BREACHES_URL = 'https://haveibeenpwned.com/api/v3/breaches'

# Maximum number of breaches to display
MAX_BREACHES = 10


def get_breach_info(domain: str) -> dict:
    """Check if a domain has been involved in publicly known data breaches.

    Uses the HIBP public /api/v3/breaches?domain= endpoint which requires
    no API key and returns breach records for any queried domain.

    Args:
        domain: Bare domain name (e.g. 'adobe.com')

    Returns:
        Dict with:
          - available (bool)
          - breached (bool)
          - breach_count (int)
          - breaches (list of breach summary dicts)
          - error (str or None)
    """
    result = {
        'available': False,
        'breached': False,
        'breach_count': 0,
        'breaches': [],
        'error': None,
    }

    if not domain:
        result['error'] = 'No domain provided.'
        return result

    try:
        resp = requests.get(
            HIBP_BREACHES_URL,
            params={'domain': domain},
            timeout=min(REQUEST_TIMEOUT, 8),
            headers={
                'User-Agent': 'PhishGuard/1.0 BreachCheck',
                'Accept': 'application/json',
            },
        )

        if resp.status_code == 404:
            # HIBP returns 404 when no breaches found
            result['available'] = True
            result['breached'] = False
            result['breach_count'] = 0
            return result

        if resp.status_code != 200:
            result['error'] = f'HIBP API returned HTTP {resp.status_code}.'
            return result

        breach_list = resp.json()
        if not isinstance(breach_list, list):
            result['error'] = 'Unexpected response format from HIBP API.'
            return result

        result['available'] = True

        if not breach_list:
            result['breached'] = False
            return result

        result['breached'] = True
        result['breach_count'] = len(breach_list)

        # Sort by BreachDate descending (most recent first) and cap
        sorted_breaches = sorted(
            breach_list,
            key=lambda b: b.get('BreachDate', '0000-00-00'),
            reverse=True,
        )[:MAX_BREACHES]

        for b in sorted_breaches:
            # Clean up description — strip HTML tags
            description = b.get('Description', '')
            import re
            description = re.sub(r'<[^>]+>', '', description)
            if len(description) > 300:
                description = description[:297] + '...'

            data_classes = b.get('DataClasses', [])

            result['breaches'].append({
                'name':         b.get('Name', 'Unknown'),
                'title':        b.get('Title', b.get('Name', 'Unknown')),
                'breach_date':  b.get('BreachDate', 'Unknown'),
                'added_date':   b.get('AddedDate', '')[:10] if b.get('AddedDate') else '',
                'pwn_count':    b.get('PwnCount', 0),
                'description':  description,
                'data_classes': data_classes,
                'is_verified':  b.get('IsVerified', False),
                'is_sensitive': b.get('IsSensitive', False),
                'logo_path':    b.get('LogoPath', ''),
            })

    except requests.exceptions.Timeout:
        result['error'] = 'HIBP API request timed out.'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to HIBP API.'
    except Exception as e:
        result['error'] = f'Breach check failed: {str(e)}'

    return result
