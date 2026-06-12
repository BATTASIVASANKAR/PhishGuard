"""
PhishGuard — WHOIS & Domain Intelligence Service
Fetches domain registration data including age, registrar, dates, and country.
"""
import re
import whois
from datetime import datetime, timezone
from config import REQUEST_TIMEOUT


def get_whois_info(domain: str) -> dict:
    """Fetch WHOIS information for a domain.

    Returns a dict with domain registration details and risk indicators.
    """
    result = {
        'available': False,
        'domain': domain,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'registrar': None,
        'domain_age_days': None,
        'registrant_country': None,
        'name_servers': [],
        'status': [],
        'org': None,
        'risk_flags': [],
        'error': None,
    }

    # Immediately fail for IP addresses (WHOIS library does not support IP lookup directly and can hang)
    if not domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) or ':' in domain:
        result['error'] = 'WHOIS lookup is not supported for IP addresses.'
        return result

    try:
        w = whois.whois(domain, timeout=REQUEST_TIMEOUT)

        if not w or not w.domain_name:
            result['error'] = 'No WHOIS data available for this domain.'
            return result

        result['available'] = True

        # ── Creation Date ────────────────────────────────────────────────
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if isinstance(creation, str):
                try:
                    creation = datetime.fromisoformat(creation)
                except (ValueError, TypeError):
                    creation = None
            if creation:
                result['creation_date'] = creation.strftime('%Y-%m-%d')
                # Calculate domain age
                now = datetime.now(timezone.utc)
                if creation.tzinfo is None:
                    from datetime import timezone as tz
                    creation = creation.replace(tzinfo=tz.utc)
                age_days = (now - creation).days
                result['domain_age_days'] = age_days

                # Risk flags based on domain age
                if age_days < 30:
                    result['risk_flags'].append('Domain is less than 30 days old — highly suspicious')
                elif age_days < 90:
                    result['risk_flags'].append('Domain is less than 90 days old — use caution')
                elif age_days < 365:
                    result['risk_flags'].append('Domain is less than 1 year old')

        # ── Expiration Date ──────────────────────────────────────────────
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            if isinstance(expiration, str):
                try:
                    expiration = datetime.fromisoformat(expiration)
                except (ValueError, TypeError):
                    expiration = None
            if expiration:
                result['expiration_date'] = expiration.strftime('%Y-%m-%d')

        # ── Updated Date ─────────────────────────────────────────────────
        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        if updated:
            if isinstance(updated, str):
                try:
                    updated = datetime.fromisoformat(updated)
                except (ValueError, TypeError):
                    updated = None
            if updated:
                result['updated_date'] = updated.strftime('%Y-%m-%d')

        # ── Registrar ───────────────────────────────────────────────────
        result['registrar'] = w.registrar or 'Unknown'

        # ── Country ─────────────────────────────────────────────────────
        country = getattr(w, 'country', None)
        if not country:
            country = getattr(w, 'registrant_country', None)
        result['registrant_country'] = country or 'Unknown'

        # ── Organization ────────────────────────────────────────────────
        result['org'] = getattr(w, 'org', None) or getattr(w, 'organization', None)

        # ── Name Servers ────────────────────────────────────────────────
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                result['name_servers'] = [str(n).lower() for n in ns]
            else:
                result['name_servers'] = [str(ns).lower()]

        # ── Status ──────────────────────────────────────────────────────
        status = w.status
        if status:
            if isinstance(status, list):
                result['status'] = [str(s) for s in status]
            else:
                result['status'] = [str(status)]

    except Exception as e:
        result['error'] = f'WHOIS lookup failed: {str(e)}'

    return result
