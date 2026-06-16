"""
PhishGuard — Composite Risk Scoring Engine
Calculates a 0–100 phishing risk score from multiple intelligence sources.
"""


def calculate_risk_score(
    ml_phishing: bool,
    pattern_score: int,
    whois_data: dict,
    ssl_data: dict,
    vt_data: dict,
    dns_data: dict,
) -> dict:
    """Calculate a composite risk score (0–100) from all analysis modules.

    Returns a dict with total score, risk level, breakdown by factor,
    and actionable recommendations.
    """
    breakdown = {}
    recommendations = []

    # ── 1. ML Prediction (max 25 pts) ────────────────────────────────────
    ml_score = 25 if ml_phishing else 0
    breakdown['ml_prediction'] = {
        'score': ml_score,
        'max': 25,
        'label': 'ML Phishing Detection',
        'detail': 'Flagged as phishing' if ml_phishing else 'No phishing detected',
    }
    if ml_phishing:
        recommendations.append('The ML model flagged this URL as a phishing attempt. Do not enter personal data.')

    # ── 2. Domain Age (max 15 pts) ───────────────────────────────────────
    domain_score = 0
    domain_detail = 'No WHOIS data available'
    if whois_data.get('available'):
        age = whois_data.get('domain_age_days')
        if age is not None:
            if age < 30:
                domain_score = 15
                domain_detail = f'Domain is only {age} days old — very new'
                recommendations.append('This domain was registered very recently (< 30 days). Newly registered domains are often used for phishing.')
            elif age < 90:
                domain_score = 10
                domain_detail = f'Domain is {age} days old — relatively new'
                recommendations.append('This domain is relatively new (< 90 days). Exercise caution.')
            elif age < 365:
                domain_score = 5
                domain_detail = f'Domain is {age} days old — less than 1 year'
            else:
                domain_score = 0
                domain_detail = f'Domain is {age} days old — established'
        else:
            domain_score = 5
            domain_detail = 'Domain age could not be determined'
    else:
        domain_score = 8
        domain_detail = 'WHOIS data unavailable — cannot verify domain age'
        recommendations.append('WHOIS information is hidden or unavailable, which can be a red flag.')

    breakdown['domain_age'] = {
        'score': domain_score,
        'max': 15,
        'label': 'Domain Age',
        'detail': domain_detail,
    }

    # ── 3. SSL Certificate (max 15 pts) ──────────────────────────────────
    ssl_score = 0
    ssl_detail = 'No SSL data available'
    if ssl_data.get('available'):
        status = ssl_data.get('status', 'unknown')
        if status == 'no_ssl':
            ssl_score = 15
            ssl_detail = 'No SSL certificate — connection is not encrypted'
            recommendations.append('This website does not use HTTPS. Your data is transmitted in plain text.')
        elif status == 'expired':
            ssl_score = 15
            ssl_detail = 'SSL certificate has expired'
            recommendations.append('The SSL certificate is expired, which is a strong indicator of a neglected or malicious site.')
        elif status == 'self_signed':
            ssl_score = 12
            ssl_detail = 'SSL certificate is self-signed'
            recommendations.append('Self-signed SSL certificates are not verified by a trusted authority.')
        elif status == 'invalid':
            ssl_score = 13
            ssl_detail = 'SSL certificate failed verification'
            recommendations.append('The SSL certificate could not be verified by trusted certificate authorities.')
        elif status == 'expiring_soon':
            ssl_score = 5
            days = ssl_data.get('days_remaining', 0)
            ssl_detail = f'SSL certificate expires in {days} days'
        elif status == 'valid':
            ssl_score = 0
            ssl_detail = 'Valid SSL certificate from trusted CA'
    elif ssl_data.get('error') and 'resolve' not in ssl_data.get('error', '').lower():
        ssl_score = 10
        ssl_detail = 'SSL certificate could not be retrieved'

    breakdown['ssl_certificate'] = {
        'score': ssl_score,
        'max': 15,
        'label': 'SSL Certificate',
        'detail': ssl_detail,
    }

    # ── 4. VirusTotal (max 20 pts) ───────────────────────────────────────
    vt_score = 0
    vt_detail = 'VirusTotal data not available'
    if vt_data.get('available'):
        malicious = vt_data.get('malicious', 0)
        suspicious = vt_data.get('suspicious', 0)
        total = vt_data.get('total_engines', 1) or 1
        threat_count = malicious + suspicious

        if threat_count == 0:
            vt_score = 0
            vt_detail = f'Clean — 0/{total} engines detected threats'
        elif threat_count <= 2:
            vt_score = 8
            vt_detail = f'{threat_count}/{total} engines flagged this URL'
            recommendations.append(f'{threat_count} security engines flagged this URL. Consider avoiding it.')
        elif threat_count <= 5:
            vt_score = 14
            vt_detail = f'{threat_count}/{total} engines flagged this URL'
            recommendations.append(f'Multiple security engines ({threat_count}) flagged this URL. High likelihood of malicious content.')
        else:
            vt_score = 20
            vt_detail = f'{threat_count}/{total} engines flagged this URL — DANGEROUS'
            recommendations.append(f'Numerous security engines ({threat_count}) flagged this URL. Avoid visiting this site.')

        # Community reputation
        community = vt_data.get('community_score', 0)
        if community < -10:
            vt_score = min(vt_score + 3, 20)
            recommendations.append('VirusTotal community has given this URL a strongly negative reputation.')

    breakdown['virustotal'] = {
        'score': vt_score,
        'max': 20,
        'label': 'VirusTotal Threat Intelligence',
        'detail': vt_detail,
    }

    # ── 5. URL Patterns (max 10 pts) ─────────────────────────────────────
    url_score = min(pattern_score, 10)
    if pattern_score >= 6:
        url_detail = 'Multiple suspicious URL patterns detected'
    elif pattern_score >= 3:
        url_detail = 'Some suspicious URL patterns found'
    elif pattern_score >= 1:
        url_detail = 'Minor URL pattern concerns'
    else:
        url_detail = 'URL structure appears normal'

    breakdown['url_patterns'] = {
        'score': url_score,
        'max': 10,
        'label': 'URL Pattern Analysis',
        'detail': url_detail,
    }

    # ── 6. DNS Anomalies (max 10 pts) ────────────────────────────────────
    dns_score = 0
    dns_details = []
    if dns_data.get('available'):
        if not dns_data.get('mx_records'):
            dns_score += 3
            dns_details.append('No MX records')
        if not dns_data.get('spf_record'):
            dns_score += 3
            dns_details.append('No SPF record')
        if dns_data.get('asn_info', {}).get('is_hosting'):
            dns_score += 2
            dns_details.append('Hosted on datacenter IP')
        if not dns_data.get('ns_records'):
            dns_score += 2
            dns_details.append('No NS records found')
        dns_score = min(dns_score, 10)
    else:
        dns_score = 5
        dns_details.append('DNS data unavailable')

    breakdown['dns_anomalies'] = {
        'score': dns_score,
        'max': 10,
        'label': 'DNS & Hosting Analysis',
        'detail': '; '.join(dns_details) if dns_details else 'DNS configuration looks normal',
    }

    # ── 7. Redirect Behavior (max 5 pts) ─────────────────────────────────
    # (Computed from tech detection side-effect — simplified here)
    redirect_score = 0
    redirect_detail = 'No redirect analysis available'
    breakdown['redirect_behavior'] = {
        'score': redirect_score,
        'max': 5,
        'label': 'Redirect Behavior',
        'detail': redirect_detail,
    }

    # ── Total Score ──────────────────────────────────────────────────────
    total = sum(b['score'] for b in breakdown.values())
    total = min(total, 100)

    # ── Risk Level ───────────────────────────────────────────────────────
    if total >= 76:
        level = 'Critical'
        level_description = 'This website presents an extremely high risk. Multiple indicators strongly suggest malicious intent.'
    elif total >= 51:
        level = 'High'
        level_description = 'Significant risk factors detected. This website should be treated as potentially dangerous.'
    elif total >= 26:
        level = 'Medium'
        level_description = 'Some risk indicators found. Exercise caution when interacting with this website.'
    else:
        level = 'Low'
        level_description = 'No significant risk indicators detected. This website appears to be legitimate.'

    if not recommendations:
        recommendations.append('No significant concerns detected. Always verify website legitimacy before sharing sensitive information.')

    return {
        'total': total,
        'max_total': 100,
        'level': level,
        'level_description': level_description,
        'breakdown': breakdown,
        'recommendations': recommendations,
    }
