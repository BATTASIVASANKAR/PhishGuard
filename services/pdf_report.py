"""
PhishGuard — PDF Security Report Generator
Generates branded, downloadable PDF reports using ReportLab.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)


# ── Brand Colors ─────────────────────────────────────────────────────────────

BRAND_DARK = colors.HexColor('#020a1a')
BRAND_BLUE = colors.HexColor('#1e90ff')
BRAND_LIGHT_BLUE = colors.HexColor('#60a5fa')
BRAND_TEXT = colors.HexColor('#e8f0fe')
BRAND_MUTED = colors.HexColor('#8ab4f8')
SAFE_GREEN = colors.HexColor('#22c55e')
DANGER_RED = colors.HexColor('#ef4444')
WARNING_AMBER = colors.HexColor('#f59e0b')
BG_CARD = colors.HexColor('#0a1628')
BG_ROW_ALT = colors.HexColor('#0d1b36')
WHITE = colors.white
BLACK = colors.black


def _get_risk_color(level: str) -> colors.HexColor:
    """Return color based on risk level."""
    return {
        'Critical': DANGER_RED,
        'High': colors.HexColor('#f87171'),
        'Medium': WARNING_AMBER,
        'Low': SAFE_GREEN,
    }.get(level, BRAND_BLUE)


def _build_styles():
    """Build custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='BrandTitle',
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=BRAND_BLUE,
        alignment=TA_CENTER,
        spaceAfter=4 * mm,
    ))

    styles.add(ParagraphStyle(
        name='BrandSubtitle',
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.HexColor('#6b7280'),
        alignment=TA_CENTER,
        spaceAfter=8 * mm,
    ))

    styles.add(ParagraphStyle(
        name='SectionHeader',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=BRAND_BLUE,
        spaceBefore=8 * mm,
        spaceAfter=4 * mm,
        borderPadding=(0, 0, 2, 0),
    ))

    styles.add(ParagraphStyle(
        name='BodyText2',
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#374151'),
        leading=14,
        spaceAfter=2 * mm,
    ))

    styles.add(ParagraphStyle(
        name='SmallMuted',
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.HexColor('#9ca3af'),
        alignment=TA_CENTER,
    ))

    styles.add(ParagraphStyle(
        name='RiskScore',
        fontName='Helvetica-Bold',
        fontSize=36,
        alignment=TA_CENTER,
        spaceAfter=2 * mm,
    ))

    styles.add(ParagraphStyle(
        name='RiskLevel',
        fontName='Helvetica-Bold',
        fontSize=16,
        alignment=TA_CENTER,
        spaceAfter=4 * mm,
    ))

    styles.add(ParagraphStyle(
        name='TableCell',
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#374151'),
        leading=12,
    ))

    styles.add(ParagraphStyle(
        name='TableHeader',
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=WHITE,
        leading=12,
    ))

    return styles


def _make_info_table(data: list[tuple[str, str]], styles) -> Table:
    """Create a styled two-column info table."""
    table_data = []
    for label, value in data:
        table_data.append([
            Paragraph(f'<b>{label}</b>', styles['TableCell']),
            Paragraph(str(value) if value else 'N/A', styles['TableCell']),
        ])

    table = Table(table_data, colWidths=[55 * mm, 115 * mm])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f4ff')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#374151')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [WHITE, colors.HexColor('#f9fafb')]),
    ]))
    return table


def generate_report(scan_data: dict) -> io.BytesIO:
    """Generate a branded PDF security report from scan data.

    Args:
        scan_data: Full scan result dict from /api/scan endpoint.

    Returns:
        BytesIO buffer containing the PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = _build_styles()
    elements = []

    # ── Header ───────────────────────────────────────────────────────────
    elements.append(Paragraph('🛡️ PhishGuard', styles['BrandTitle']))
    elements.append(Paragraph('Website Intelligence & Security Report', styles['BrandSubtitle']))
    elements.append(HRFlowable(width='100%', thickness=1, color=BRAND_BLUE, spaceAfter=4 * mm))

    # Report metadata
    url = scan_data.get('url', 'Unknown')
    timestamp = scan_data.get('timestamp', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    elements.append(Paragraph(f'<b>URL Analyzed:</b> {url}', styles['BodyText2']))
    elements.append(Paragraph(f'<b>Report Generated:</b> {timestamp}', styles['BodyText2']))
    elements.append(Spacer(1, 6 * mm))

    # ── Risk Data ────────────────────────────────────────────────────────
    risk = scan_data.get('risk_score', {})


    # ── WHOIS Information ────────────────────────────────────────────────
    whois = scan_data.get('whois', {})
    if whois.get('available'):
        elements.append(Paragraph('WHOIS & Domain Information', styles['SectionHeader']))
        whois_rows = [
            ('Domain', whois.get('domain', 'N/A')),
            ('Registrar', whois.get('registrar', 'N/A')),
            ('Creation Date', whois.get('creation_date', 'N/A')),
            ('Expiration Date', whois.get('expiration_date', 'N/A')),
            ('Domain Age', f"{whois.get('domain_age_days', 'N/A')} days"),
            ('Country', whois.get('registrant_country', 'N/A')),
            ('Organization', whois.get('org', 'N/A')),
        ]
        elements.append(_make_info_table(whois_rows, styles))

    # ── SSL Certificate ──────────────────────────────────────────────────
    ssl = scan_data.get('ssl', {})
    elements.append(Paragraph('SSL Certificate Analysis', styles['SectionHeader']))
    if ssl.get('available'):
        status_label = ssl.get('status', 'unknown').replace('_', ' ').title()
        ssl_rows = [
            ('Status',              status_label),
            ('Issuer CN',           ssl.get('issuer_cn') or ssl.get('issuer') or 'N/A'),
            ('Subject CN',          ssl.get('subject_cn') or ssl.get('subject') or 'N/A'),
            ('Valid From',          ssl.get('valid_from') or 'N/A'),
            ('Valid To',            ssl.get('valid_to') or 'N/A'),
            ('Days Remaining',      str(ssl.get('days_remaining', 'N/A'))),
            ('Signature Algorithm', ssl.get('signature_algorithm') or 'N/A'),
            ('Self-Signed',         'Yes' if ssl.get('is_self_signed') else 'No'),
        ]
        elements.append(_make_info_table(ssl_rows, styles))
    else:
        msg = ssl.get('error') or 'Certificate information unavailable'
        elements.append(Paragraph(msg, styles['BodyText2']))

    # ── VirusTotal ───────────────────────────────────────────────────────
    vt = scan_data.get('virustotal', {})
    if vt.get('available'):
        elements.append(Paragraph('VirusTotal Threat Analysis', styles['SectionHeader']))
        vt_rows = [
            ('Malicious', str(vt.get('malicious', 0))),
            ('Suspicious', str(vt.get('suspicious', 0))),
            ('Harmless', str(vt.get('harmless', 0))),
            ('Undetected', str(vt.get('undetected', 0))),
            ('Total Engines', str(vt.get('total_engines', 0))),
            ('Community Score', str(vt.get('community_score', 0))),
            ('Scan Date', vt.get('scan_date', 'N/A')),
        ]
        elements.append(_make_info_table(vt_rows, styles))

        # Detection list
        detections = vt.get('detections', [])
        if detections:
            elements.append(Spacer(1, 3 * mm))
            elements.append(Paragraph('<b>Engine Detections:</b>', styles['BodyText2']))
            for d in detections[:10]:
                elements.append(Paragraph(
                    f"• {d['engine']}: {d['result']} ({d['category']})",
                    styles['BodyText2']
                ))

    # ── DNS & Hosting ────────────────────────────────────────────────────
    dns = scan_data.get('dns', {})
    if dns.get('available'):
        elements.append(Paragraph('DNS & Hosting Information', styles['SectionHeader']))
        loc = dns.get('server_location', {})
        location_str = ', '.join(filter(None, [loc.get('city'), loc.get('region'), loc.get('country')])) or 'N/A'
        dns_rows = [
            ('IP Address', ', '.join(dns.get('ip_addresses', [])) or 'N/A'),
            ('Hosting Provider', dns.get('hosting_provider', 'N/A')),
            ('Server Location', location_str),
            ('NS Records', ', '.join(dns.get('ns_records', [])) or 'N/A'),
            ('MX Records', ', '.join(r.get('host', '') for r in dns.get('mx_records', [])) or 'N/A'),
            ('SPF Record', (dns.get('spf_record') or 'Not found')[:80]),
            ('DMARC Record', (dns.get('dmarc_record') or 'Not found')[:80]),
        ]
        elements.append(_make_info_table(dns_rows, styles))

    # ── Technology Stack ─────────────────────────────────────────────────
    techs = scan_data.get('technologies', {})
    tech_list = techs.get('technologies', []) if isinstance(techs, dict) else []
    if tech_list:
        elements.append(Paragraph('Technology Stack', styles['SectionHeader']))
        tech_rows = [
            [
                Paragraph('<b>Technology</b>', styles['TableHeader']),
                Paragraph('<b>Category</b>', styles['TableHeader']),
            ]
        ]
        for t in tech_list:
            tech_rows.append([
                Paragraph(t.get('name', ''), styles['TableCell']),
                Paragraph(t.get('category', ''), styles['TableCell']),
            ])
        tech_table = Table(tech_rows, colWidths=[85 * mm, 85 * mm])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, colors.HexColor('#f9fafb')]),
        ]))
        elements.append(tech_table)

    # ── URL Pattern Findings ─────────────────────────────────────────────
    patterns = scan_data.get('url_patterns', {})
    findings = patterns.get('findings', [])
    if findings:
        elements.append(Paragraph('URL Pattern Findings', styles['SectionHeader']))
        for f in findings:
            is_positive = 'enabled' in f or 'detected' in f or 'Secure' in f
            if is_positive:
                elements.append(Paragraph(f'<font color="#22c55e">✓ {f}</font>', styles['BodyText2']))
            else:
                elements.append(Paragraph(f'⚠ {f}', styles['BodyText2']))


    # ── Footer ───────────────────────────────────────────────────────────
    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#d1d5db'), spaceAfter=3 * mm))
    elements.append(Paragraph(
        'Generated by PhishGuard — Website Intelligence & Security Platform<br/>'
        'This report is for educational and cybersecurity awareness purposes only.',
        styles['SmallMuted']
    ))

    # ── Build PDF ────────────────────────────────────────────────────────
    doc.build(elements)
    buffer.seek(0)
    return buffer
