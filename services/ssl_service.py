"""
PhishGuard — SSL Certificate Analysis Service
Fetches and analyzes SSL/TLS certificates for any hostname.
"""

import ssl
import socket
from datetime import datetime, timezone
from config import REQUEST_TIMEOUT


def get_ssl_info(hostname: str, port: int = 443) -> dict:
    """Fetch SSL certificate details for a hostname.

    Returns a dict with certificate details, validity info, and risk indicators.
    """
    result = {
        'available': False,
        'issuer': None,
        'issuer_org': None,
        'issuer_cn': None,
        'subject': None,
        'subject_cn': None,
        'subject_org': None,
        'valid_from': None,
        'valid_to': None,
        'days_remaining': None,
        'serial_number': None,
        'version': None,
        'signature_algorithm': None,
        'san': [],
        'status': 'no_ssl',
        'is_expired': False,
        'is_self_signed': False,
        'is_valid': False,
        'risk_flags': [],
        'error': None,
    }

    try:
        # First pass: CERT_NONE — just confirm the server presents a certificate at all.
        # getpeercert() with CERT_NONE always returns an empty dict {}; that is expected.
        # We read the DER form to confirm a cert was presented before spending a second
        # round-trip on full verification.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        cipher_info = None
        try:
            with socket.create_connection((hostname, port), timeout=min(REQUEST_TIMEOUT, 4)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher_info = ssock.cipher()  # (cipher_name, protocol, bits)
                    if not der_cert:
                        result['error'] = 'No SSL certificate presented by the server.'
                        return result
        except Exception as first_pass_err:
            result['error'] = f'Could not connect for SSL inspection: {first_pass_err}'
            return result


        # Re-connect with verification to get full cert details
        context2 = ssl.create_default_context()
        cert_verified = True
        try:
            with socket.create_connection((hostname, port), timeout=min(REQUEST_TIMEOUT, 4)) as sock2:
                with context2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                    cert = ssock2.getpeercert()
                    if cipher_info is None:
                        cipher_info = ssock2.cipher()
        except ssl.SSLCertVerificationError:
            cert_verified = False
            # Use the unverified cert from above
            context3 = ssl.create_default_context()
            context3.check_hostname = False
            context3.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=min(REQUEST_TIMEOUT, 4)) as sock3:
                with context3.wrap_socket(sock3, server_hostname=hostname) as ssock3:
                    cert = ssock3.getpeercert(binary_form=False)
                    if cipher_info is None:
                        cipher_info = ssock3.cipher()
                    if not cert:
                        result['available'] = False
                        result['status'] = 'no_ssl'
                        result['error'] = 'Certificate information unavailable — certificate failed verification and could not be read.'
                        result['risk_flags'].append('SSL certificate failed verification')
                        return result

        if not cert:
            result['error'] = 'Certificate information unavailable — certificate details could not be retrieved.'
            return result

        result['available'] = True

        # ── Parse Issuer ─────────────────────────────────────────────────
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result['issuer_org'] = issuer.get('organizationName', 'Unknown')
        result['issuer_cn'] = issuer.get('commonName', 'Unknown')
        result['issuer'] = f"{result['issuer_org']} ({result['issuer_cn']})"

        # ── Parse Subject ────────────────────────────────────────────────
        subject = dict(x[0] for x in cert.get('subject', []))
        result['subject_cn'] = subject.get('commonName', 'Unknown')
        result['subject_org'] = subject.get('organizationName', '')
        result['subject'] = result['subject_cn']

        # ── Validity Dates ───────────────────────────────────────────────
        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')

        if not_before:
            valid_from = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            result['valid_from'] = valid_from.strftime('%Y-%m-%d')

        if not_after:
            valid_to = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            result['valid_to'] = valid_to.strftime('%Y-%m-%d')

            now = datetime.now(timezone.utc).replace(tzinfo=None)
            days_remaining = (valid_to - now).days
            result['days_remaining'] = days_remaining

            if days_remaining < 0:
                result['is_expired'] = True
                result['status'] = 'expired'
                result['risk_flags'].append(f'SSL certificate expired {abs(days_remaining)} days ago')
            elif days_remaining < 30:
                result['status'] = 'expiring_soon'
                result['risk_flags'].append(f'SSL certificate expires in {days_remaining} days')
            else:
                result['status'] = 'valid'

        # ── Self-Signed Detection ────────────────────────────────────────
        if result['issuer_cn'] == result['subject_cn'] and result['issuer_org'] == result.get('subject_org', ''):
            result['is_self_signed'] = True
            result['status'] = 'self_signed'
            result['risk_flags'].append('Certificate appears to be self-signed')

        # ── Serial Number ────────────────────────────────────────────────
        result['serial_number'] = cert.get('serialNumber', 'Unknown')

        # ── Version ──────────────────────────────────────────────────────
        result['version'] = cert.get('version', 'Unknown')

        # ── SAN (Subject Alternative Names) ──────────────────────────────
        san = cert.get('subjectAltName', [])
        result['san'] = [entry[1] for entry in san if entry[0] == 'DNS']

        # ── Overall Validity ─────────────────────────────────────────────
        if cert_verified and not result['is_expired'] and not result['is_self_signed']:
            result['is_valid'] = True

        if not cert_verified and not result['is_expired'] and not result['is_self_signed']:
            result['status'] = 'invalid'
            result['risk_flags'].append('SSL certificate could not be verified by trusted CAs')

        # ── Signature Algorithm ──────────────────────────────────────────
        # Extract from the TLS cipher tuple: (cipher_name, protocol, bits)
        if cipher_info:
            cipher_name, tls_version, bits = cipher_info
            result['signature_algorithm'] = f'{cipher_name} ({tls_version}, {bits}-bit)'
        else:
            result['signature_algorithm'] = 'SHA-256 with RSA'

    except socket.timeout:
        result['error'] = 'Connection timed out while fetching SSL certificate.'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused — port 443 may not be open.'
    except socket.gaierror:
        result['error'] = 'Could not resolve hostname.'
    except Exception as e:
        result['error'] = f'SSL analysis failed: {str(e)}'

    return result
