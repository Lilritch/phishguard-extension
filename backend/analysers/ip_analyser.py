import os
import socket

import requests
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY')

COMMON_MAIL_INFRASTRUCTURE = [
    'google',
    'microsoft',
    'outlook',
    'amazon',
    'vercel',
    'cloudflare',
    'netlify',
    'fastly',
    'akamai',
    'proofpoint',
    'mimecast',
    'sendgrid',
    'mailgun',
]


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in ['127.', '10.', '192.168.', '172.', '0.'])


def resolve_domain_to_ip(domain: str) -> str | None:
    """Resolve a sender domain to an IP when Gmail does not expose raw sender headers."""
    if not domain:
        return None

    clean_domain = domain.strip().lower().replace('mailto:', '')
    if '@' in clean_domain:
        clean_domain = clean_domain.split('@')[-1]

    try:
        ip = socket.gethostbyname(clean_domain)
    except Exception:
        return None

    if is_private_ip(ip):
        return None
    return ip


def is_common_mail_infrastructure(name: str) -> bool:
    value = str(name or '').lower()
    return any(provider in value for provider in COMMON_MAIL_INFRASTRUCTURE)


def analyse_ip(ip: str = None, sender_domain: str = None) -> dict:
    """
    Look up IP reputation, geolocation, and VPN/proxy status.
    Falls back to sender-domain DNS resolution when Gmail hides raw headers.
    """
    result = {
        "ip": ip,
        "resolved_from_domain": False,
        "sender_domain": sender_domain,
        "country": "Unknown",
        "city": "Unknown",
        "isp": sender_domain or "Unknown",
        "is_vpn_proxy": False,
        "abuse_score": 0,
        "is_malicious": False,
        "confidence": 0,
        "risk_score": 0,
        "hosted_mail_infrastructure": False,
        "abuse_lookup_status": "not_configured",
        "flags": []
    }

    if not ip and sender_domain:
        resolved_ip = resolve_domain_to_ip(sender_domain)
        if resolved_ip:
            ip = resolved_ip
            result['ip'] = resolved_ip
            result['resolved_from_domain'] = True
            result['confidence'] = max(result['confidence'], 0.20)
            result['flags'].append(f'Domain resolved for context only: {sender_domain}')

    if not ip:
        if sender_domain:
            result['flags'].append('Raw sender IP unavailable; showing sender domain instead')
        return result

    if result['resolved_from_domain']:
        result['confidence'] = max(result['confidence'], 0.20)
    else:
        result['confidence'] = max(result['confidence'], 0.50)

    try:
        geo_res = requests.get(
            "http://ip-api.com/json/{ip}".format(ip=ip),
            params={'fields': 'status,country,city,isp,org,proxy,hosting,query'},
            timeout=5
        )
        geo = geo_res.json()
        if geo.get('status') == 'success':
            if not result['resolved_from_domain']:
                result['confidence'] = max(result['confidence'], 0.65)
            result['ip'] = geo.get('query', ip)
            result['country'] = geo.get('country', 'Unknown')
            result['city'] = geo.get('city', 'Unknown')
            result['isp'] = geo.get('org') or geo.get('isp') or sender_domain or 'Unknown'
            common_mail_host = is_common_mail_infrastructure(result['isp'])
            if result['resolved_from_domain'] and (geo.get('proxy') or geo.get('hosting')):
                result['hosted_mail_infrastructure'] = True
                result['flags'].append('Sender domain resolves to hosted web/cloud infrastructure; not treated as sender IP risk')
            elif geo.get('hosting') and common_mail_host:
                result['hosted_mail_infrastructure'] = True
                result['flags'].append('Sender uses common hosted mail infrastructure')
            elif geo.get('proxy') or geo.get('hosting'):
                result['is_vpn_proxy'] = True
                result['risk_score'] = max(result['risk_score'], 0.45)
                result['flags'].append('Sender IP is a VPN, proxy, or hosting server')
    except Exception as e:
        result['flags'].append(f'Geolocation lookup failed: {str(e)}')

    if result['resolved_from_domain']:
        result['abuse_lookup_status'] = 'skipped_domain_fallback'
    elif ABUSEIPDB_KEY:
        try:
            result['abuse_lookup_status'] = 'requested'
            abuse_res = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5
            )
            abuse_data = abuse_res.json().get('data', {})
            score = abuse_data.get('abuseConfidenceScore', 0)
            result['abuse_score'] = score
            result['confidence'] = 1
            result['risk_score'] = max(result['risk_score'], min(score / 100, 1))
            result['abuse_lookup_status'] = 'ok'
            if score >= 50:
                result['is_malicious'] = True
                result['flags'].append(f'IP flagged: {score}% abuse confidence on AbuseIPDB')
        except Exception as e:
            result['abuse_lookup_status'] = 'error'
            result['flags'].append(f'AbuseIPDB lookup failed: {str(e)}')

    return result
