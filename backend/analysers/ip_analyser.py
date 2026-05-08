import os
import socket

import requests
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY')


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
        "flags": []
    }

    if not ip and sender_domain:
        resolved_ip = resolve_domain_to_ip(sender_domain)
        if resolved_ip:
            ip = resolved_ip
            result['ip'] = resolved_ip
            result['resolved_from_domain'] = True
            result['flags'].append(f'IP resolved from sender domain: {sender_domain}')

    if not ip:
        if sender_domain:
            result['flags'].append('Raw sender IP unavailable; showing sender domain instead')
        return result

    try:
        geo_res = requests.get(
            "http://ip-api.com/json/{ip}".format(ip=ip),
            params={'fields': 'status,country,city,isp,org,proxy,hosting,query'},
            timeout=5
        )
        geo = geo_res.json()
        if geo.get('status') == 'success':
            result['ip'] = geo.get('query', ip)
            result['country'] = geo.get('country', 'Unknown')
            result['city'] = geo.get('city', 'Unknown')
            result['isp'] = geo.get('org') or geo.get('isp') or sender_domain or 'Unknown'
            if geo.get('proxy') or geo.get('hosting'):
                result['is_vpn_proxy'] = True
                result['flags'].append('Sender IP is a VPN, proxy, or hosting server')
    except Exception as e:
        result['flags'].append(f'Geolocation lookup failed: {str(e)}')

    if ABUSEIPDB_KEY:
        try:
            abuse_res = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5
            )
            abuse_data = abuse_res.json().get('data', {})
            score = abuse_data.get('abuseConfidenceScore', 0)
            result['abuse_score'] = score
            if score >= 50:
                result['is_malicious'] = True
                result['flags'].append(f'IP flagged: {score}% abuse confidence on AbuseIPDB')
        except Exception as e:
            result['flags'].append(f'AbuseIPDB lookup failed: {str(e)}')

    return result
