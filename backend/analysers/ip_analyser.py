import requests
import os
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY')

def analyse_ip(ip: str) -> dict:
    """
    Look up IP reputation, geolocation, and VPN/proxy status.
    """
    result = {
        "ip": ip,
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "is_vpn_proxy": False,
        "abuse_score": 0,
        "is_malicious": False,
        "flags": []
    }

    if not ip:
        return result

    # Geolocation + VPN detection via ip-api.com (free)
    try:
        geo_res = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting",
            timeout=5
        )
        geo = geo_res.json()
        if geo.get('status') == 'success':
            result['country'] = geo.get('country', 'Unknown')
            result['city'] = geo.get('city', 'Unknown')
            result['isp'] = geo.get('isp', 'Unknown')
            if geo.get('proxy') or geo.get('hosting'):
                result['is_vpn_proxy'] = True
                result['flags'].append('Sender IP is a VPN, proxy, or hosting server')
    except Exception as e:
        result['flags'].append(f'Geolocation lookup failed: {str(e)}')

    # Abuse reputation via AbuseIPDB
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
                result['flags'].append(f'IP has {score}% abuse confidence score on AbuseIPDB')
        except Exception as e:
            result['flags'].append(f'AbuseIPDB lookup failed: {str(e)}')

    return result 