import re

def analyse_headers(raw_headers: str) -> dict:
    """
    Parse email headers to check SPF, DKIM, DMARC,
    extract sender IP and return domain info.
    """
    results = {
        "spf": "UNKNOWN",
        "dkim": "UNKNOWN",
        "dmarc": "UNKNOWN",
        "sender_ip": None,
        "sender_domain": None,
        "reply_to_mismatch": False,
        "authentication_available": False,
        "header_source": "unknown",
        "flags": []
    }

    if not raw_headers:
        return results

    headers_lower = raw_headers.lower()
    source_match = re.search(r'x-phishguard-header-source:\s*([\w_-]+)', headers_lower)
    if source_match:
        results['header_source'] = source_match.group(1)
    auth_tokens = ['authentication-results:', 'spf=', 'dkim=', 'dmarc=']
    results['authentication_available'] = any(token in headers_lower for token in auth_tokens)

    # SPF check
    if 'spf=pass' in headers_lower or re.search(r'received-spf:\s*pass\b', headers_lower):
        results['spf'] = 'PASS'
    elif (
        'spf=fail' in headers_lower or
        'spf=softfail' in headers_lower or
        re.search(r'received-spf:\s*(?:fail|softfail)\b', headers_lower)
    ):
        results['spf'] = 'FAIL'
        results['flags'].append('SPF authentication failed')

    # DKIM check
    if 'dkim=pass' in headers_lower:
        results['dkim'] = 'PASS'
    elif 'dkim=fail' in headers_lower:
        results['dkim'] = 'FAIL'
        results['flags'].append('DKIM signature invalid')

    # DMARC check
    if 'dmarc=pass' in headers_lower:
        results['dmarc'] = 'PASS'
    elif 'dmarc=fail' in headers_lower:
        results['dmarc'] = 'FAIL'
        results['flags'].append('DMARC policy violation')
    elif 'dmarc=none' in headers_lower:
        results['dmarc'] = 'NONE'
        results['flags'].append('No DMARC record found')
    elif not results['authentication_available']:
        results['flags'].append('Authentication results unavailable in Gmail view')

    # Extract sender IP from Received headers
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, raw_headers)
    # Filter out private/localhost IPs
    public_ips = [ip for ip in ips if not (
        ip.startswith('127.') or
        ip.startswith('10.') or
        ip.startswith('192.168.') or
        ip.startswith('172.')
    )]
    if public_ips:
        results['sender_ip'] = public_ips[-1]  # Last hop = original sender

    sender_domain_match = re.search(r'x-sender-domain:\s*([\w\.-]+)', headers_lower)
    if sender_domain_match:
        results['sender_domain'] = sender_domain_match.group(1)

    from_match = re.search(r'from:.*?@([\w\.-]+)', headers_lower)
    if from_match and not results['sender_domain']:
        results['sender_domain'] = from_match.group(1)

    
    from_match2 = re.search(r'from:.*?<(.+?)>', headers_lower)
    reply_match = re.search(r'reply-to:.*?<(.+?)>', headers_lower)
    if from_match2 and reply_match:
        from_domain = from_match2.group(1).split('@')[-1]
        reply_domain = reply_match.group(1).split('@')[-1]
        if from_domain != reply_domain:
            results['reply_to_mismatch'] = True
            results['flags'].append(f'Reply-To domain mismatch: {reply_domain}')

    return results 
