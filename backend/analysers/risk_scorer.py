def calculate_risk_score(ml_result: dict, header_result: dict,
                          ip_result: dict, link_result: dict,
                          intent_result: dict = None,
                          prompt_result: dict = None,
                          tracking_result: dict = None,
                          attachment_result: dict = None) -> dict:
    """
    Combine all signals into a single risk score (0-100) and level.
    """
    score = 0
    flags = []

    
    ml_confidence = ml_result.get('confidence', 0)
    score += (ml_confidence / 100) * 40
    if ml_confidence >= 70:
        flags.append(f"AI model: {ml_confidence}% confidence this is phishing/spam")

    
    if header_result.get('spf') == 'FAIL':
        score += 10
        flags.append('SPF check failed')
    if header_result.get('dkim') == 'FAIL':
        score += 10
        flags.append('DKIM check failed')
    if header_result.get('dmarc') in ['FAIL', 'NONE']:
        score += 5
        flags.append(f"DMARC: {header_result.get('dmarc')}")
    if header_result.get('reply_to_mismatch'):
        score += 8
        flags.append('Reply-To address does not match sender')

    
    if ip_result.get('is_vpn_proxy'):
        score += 8
        flags.append('Sent through VPN/proxy/hosting server')
    if ip_result.get('is_malicious'):
        score += 12
        flags.append(f"Sender IP flagged: {ip_result.get('abuse_score')}% abuse score")

    
    suspicious_count = len(link_result.get('suspicious_links', []))
    link_score = min(suspicious_count * 5, 15)
    score += link_score
    if suspicious_count > 0:
        flags.append(f"{suspicious_count} suspicious link(s) in email")

    
    intent_result = intent_result or {}
    if intent_result.get('matches'):
        intent_confidence = intent_result.get('confidence', 0)
        score += min((intent_confidence / 100) * 10, 10)
        flags.append(intent_result.get('flags', [])[0])

    
    prompt_result = prompt_result or {}
    if prompt_result.get('risk') == 'HIGH':
        score += 10
        flags.append('Hidden AI prompt-injection patterns detected')
    elif prompt_result.get('risk') == 'MEDIUM':
        score += 5
        flags.append('Possible hidden AI prompt-injection content')

    tracking_result = tracking_result or {}
    if tracking_result.get('risk') == 'HIGH':
        score += 8
        flags.append('Multiple hidden tracking pixels detected')
    elif tracking_result.get('risk') == 'MEDIUM':
        score += 4
        flags.append('Possible hidden tracking pixel detected')

    attachment_result = attachment_result or {}
    if attachment_result.get('risk') == 'HIGH':
        score += 12
        flags.append('High-risk attachment detected')
    elif attachment_result.get('risk') == 'MEDIUM':
        score += 7
        flags.append('Suspicious attachment detected')

    
    score = min(round(score), 100)
 
    
    if score >= 65:
        level = "HIGH"
        verdict = "🔴 HIGH RISK — Likely phishing or scam"
    elif score >= 35:
        level = "MEDIUM"
        verdict = "🟡 MEDIUM RISK — Treat with caution"
    else:
        level = "LOW"
        verdict = "🟢 LOW RISK — Appears legitimate"

    return {
        "score": score,
        "level": level,
        "verdict": verdict,
        "flags": (
            flags
            + header_result.get('flags', [])
            + ip_result.get('flags', [])
            + prompt_result.get('flags', [])
            + tracking_result.get('flags', [])
            + attachment_result.get('flags', [])
        )
    } 
