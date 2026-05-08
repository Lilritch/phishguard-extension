def calculate_risk_score(ml_result: dict, header_result: dict,
                          ip_result: dict, link_result: dict) -> dict:
    """
    Combine all signals into a single risk score (0-100) and level.
    """
    score = 0
    flags = []

    # ML model confidence (max 40 points)
    ml_confidence = ml_result.get('confidence', 0)
    score += (ml_confidence / 100) * 40
    if ml_confidence >= 70:
        flags.append(f"AI model: {ml_confidence}% confidence this is phishing/spam")

    # Header analysis (max 25 points)
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

    # IP analysis (max 20 points)
    if ip_result.get('is_vpn_proxy'):
        score += 8
        flags.append('Sent through VPN/proxy/hosting server')
    if ip_result.get('is_malicious'):
        score += 12
        flags.append(f"Sender IP flagged: {ip_result.get('abuse_score')}% abuse score")

    # Link analysis (max 15 points)
    suspicious_count = len(link_result.get('suspicious_links', []))
    link_score = min(suspicious_count * 5, 15)
    score += link_score
    if suspicious_count > 0:
        flags.append(f"{suspicious_count} suspicious link(s) in email")

    # Cap at 100
    score = min(round(score), 100)
 
    # Determine level
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
        "flags": flags + header_result.get('flags', []) + ip_result.get('flags', [])
    } 