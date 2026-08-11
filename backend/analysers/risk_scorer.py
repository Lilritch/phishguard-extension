BASE_WEIGHTS = {
    "nlp": 0.40,
    "header": 0.25,
    "ip": 0.20,
    "url": 0.15,
}

VERDICTS = {
    "HIGH": "🔴 HIGH RISK — Likely phishing or scam",
    "MEDIUM": "🟡 MEDIUM RISK — Treat with caution",
    "LOW": "🟢 LOW RISK — Appears legitimate",
}


def _clamp(value, minimum=0.0, maximum=1.0):
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, numeric))


def _round(value):
    return round(_clamp(value), 3)


def _nlp_signal(ml_result):
    phishing_probability = _clamp(ml_result.get("confidence", 0) / 100)
    evidence = [
        f"ML label: {ml_result.get('label', 'Unknown')}",
        f"Phishing probability: {round(phishing_probability * 100, 1)}%",
    ]
    return {
        "label": "NLP body analysis",
        "score": _round(phishing_probability),
        "confidence": _round(phishing_probability),
        "base_weight": BASE_WEIGHTS["nlp"],
        "adaptive_weight": 0,
        "evidence": evidence,
    }


def _header_signal(header_result):
    spf = str(header_result.get("spf", "UNKNOWN")).upper()
    dkim = str(header_result.get("dkim", "UNKNOWN")).upper()
    dmarc = str(header_result.get("dmarc", "UNKNOWN")).upper()
    checks = [spf, dkim, dmarc]
    confidence = len([check for check in checks if check != "UNKNOWN"]) / 3

    risk = 0
    if spf == "FAIL":
        risk += 0.40
    if dkim == "FAIL":
        risk += 0.35
    if dmarc == "FAIL":
        risk += 0.35
    elif dmarc == "NONE":
        risk += 0.12
    evidence = [f"SPF {spf}", f"DKIM {dkim}", f"DMARC {dmarc}"]

    if header_result.get("reply_to_mismatch"):
        risk += 0.25
        evidence.append("Reply-To domain mismatch")

    if confidence == 0:
        evidence.append("Authentication data not visible to the Gmail content script")

    return {
        "label": "Header authentication",
        "score": _round(min(risk, 1)),
        "confidence": _round(confidence),
        "base_weight": BASE_WEIGHTS["header"],
        "adaptive_weight": 0,
        "evidence": evidence,
    }


def _ip_signal(ip_result):
    risk = _clamp(ip_result.get("risk_score", 0))
    evidence = []

    if ip_result.get("ip"):
        evidence.append(f"Sender IP: {ip_result.get('ip')}")
    elif ip_result.get("sender_domain"):
        evidence.append(f"Sender domain: {ip_result.get('sender_domain')}")

    if ip_result.get("is_malicious"):
        risk = max(risk, 0.85)
        evidence.append(f"AbuseIPDB score: {ip_result.get('abuse_score', 0)}%")
    if ip_result.get("is_vpn_proxy"):
        risk = max(risk, 0.45)
        evidence.append("VPN, proxy, or hosting infrastructure")
    elif ip_result.get("hosted_mail_infrastructure"):
        evidence.append("Common hosted mail infrastructure")

    if "confidence" in ip_result:
        confidence = _clamp(ip_result.get("confidence"))
    elif ip_result.get("ip") and ip_result.get("country") != "Unknown":
        confidence = 0.65
    elif ip_result.get("ip"):
        confidence = 0.50
    elif ip_result.get("sender_domain"):
        confidence = 0.25
    else:
        confidence = 0

    if not evidence:
        evidence.append("No sender IP or domain reputation signal available")

    return {
        "label": "IP reputation",
        "score": _round(risk),
        "confidence": _round(confidence),
        "base_weight": BASE_WEIGHTS["ip"],
        "adaptive_weight": 0,
        "evidence": evidence,
    }


def _url_signal(link_result):
    links = int(link_result.get("total_links", 0) or 0)
    suspicious_links = link_result.get("suspicious_links", []) or []
    triggered_reasons = sum(len(item.get("reasons", [])) for item in suspicious_links)
    score = min(triggered_reasons / 4, 1) if links else 0
    confidence = 1 if links else 0

    evidence = [f"{links} URL(s) found"]
    if suspicious_links:
        evidence.append(f"{len(suspicious_links)} suspicious URL(s)")
    else:
        evidence.append("No suspicious URL heuristic triggered")

    return {
        "label": "URL heuristics",
        "score": _round(score),
        "confidence": _round(confidence),
        "base_weight": BASE_WEIGHTS["url"],
        "adaptive_weight": 0,
        "evidence": evidence,
    }


def _auxiliary_adjustment(intent_result, prompt_result, tracking_result, attachment_result):
    adjustment = 0
    flags = []

    intent_result = intent_result or {}
    if intent_result.get("matches") and intent_result.get("confidence", 0) >= 70:
        adjustment += min(_clamp(intent_result.get("confidence", 0) / 100) * 0.04, 0.04)
        flags.extend(intent_result.get("flags", [])[:1])

    prompt_result = prompt_result or {}
    if prompt_result.get("risk") == "HIGH":
        adjustment += 0.08
        flags.append("Hidden AI prompt-injection patterns detected")

    tracking_result = tracking_result or {}
    if tracking_result.get("risk") == "HIGH":
        adjustment += 0.05
        flags.append("Multiple hidden tracking pixels detected")
    elif tracking_result.get("risk") == "MEDIUM":
        adjustment += 0.03
        flags.append("Possible hidden tracking pixel detected")

    attachment_result = attachment_result or {}
    if attachment_result.get("risk") == "HIGH":
        adjustment += 0.10
        flags.append("High-risk attachment detected")
    elif attachment_result.get("risk") == "MEDIUM":
        adjustment += 0.06
        flags.append("Suspicious attachment detected")

    return _round(min(adjustment, 0.18)), flags


def _level_from_score(score):
    if score >= 0.60:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    return "LOW"


def _build_uncertainty(signals, ip_result):
    weighted_confidence = sum(
        values["base_weight"] * values["confidence"]
        for values in signals.values()
    )
    completeness = _round(weighted_confidence / sum(BASE_WEIGHTS.values()))
    uncertainty = _round(1 - completeness)
    missing = [
        values["label"]
        for values in signals.values()
        if values["confidence"] <= 0
    ]
    partial = [
        values["label"]
        for values in signals.values()
        if 0 < values["confidence"] < 0.60
    ]
    reasons = []

    if missing:
        reasons.append(f"Missing signal(s): {', '.join(missing)}")
    if partial:
        reasons.append(f"Partial signal(s): {', '.join(partial)}")
    if (ip_result or {}).get("abuse_lookup_status") == "error":
        reasons.append("External IP reputation lookup failed")
    elif (ip_result or {}).get("abuse_lookup_status") == "not_configured":
        reasons.append("AbuseIPDB API key is not configured or was not used")
    if not reasons:
        reasons.append("All core signals contributed usable evidence")

    if uncertainty >= 0.60:
        level = "HIGH"
    elif uncertainty >= 0.30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "level": level,
        "score": round(uncertainty * 100),
        "evidence_completeness": round(completeness * 100),
        "reasons": reasons,
    }


def _signal_contribution(signal):
    return signal["score"] * signal["adaptive_weight"]


def _new_score_after_reduction(final_score, reduction):
    return round(max(final_score - reduction, 0) * 100)


def _build_counterfactuals(signals, auxiliary_score, vsr, final_score):
    candidates = []

    nlp = signals["nlp"]
    nlp_reduction = _signal_contribution(nlp)
    if nlp_reduction >= 0.04:
        candidates.append({
            "action": "Reduce suspicious wording in the email body",
            "risk_reduction": round(nlp_reduction * 100, 1),
            "new_score": _new_score_after_reduction(final_score, nlp_reduction),
            "explanation": "The NLP signal would contribute less if urgency, credential requests, or phishing-like wording were absent.",
        })

    header = signals["header"]
    header_reduction = _signal_contribution(header)
    if header_reduction >= 0.04:
        candidates.append({
            "action": "Pass SPF, DKIM, and DMARC authentication",
            "risk_reduction": round(header_reduction * 100, 1),
            "new_score": _new_score_after_reduction(final_score, header_reduction),
            "explanation": "Authenticated headers would reduce the header-risk contribution.",
        })

    ip = signals["ip"]
    ip_reduction = _signal_contribution(ip)
    if ip_reduction >= 0.04:
        candidates.append({
            "action": "Use reputable non-abusive sending infrastructure",
            "risk_reduction": round(ip_reduction * 100, 1),
            "new_score": _new_score_after_reduction(final_score, ip_reduction),
            "explanation": "A clean sender IP or domain reputation would lower the IP-risk contribution.",
        })

    url = signals["url"]
    url_reduction = _signal_contribution(url)
    if url_reduction >= 0.04:
        candidates.append({
            "action": "Remove or replace suspicious links",
            "risk_reduction": round(url_reduction * 100, 1),
            "new_score": _new_score_after_reduction(final_score, url_reduction),
            "explanation": "Direct official links without shorteners or suspicious URL structure would lower URL risk.",
        })

    if auxiliary_score >= 0.04:
        candidates.append({
            "action": "Remove auxiliary red flags",
            "risk_reduction": round(auxiliary_score * 100, 1),
            "new_score": _new_score_after_reduction(final_score, auxiliary_score),
            "explanation": "Intent, prompt-injection, tracking-pixel, or attachment warnings added extra risk.",
        })

    if vsr.get("applied"):
        candidates.append({
            "action": "Build a clean sender history over future scans",
            "risk_reduction": round(max(final_score - 0.39, 0) * 100, 1),
            "new_score": 39,
            "explanation": "VSR prevents one clean-looking email from immediately resetting a recently high-risk sender.",
        })

    candidates = sorted(candidates, key=lambda item: item["risk_reduction"], reverse=True)
    if candidates:
        return candidates[:4]

    return [{
        "action": "No single counterfactual dominates this verdict",
        "risk_reduction": 0,
        "new_score": round(final_score * 100),
        "explanation": "The current verdict is driven by weak or incomplete signals rather than one removable red flag.",
    }]


def _normalise_sender_history(sender_history):
    if not isinstance(sender_history, list):
        return []
    normalised = []
    for item in sender_history[:3]:
        level = str(item.get("level", item) if isinstance(item, dict) else item).upper()
        if level in {"HIGH", "MEDIUM", "LOW"}:
            normalised.append(level)
    return normalised


def _apply_vsr(level, score, sender_history):
    history = _normalise_sender_history(sender_history)
    applied = level == "LOW" and "HIGH" in history
    if not applied:
        if level != "LOW":
            reason = "VSR made no change because the current CWAF verdict is already MEDIUM or HIGH."
        else:
            reason = "No previous high-risk verdict in the sender's last three scans."
        return level, score, {
            "enabled": True,
            "applied": False,
            "history": history,
            "reason": reason,
        }

    return "MEDIUM", max(score, 0.40), {
        "enabled": True,
        "applied": True,
        "history": history,
        "reason": "Previous high-risk sender history upgraded the verdict from LOW to MEDIUM.",
    }


def _has_hard_evidence(signals, intent_result, prompt_result, attachment_result):
    return any([
        signals["header"]["confidence"] > 0 and signals["header"]["score"] >= 0.35,
        signals["ip"]["confidence"] > 0 and signals["ip"]["score"] >= 0.45,
        signals["url"]["confidence"] > 0 and signals["url"]["score"] >= 0.25,
        (intent_result or {}).get("matches") and (intent_result or {}).get("confidence", 0) >= 70,
        (prompt_result or {}).get("risk") == "HIGH",
        (attachment_result or {}).get("risk") in {"MEDIUM", "HIGH"},
    ])


def calculate_risk_score(ml_result: dict, header_result: dict,
                         ip_result: dict, link_result: dict,
                         intent_result: dict = None,
                         prompt_result: dict = None,
                         tracking_result: dict = None,
                         attachment_result: dict = None,
                         sender_history: list = None) -> dict:
    """
    Confidence-Weighted Adaptive Fusion (CWAF) with Verdict Stability Rule.

    CWAF combines the proposal's four core signals: NLP, headers, IP reputation,
    and URL heuristics. Extra project signals are reported as auxiliary
    adjustments so the thesis algorithm remains auditable.
    """
    signals = {
        "nlp": _nlp_signal(ml_result or {}),
        "header": _header_signal(header_result or {}),
        "ip": _ip_signal(ip_result or {}),
        "url": _url_signal(link_result or {}),
    }

    raw_weights = {
        name: values["base_weight"] * values["confidence"]
        for name, values in signals.items()
    }
    total_weight = sum(raw_weights.values())

    if total_weight:
        for name, values in signals.items():
            values["adaptive_weight"] = _round(raw_weights[name] / total_weight)
        cwaf_score = sum(values["score"] * values["adaptive_weight"] for values in signals.values())
    else:
        cwaf_score = 0

    auxiliary_score, auxiliary_flags = _auxiliary_adjustment(
        intent_result,
        prompt_result,
        tracking_result,
        attachment_result,
    )
    final_score = _round(min(cwaf_score + auxiliary_score, 1))
    calibrated = False
    calibration_reason = "No legitimate-borderline calibration was needed."
    hard_evidence = _has_hard_evidence(signals, intent_result, prompt_result, attachment_result)
    if (
        str((ml_result or {}).get("label", "")).upper() == "LEGITIMATE"
        and final_score < 0.45
        and not hard_evidence
    ):
        final_score = min(final_score, 0.39)
        calibrated = True
        calibration_reason = "Borderline legitimate NLP result capped because no hard phishing indicator was present."
    elif (
        final_score < 0.65
        and not hard_evidence
        and signals["nlp"]["adaptive_weight"] >= 0.95
    ):
        final_score = min(final_score, 0.39)
        calibrated = True
        calibration_reason = "NLP-only borderline suspicion capped because no hard phishing indicator was present."
    original_level = _level_from_score(final_score)
    level, final_score, vsr = _apply_vsr(original_level, final_score, sender_history or [])

    flags = []
    for name, values in signals.items():
        if values["confidence"] > 0 and values["score"] >= 0.50:
            flags.append(f"{values['label']}: elevated risk ({round(values['score'] * 100)}%)")
    flags.extend(auxiliary_flags)
    flags.extend((header_result or {}).get("flags", []))
    flags.extend((ip_result or {}).get("flags", []))
    flags.extend((prompt_result or {}).get("flags", []))
    flags.extend((tracking_result or {}).get("flags", []))
    flags.extend((attachment_result or {}).get("flags", []))

    if not flags:
        flags.append("No major red flags found by active signals")

    if vsr["applied"]:
        flags.append("VSR upgraded this sender because recent history includes a high-risk verdict")

    uncertainty = _build_uncertainty(signals, ip_result or {})
    counterfactuals = _build_counterfactuals(signals, auxiliary_score, vsr, final_score)

    return {
        "score": round(final_score * 100),
        "level": level,
        "verdict": VERDICTS[level],
        "flags": list(dict.fromkeys(flags)),
        "uncertainty": uncertainty,
        "counterfactuals": counterfactuals,
        "fusion": {
            "algorithm": "CWAF+VSR",
            "core_score": round(cwaf_score * 100, 1),
            "auxiliary_adjustment": round(auxiliary_score * 100, 1),
            "thresholds": {
                "phishing": ">= 60",
                "suspicious": "40-59",
                "legitimate": "< 40",
            },
            "signals": signals,
            "vsr": vsr,
            "calibration": {
                "applied": calibrated,
                "reason": calibration_reason,
            },
        },
    }
