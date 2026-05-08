import re


INJECTION_PHRASES = [
    r"ignore (?:all )?(?:previous|prior) instructions",
    r"disregard (?:all )?(?:previous|prior) instructions",
    r"system prompt",
    r"developer message",
    r"you are now",
    r"do not reveal",
    r"assistant must",
    r"hidden instruction",
]


def _find_hidden_html(body_html: str) -> list:
    findings = []
    if not body_html:
        return findings

    hidden_patterns = [
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"opacity\s*:\s*0(?:\.0+)?",
        r"font-size\s*:\s*0",
        r"color\s*:\s*(?:white|#fff|#ffffff|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
        r"height\s*:\s*0",
        r"width\s*:\s*0",
    ]

    for pattern in hidden_patterns:
        if re.search(pattern, body_html, re.IGNORECASE):
            findings.append(f"Hidden HTML/CSS pattern: {pattern}")

    return findings


def analyse_prompt_injection(body: str, body_html: str = "") -> dict:
    """
    Detect hidden or suspicious instructions that could manipulate AI summaries
    or assistants that read the email.
    """
    text = f"{body or ''}\n{body_html or ''}"
    findings = _find_hidden_html(body_html)

    for pattern in INJECTION_PHRASES:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(f"AI instruction phrase: {pattern}")

    zero_width_count = len(re.findall(r"[\u200b-\u200f\ufeff]", text))
    if zero_width_count >= 8:
        findings.append(f"Unusual hidden zero-width characters: {zero_width_count}")

    risk = "NONE"
    if findings:
        risk = "HIGH" if len(findings) >= 3 else "MEDIUM"

    return {
        "risk": risk,
        "findings": findings,
        "flags": ["Possible hidden AI prompt-injection content"] if findings else [],
    }
