from pathlib import Path


HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".vbs",
    ".js",
    ".jse",
    ".jar",
    ".ps1",
    ".reg",
    ".hta",
}

MEDIUM_RISK_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
    ".doc",
    ".xls",
    ".rtf",
    ".html",
    ".htm",
}


def analyse_attachments(attachments=None) -> dict:
    """
    Score attachment metadata extracted by the extension.
    The backend only receives names/types, not file contents.
    """
    attachments = attachments or []
    risky = []
    flags = []

    for attachment in attachments:
        name = str(attachment.get("name") or "").strip()
        mime_type = str(attachment.get("type") or "").strip()
        extension = Path(name.lower()).suffix
        reasons = []
        severity = "LOW"

        if extension in HIGH_RISK_EXTENSIONS:
            severity = "HIGH"
            reasons.append(f"dangerous executable/script extension: {extension}")
        elif extension in MEDIUM_RISK_EXTENSIONS:
            severity = "MEDIUM"
            reasons.append(f"attachment type often abused in phishing: {extension}")

        lowered_name = name.lower()
        if lowered_name.count(".") >= 2:
            severity = "HIGH" if severity == "MEDIUM" else severity
            reasons.append("double-extension filename")
        if any(word in lowered_name for word in ["invoice", "payment", "receipt", "urgent", "statement"]):
            reasons.append("financial or urgency-themed filename")
        if "macro" in mime_type.lower():
            severity = "MEDIUM" if severity == "LOW" else severity
            reasons.append("macro-capable MIME type")

        if reasons:
            risky.append({
                "name": name or "Unnamed attachment",
                "type": mime_type,
                "severity": severity,
                "reasons": reasons,
            })

    high_count = sum(1 for item in risky if item["severity"] == "HIGH")
    medium_count = sum(1 for item in risky if item["severity"] == "MEDIUM")
    if high_count:
        flags.append(f"{high_count} high-risk attachment(s) detected")
    if medium_count:
        flags.append(f"{medium_count} suspicious attachment(s) detected")

    risk = "HIGH" if high_count else "MEDIUM" if medium_count else "LOW" if attachments else "NONE"
    return {
        "total_attachments": len(attachments),
        "risky_attachments": risky,
        "risk": risk,
        "flags": flags,
    }
