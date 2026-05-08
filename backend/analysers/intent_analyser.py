import re


INTENTS = [
    {
        "goal": "Steal login credentials",
        "patterns": [
            r"\blog[\s-]?in\b",
            r"\bsign[\s-]?in\b",
            r"\bpassword\b",
            r"\baccount (?:locked|suspended|restricted|verification)\b",
            r"\bverify (?:your )?account\b",
            r"\breset (?:your )?password\b",
        ],
        "dangerous_step": "Clicking a sign-in or verification link",
        "advice": "Open the service by typing its official website yourself, not from this email.",
    },
    {
        "goal": "Collect payment or banking details",
        "patterns": [
            r"\bpayment\b",
            r"\binvoice\b",
            r"\bbank\b",
            r"\bwire transfer\b",
            r"\bcard details\b",
            r"\bbilling\b",
            r"\boverdue\b",
        ],
        "dangerous_step": "Sending money or updating payment details",
        "advice": "Confirm payment requests using a trusted phone number or official portal.",
    },
    {
        "goal": "Push an urgent unsafe action",
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bwithin \d+ hours\b",
            r"\bfinal notice\b",
            r"\bact now\b",
            r"\bdeadline\b",
        ],
        "dangerous_step": "Acting before verifying the sender",
        "advice": "Slow down and verify the request through a separate trusted channel.",
    },
    {
        "goal": "Harvest personal information",
        "patterns": [
            r"\bsocial security\b",
            r"\bpassport\b",
            r"\bstudent id\b",
            r"\bdate of birth\b",
            r"\bverification code\b",
            r"\b2fa\b",
            r"\botp\b",
        ],
        "dangerous_step": "Replying with sensitive personal information",
        "advice": "Do not send codes or identity documents through email unless independently verified.",
    },
]


def analyse_intent(subject: str, body: str) -> dict:
    """
    Explain what the email appears to be trying to make the reader do.
    This is deterministic and transparent so the UI can show a clear threat story.
    """
    text = f"{subject or ''}\n{body or ''}".lower()
    matches = []

    for intent in INTENTS:
        evidence = []
        for pattern in intent["patterns"]:
            if re.search(pattern, text):
                evidence.append(pattern.replace("\\b", "").replace("\\", ""))
        if evidence:
            matches.append({
                "goal": intent["goal"],
                "dangerous_step": intent["dangerous_step"],
                "advice": intent["advice"],
                "evidence": evidence[:4],
                "confidence": min(95, 45 + len(evidence) * 15),
            })

    if not matches:
        return {
            "goal": "No clear malicious goal detected",
            "dangerous_step": "None identified",
            "advice": "Still verify unexpected requests before clicking links or sending information.",
            "confidence": 20,
            "matches": [],
            "flags": [],
        }

    matches.sort(key=lambda item: item["confidence"], reverse=True)
    top = matches[0]

    return {
        "goal": top["goal"],
        "dangerous_step": top["dangerous_step"],
        "advice": top["advice"],
        "confidence": top["confidence"],
        "matches": matches,
        "flags": [f"Likely goal: {top['goal']}"],
    }
