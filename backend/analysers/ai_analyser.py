import json
import os
from typing import Any

import requests


MAX_EMAIL_CHARS = 4500
TIMEOUT_SECONDS = 18


def _clip(value: str, limit: int = MAX_EMAIL_CHARS) -> str:
    value = str(value or "").strip()
    if len(value) <= limit:
        return value
    return value[:limit] + "\n[content truncated for AI analysis]"


def _fallback_summary(subject: str, sender_email: str, risk: dict, intent_result: dict,
                      link_result: dict, prompt_result: dict) -> dict:
    flags = risk.get("flags", [])[:4]
    red_flags = flags[:] if flags else []

    if link_result.get("suspicious_links"):
        red_flags.append("The message contains suspicious or shortened links.")
    if prompt_result.get("risk") in {"MEDIUM", "HIGH"}:
        red_flags.append("The message contains hidden text that may target AI tools.")
    if intent_result.get("goal"):
        red_flags.append(f"Likely goal: {intent_result.get('goal')}.")

    if not red_flags:
        red_flags = ["No major red flags were found by the local analysers."]

    level = risk.get("level", "LOW")
    if level == "HIGH":
        action = "Do not click links or reply. Verify the request through an official website or a trusted contact."
    elif level == "MEDIUM":
        action = "Treat the message with caution and verify the sender before taking action."
    else:
        action = "The message appears low risk, but continue to verify unusual requests."

    return {
        "enabled": False,
        "provider": "local",
        "model": "template",
        "status": "fallback",
        "summary": (
            f"Local analysis for '{subject or 'this email'}' from "
            f"{sender_email or 'an unknown sender'} produced a {level} risk rating."
        ),
        "red_flags": red_flags[:5],
        "recommended_action": action,
        "thesis_note": "This explanation was generated from local ML and rule-based signals because no external AI key was configured.",
    }


def _extract_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


def _build_prompt(subject: str, body: str, sender_email: str, sender_domain: str,
                  risk: dict, ml_result: dict, header_result: dict, ip_result: dict,
                  link_result: dict, intent_result: dict, prompt_result: dict) -> str:
    evidence = {
        "risk": risk,
        "ml": ml_result,
        "headers": header_result,
        "ip": ip_result,
        "links": {
            "total_links": link_result.get("total_links", 0),
            "suspicious_links": link_result.get("suspicious_links", [])[:5],
        },
        "intent": intent_result,
        "prompt_injection": prompt_result,
    }

    return f"""
You are a cybersecurity assistant inside a phishing-detection thesis project.
Use the analyser evidence first. Do not invent facts that are not present.
Return only valid JSON with these keys:
summary: string
red_flags: array of short strings
recommended_action: string
thesis_note: string explaining how this AI layer supports interpretability

Email metadata:
Subject: {subject}
Sender email: {sender_email}
Sender domain: {sender_domain}

Email body:
{_clip(body)}

Existing analyser evidence:
{json.dumps(evidence, indent=2)}
""".strip()


def _call_openai(prompt: str) -> tuple[dict, str]:
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    response = requests.post(
        "https://api.openai.com/v1/responses",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "input": [
                {
                    "role": "system",
                    "content": "Return concise phishing-analysis JSON for a browser extension.",
                },
                {"role": "user", "content": prompt},
            ],
            "text": {"format": {"type": "json_object"}},
        },
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    text = payload.get("output_text", "")
    if not text:
        text = payload["output"][0]["content"][0]["text"]
    return _extract_json(text), model


def _call_deepseek(prompt: str) -> tuple[dict, str]:
    api_key = os.getenv("DEEPSEEK_API_KEY")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY is not configured")

    response = requests.post(
        "https://api.deepseek.com/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return only valid JSON for phishing-analysis explanation.",
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        },
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    text = payload["choices"][0]["message"]["content"]
    return _extract_json(text), model


def analyse_with_ai(subject: str, body: str, sender_email: str, sender_domain: str,
                    risk: dict, ml_result: dict, header_result: dict, ip_result: dict,
                    link_result: dict, intent_result: dict, prompt_result: dict) -> dict:
    """
    Optional LLM explanation layer.

    The local ML/rule analysers remain the source of the detection score. This
    function adds a user-friendly interpretation for the extension and thesis.
    """
    provider = os.getenv("AI_PROVIDER", "local").strip().lower()

    if provider not in {"openai", "deepseek"}:
        return _fallback_summary(subject, sender_email, risk, intent_result, link_result, prompt_result)

    prompt = _build_prompt(
        subject,
        body,
        sender_email,
        sender_domain,
        risk,
        ml_result,
        header_result,
        ip_result,
        link_result,
        intent_result,
        prompt_result,
    )

    try:
        if provider == "openai":
            result, model = _call_openai(prompt)
        else:
            result, model = _call_deepseek(prompt)

        return {
            "enabled": True,
            "provider": provider,
            "model": model,
            "status": "ok",
            "summary": str(result.get("summary", "")).strip(),
            "red_flags": [str(item).strip() for item in result.get("red_flags", []) if str(item).strip()][:5],
            "recommended_action": str(result.get("recommended_action", "")).strip(),
            "thesis_note": str(result.get("thesis_note", "")).strip(),
        }
    except Exception as exc:
        fallback = _fallback_summary(subject, sender_email, risk, intent_result, link_result, prompt_result)
        fallback.update({
            "provider": provider,
            "status": "error",
            "error": str(exc),
        })
        return fallback
