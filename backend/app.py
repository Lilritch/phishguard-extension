from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

from ml.predict import predict_email
from analysers.header_analyser import analyse_headers
from analysers.ip_analyser import analyse_ip
from analysers.link_scanner import extract_links, scan_links
from analysers.risk_scorer import calculate_risk_score
from analysers.intent_analyser import analyse_intent
from analysers.prompt_injection_analyser import analyse_prompt_injection
from analysers.ai_analyser import analyse_with_ai

app = Flask(__name__)
CORS(app)  # Allow Chrome extension to call this API

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "PhishGuard backend running",
        "routes": {
            "health": "GET /health",
            "analyse": "POST /analyse"
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "PhishGuard backend running ✅", "version": "3.0"})

@app.route('/analyse', methods=['POST'])
def analyse():
    """
    Main endpoint. Receives email data from Chrome extension,
    returns full risk analysis.
    """
    data = request.get_json(silent=True) or {}

    subject = data.get('subject', '')
    body = data.get('body', '')
    body_html = data.get('body_html', '')
    raw_headers = data.get('headers', '')
    sender_email = data.get('senderEmail', '')
    sender_domain = data.get('senderDomain', '')

    if not sender_domain and sender_email and '@' in sender_email:
        sender_domain = sender_email.split('@')[-1]

    # Run all analysers
    ml_result = predict_email(subject, body)
    header_result = analyse_headers(raw_headers)
    if not sender_domain:
        sender_domain = header_result.get('sender_domain')
    ip_result = analyse_ip(header_result.get('sender_ip'), sender_domain=sender_domain)
    links = extract_links(body)
    link_result = scan_links(links)
    intent_result = analyse_intent(subject, body)
    prompt_result = analyse_prompt_injection(body, body_html)
    risk = calculate_risk_score(
        ml_result,
        header_result,
        ip_result,
        link_result,
        intent_result,
        prompt_result
    )
    ai_result = analyse_with_ai(
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
        prompt_result
    )

    return jsonify({
        "risk": risk,
        "ml": ml_result,
        "headers": header_result,
        "ip": ip_result,
        "links": link_result,
        "intent": intent_result,
        "prompt_injection": prompt_result,
        "ai_explanation": ai_result
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001)
