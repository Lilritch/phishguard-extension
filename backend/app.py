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
    return jsonify({"status": "PhishGuard backend running ✅"})

@app.route('/analyse', methods=['POST'])
def analyse():
    """
    Main endpoint. Receives email data from Chrome extension,
    returns full risk analysis.
    """
    data = request.get_json(silent=True) or {}

    subject = data.get('subject', '')
    body = data.get('body', '')
    raw_headers = data.get('headers', '')

    # Run all analysers
    ml_result = predict_email(subject, body)
    header_result = analyse_headers(raw_headers)
    ip_result = analyse_ip(header_result.get('sender_ip'))
    links = extract_links(body)
    link_result = scan_links(links)
    risk = calculate_risk_score(ml_result, header_result, ip_result, link_result)

    return jsonify({
        "risk": risk,
        "ml": ml_result,
        "headers": header_result,
        "ip": ip_result,
        "links": link_result
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001)
