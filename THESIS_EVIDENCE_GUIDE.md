# PhishGuard Thesis Evidence Guide

Use this file as a checklist when collecting proof for your thesis report and presentation.

For dataset expansion and retraining commands, see `DATASET_TRAINING_GUIDE.md`.

## Screenshots To Capture

1. Chrome extension loaded from `chrome://extensions`.
2. Flask backend running in the terminal on port `5001`.
3. Backend health check at `http://127.0.0.1:5001/health`.
4. Gmail message before scanning.
5. PhishGuard popup after scanning an email.
6. Gmail inline PhishGuard panel after scanning an email.
7. AI explanation section showing summary, red flags, and recommended action.
8. CWAF signal-weight section showing adaptive weights.
9. Counterfactual risk-reduction section.
10. Uncertainty/evidence-completeness section.
11. Exported anonymised evidence JSON from the popup.
12. Exported labelled feedback CSV after using `Mark safe` and `Mark phishing`.
13. OAuth/Gmail API configuration in `manifest.json` with the client ID partly hidden in screenshots.
14. High-risk, medium-risk, and low-risk scan examples if you can collect all three.
15. Terminal output from model evaluation or training.
16. Project code structure showing `backend`, `extension`, and `backend/analysers`.

## Evidence You Can Still Collect Later

You do not need screenshots from the exact moment you originally built each feature. For a thesis, it is acceptable to capture evidence after implementation as long as the screenshots show the final system working.

Good evidence includes:

- screenshots of the working extension
- screenshots of backend API responses
- screenshots of terminal commands
- code snippets from important files
- model evaluation metrics
- architecture diagrams
- dataset description tables
- test email examples and their scan results

## Suggested Commands For Evidence

Start the backend:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python app.py
```

Check backend health:

```bash
curl http://127.0.0.1:5001/health
```

Export ML evaluation metrics:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python ml/evaluate.py --limit 2000
```

This writes repeatable thesis evidence to:

```text
backend/ml/evaluation/latest_metrics.json
```

Capture the framework methodology endpoint:

```bash
curl http://127.0.0.1:5001/methodology
```

Run a sample analysis request:

```bash
curl -X POST http://127.0.0.1:5001/analyse \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent account verification required",
    "body": "Your account will be suspended. Click http://bit.ly/verify-now and confirm your password.",
    "senderEmail": "security@example-alert.com",
    "senderDomain": "example-alert.com",
    "headers": "From: Security <security@example-alert.com>",
    "senderHistory": [{"level": "HIGH", "score": 88}]
  }'
```

In the JSON response, capture the `risk.fusion` object. It shows the CWAF core score, auxiliary adjustment, adaptive signal weights, and VSR decision.
Also capture `risk.counterfactuals` and `risk.uncertainty`; these are the clearest evidence for the personalised XAI contribution.

## Exporting Thesis Evidence From The Extension

After scanning several Gmail messages:

1. Open the PhishGuard-XAI popup.
2. Click `Export evidence`.
3. Keep the downloaded JSON file with your thesis screenshots.

The evidence JSON stores metadata, verdicts, CWAF weights, uncertainty, VSR status, and counterfactual summaries. It does not store the full email body text.

If you used `Mark safe` or `Mark phishing`, the export also downloads a CSV of labelled feedback examples. That CSV does include the email text because it is meant for retraining, so keep it private and describe it as a local labelled thesis dataset.

To retrain with that feedback:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python data/download_datasets.py
python ml/train.py --feedback-weight 5
```

## How To Explain The AI Integration

Use this wording in your thesis:

> PhishGuard uses a hybrid architecture. The machine learning model and rule-based analysers produce the primary phishing risk score, while the optional LLM integration generates a user-friendly explanation, red flags, and recommended action. This improves interpretability without making the external AI model the only detection mechanism.

## API Key Configuration

By default, the project uses a local explanation template:

```bash
AI_PROVIDER=local
```

For OpenAI:

```bash
AI_PROVIDER=openai
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4.1-mini
```

For DeepSeek:

```bash
AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=your_key_here
DEEPSEEK_MODEL=deepseek-chat
```
