# PhishGuard Thesis Evidence Guide

Use this file as a checklist when collecting proof for your thesis report and presentation.

## Screenshots To Capture

1. Chrome extension loaded from `chrome://extensions`.
2. Flask backend running in the terminal on port `5001`.
3. Backend health check at `http://127.0.0.1:5001/health`.
4. Gmail message before scanning.
5. PhishGuard popup after scanning an email.
6. Gmail inline PhishGuard panel after scanning an email.
7. AI explanation section showing summary, red flags, and recommended action.
8. High-risk, medium-risk, and low-risk scan examples if you can collect all three.
9. Terminal output from model evaluation or training.
10. Project code structure showing `backend`, `extension`, and `backend/analysers`.

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
cd /Users/apple/projects/phishguard-extension
source backend/venv/bin/activate
python backend/app.py
```

Check backend health:

```bash
curl http://127.0.0.1:5001/health
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
    "headers": "From: Security <security@example-alert.com>"
  }'
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
