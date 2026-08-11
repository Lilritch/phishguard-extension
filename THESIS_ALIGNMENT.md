# PhishGuard-XAI Thesis Alignment

This file maps the current repository to the proposal titled:

`PhishGuard-XAI: A Machine Learning and LLM-Augmented Explainable Framework for Real-Time Multi-Signal Phishing Detection in Email Clients`

## What The Current Project Already Supports

- **Live Gmail deployment:** Chrome Extension Manifest V3 runs inside Gmail and can show both popup and inline Gmail-panel results.
- **Gmail API/OAuth header retrieval:** The extension can request read-only Gmail metadata headers through `chrome.identity` and the Gmail API once a Google OAuth client ID is configured.
- **Backend serving:** Flask API exposes `/health`, `/analyse`, and `/methodology` on port `5001`.
- **Four core signals:** The backend extracts NLP, header authentication, sender IP/reputation, and URL heuristic signals.
- **Sender-aware link analysis:** URL risk now checks whether visible links stay on the sender's real domain/subdomains and flags sensitive external redirects, shorteners, IP URLs, and brand-like mismatches.
- **CWAF evidence:** `risk.fusion.signals` now returns each signal's score, confidence, base weight, and adaptive weight.
- **VSR evidence:** The extension sends the sender's last three verdicts, and the backend can upgrade a LOW verdict to MEDIUM if recent sender history includes HIGH.
- **Counterfactual explanations:** `risk.counterfactuals` shows which changes would reduce the risk score, such as fixing authentication or removing suspicious links.
- **Uncertainty reporting:** `risk.uncertainty` reports evidence completeness and explains missing or partial signals.
- **Anonymised thesis evidence logging:** The extension stores local scan metadata, signal weights, counterfactuals, uncertainty, and verdicts without storing email body text.
- **User feedback dataset:** `Mark safe` and `Mark phishing` buttons collect explicitly labelled hard negatives and hard positives, then export them as retrainable CSV rows.
- **Auxiliary security signals:** Prompt-injection, tracking-pixel, attachment, and phishing-intent checks are included as additional evidence.
- **LLM-augmented explanation layer:** `AI_PROVIDER=local`, `openai`, or `deepseek` can produce user-facing explanation text.
- **Repeatable ML metrics:** `backend/ml/evaluate.py` exports accuracy, precision, recall, F1, macro-F1, AUC-ROC, latency, and a confusion matrix.
- **Thesis screenshots:** The popup, Gmail panel, `/methodology`, and `/analyse` JSON response can all be captured as implementation evidence.

## What The Proposal Claims But Still Needs Stronger Evidence

- **True SHAP and LIME explanations:** The current project now has counterfactual/user-facing explanations, but not real SHAP/LIME attribution yet.
- **DistilBERT model:** The current runnable backend serves the scikit-learn model, not a fine-tuned DistilBERT pipeline.
- **Model comparison experiment:** XGBoost, Random Forest, GBM, and DistilBERT metrics still need a repeatable experiment script and result table.
- **Calibration evidence:** The current model returns probabilities, but there is no calibration curve, Brier score, or reliability diagram yet.
- **Ablation study:** The repo needs a script that runs C1-C8 signal configurations and exports precision, recall, F1, latency, and McNemar test results.
- **User study materials:** Consent form, task sheet, answer key, trust questionnaire, and anonymised results template still need to be added.
- **Dataset/model versioning:** DVC or MLflow is not yet configured, so dataset and model provenance evidence is limited.
- **Dependency lock file:** `requirements.txt` is now pinned, but a full lock file would make reproduction even stronger.

## Recommended Next Implementation Order

1. Add XGBoost as the main classical baseline and retrain the saved model with the current environment.
2. Configure the Gmail API OAuth client ID and capture examples where authenticated headers reduce false positives.
3. Add lightweight SHAP explanations for the tree model and display top features in the popup/Gmail panel.
4. Add an ablation runner for NLP-only, header-only, IP-only, URL-only, static fusion, and CWAF+VSR.
5. Add a `thesis/evidence/` folder for exported JSON, screenshots, metrics CSV files, feedback CSV files, and study forms.
6. Add DVC or MLflow after the first stable result table exists.

## Suggested Thesis Wording

Use careful wording until SHAP, LIME, DistilBERT, and the user study are fully implemented:

> The current PhishGuard-XAI prototype implements a live Gmail extension, Gmail API/OAuth header retrieval, multi-signal phishing analysis, sender-aware link validation, CWAF adaptive fusion, VSR sender-history stabilisation, counterfactual risk-reduction explanations, uncertainty reporting, anonymised evidence logging, and user-feedback hard-example collection. The remaining thesis experiments will extend this prototype with formal SHAP/LIME attribution, model comparison, ablation testing, and a controlled user study.
