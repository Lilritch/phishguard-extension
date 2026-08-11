import joblib
import os
import re
import sys

try:
    import sklearn._loss._loss as sklearn_loss
    sys.modules.setdefault('_loss', sklearn_loss)
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'phishguard_model.pkl')

_model = None

def load_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model

def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\S+@\S+', ' EMAIL ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def predict_email(subject: str, body: str) -> dict:
    """
    Predict if an email is phishing/spam.
    Returns: dict with label, confidence, and risk_level
    """
    model = load_model()
    text = f"{subject} {body}"
    text_clean = clean_text(text)
    
    proba = model.predict_proba([text_clean])[0]
    confidence = float(proba[1])  # Probability of being phishing/spam
    label = "PHISHING/SPAM" if confidence >= 0.5 else "LEGITIMATE"
    
    if confidence >= 0.75:
        risk_level = "HIGH"
    elif confidence >= 0.45:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
     
    return {
        "label": label,
        "confidence": round(confidence * 100, 1),
        "risk_level": risk_level
    }
