import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
import re

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '..', 'data', 'datasets')
MODEL_DIR = os.path.join(BASE_DIR, 'model')
os.makedirs(MODEL_DIR, exist_ok=True)

def clean_text(text):
    """Clean and normalise email text."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)   # Replace URLs
    text = re.sub(r'\S+@\S+', ' EMAIL ', text)          # Replace emails
    text = re.sub(r'[^a-z\s]', ' ', text)               # Remove special chars
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def load_datasets():
    """Load and combine phishing + spam/ham datasets."""
    dfs = []

    # Load spam/ham dataset
    spam_path = os.path.join(DATA_DIR, 'spam_ham.csv')
    if os.path.exists(spam_path):
        df1 = pd.read_csv(spam_path)
        # Normalise column names - common variations
        df1.columns = df1.columns.str.lower().str.strip()
        if 'message' in df1.columns and 'label' in df1.columns:
            df1 = df1[['message', 'label']].rename(columns={'message': 'text'})
            df1['label'] = df1['label'].map({'spam': 1, 'ham': 0})
        elif 'text' in df1.columns and 'spam' in df1.columns:
            df1 = df1[['text', 'spam']].rename(columns={'spam': 'label'})
        dfs.append(df1)
        print(f"Loaded spam/ham dataset: {len(df1)} records")

    # Load phishing dataset
    phish_path = os.path.join(DATA_DIR, 'phishing_raw.csv')
    if os.path.exists(phish_path):
        df2 = pd.read_csv(phish_path)
        df2.columns = df2.columns.str.lower().str.strip()
        # Try to find text column
        text_col = next((c for c in df2.columns if 'text' in c or 'body' in c or 'content' in c), None)
        if text_col:
            df2 = df2[[text_col]].rename(columns={text_col: 'text'})
            df2['label'] = 1  # All phishing
            dfs.append(df2)
            print(f"Loaded phishing dataset: {len(df2)} records")

    if not dfs:
        raise FileNotFoundError("No datasets found in data/datasets/. Please download them first.")

    combined = pd.concat(dfs, ignore_index=True)
    combined.dropna(subset=['text'], inplace=True)
    combined['label'] = combined['label'].astype(int)

    print(f"\nCombined dataset: {len(combined)} records")
    print(f"Label distribution:\n{combined['label'].value_counts()}")
    return combined

def train():
    """Train and save the phishing/spam detection model."""
    print("Loading datasets...")
    df = load_datasets()

    # Clean text
    print("Cleaning text...")
    df['text_clean'] = df['text'].apply(clean_text)

    X = df['text_clean']
    y = df['label']

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build pipeline: TF-IDF + Gradient Boosting
    print("Training model...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=15000,
            ngram_range=(1, 2),
            stop_words='english',
            sublinear_tf=True
        )),
        ('clf', GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=4,
            random_state=42
        ))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    print("\n--- Model Results ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing/Spam']))

    # Save model
    model_path = os.path.join(MODEL_DIR, 'phishguard_model.pkl')
    joblib.dump(pipeline, model_path)
    print(f"\nModel saved to {model_path}")

if __name__ == "__main__":
    train() 