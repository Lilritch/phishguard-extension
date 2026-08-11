import argparse
import json
import time
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from predict import clean_text, load_model


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET = BASE_DIR.parent / "data" / "datasets" / "combined_training.csv"
DEFAULT_OUTPUT = BASE_DIR / "evaluation" / "latest_metrics.json"


def _normalise_labels(series):
    if series.dtype == object:
        mapping = {
            "spam": 1,
            "phishing": 1,
            "phishing/spam": 1,
            "malicious": 1,
            "ham": 0,
            "legitimate": 0,
            "safe": 0,
        }
        return series.astype(str).str.strip().str.lower().map(mapping).fillna(series)
    return series


def load_dataset(path, limit):
    df = pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip")
    df.columns = df.columns.str.lower().str.strip()

    text_col = next((col for col in df.columns if col in {"text", "message", "body", "content"}), None)
    label_col = next((col for col in df.columns if col in {"label", "spam", "target", "class"}), None)
    if not text_col or not label_col:
        raise ValueError(f"Dataset must contain text and label columns. Found: {list(df.columns)}")

    df = df[[text_col, label_col]].dropna()
    df = df.rename(columns={text_col: "text", label_col: "label"})
    df["label"] = _normalise_labels(df["label"]).astype(int)
    df = df[df["label"].isin([0, 1])]

    if limit and len(df) > limit:
        df = df.sample(n=limit, random_state=42)

    return df.reset_index(drop=True)


def evaluate(dataset_path, limit, output_path):
    df = load_dataset(dataset_path, limit)
    model = load_model()

    text = df["text"].map(clean_text).tolist()
    y_true = df["label"].tolist()

    started = time.perf_counter()
    probabilities = model.predict_proba(text)[:, 1]
    elapsed = time.perf_counter() - started

    y_pred = (probabilities >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )

    try:
        auc_roc = roc_auc_score(y_true, probabilities)
    except ValueError:
        auc_roc = None

    metrics = {
        "dataset": str(dataset_path),
        "sample_size": len(df),
        "positive_label": "phishing_or_spam",
        "threshold": 0.5,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "macro_precision": round(float(macro_precision), 4),
        "macro_recall": round(float(macro_recall), 4),
        "macro_f1": round(float(macro_f1), 4),
        "auc_roc": round(float(auc_roc), 4) if auc_roc is not None else None,
        "latency_ms_per_email": round((elapsed / max(len(df), 1)) * 1000, 3),
        "confusion_matrix": {
            "labels": ["legitimate", "phishing_or_spam"],
            "matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Evaluate the PhishGuard ML model for thesis evidence.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--limit", type=int, default=2000, help="Sample size for quick repeatable evaluation.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    metrics = evaluate(args.dataset, args.limit, args.output)
    print(json.dumps(metrics, indent=2))
    print(f"\nSaved metrics to {args.output}")


if __name__ == "__main__":
    main()
