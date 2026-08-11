import argparse
import json
import os
import re
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data" / "datasets"
MODEL_DIR = BASE_DIR / "model"
EVALUATION_DIR = BASE_DIR / "evaluation"
DEFAULT_DATASET = DATA_DIR / "combined_training.csv"
DEFAULT_MODEL_PATH = MODEL_DIR / "phishguard_model.pkl"
DEFAULT_REPORT_PATH = EVALUATION_DIR / "train_metrics.json"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
EVALUATION_DIR.mkdir(parents=True, exist_ok=True)


def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_dataset(path: Path, limit: int | None = None) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} does not exist. Build it first with: "
            "cd backend && source .venv/bin/activate && python data/download_datasets.py"
        )

    df = pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip")
    df.columns = df.columns.str.lower().str.strip()
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{path} must contain text and label columns. Found: {list(df.columns)}")

    df = df[["text", "label"] + (["source"] if "source" in df.columns else [])].dropna()
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]
    df["text_clean"] = df["text"].map(clean_text)
    df = df[df["text_clean"].str.len() > 0]

    if limit and len(df) > limit:
        df = df.sample(n=limit, random_state=42)

    return df.reset_index(drop=True)


def build_sample_weights(df: pd.DataFrame, manual_weight: float, feedback_weight: float) -> pd.Series:
    weights = pd.Series(1.0, index=df.index)
    if "source" not in df.columns:
        return weights

    source = df["source"].astype(str).str.lower()
    manual_mask = source.str.startswith("manual:")
    feedback_mask = source.str.contains("feedback", regex=False)

    if manual_weight > 1:
        weights.loc[manual_mask] = manual_weight
    if feedback_weight > 1:
        weights.loc[feedback_mask] = feedback_weight

    return weights


def build_classifier(model_name: str):
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )

    if model_name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise SystemExit("xgboost is not installed. Install requirements or use --model gbm.") from exc

        return XGBClassifier(
            n_estimators=350,
            learning_rate=0.08,
            max_depth=5,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42,
        )

    return GradientBoostingClassifier(
        n_estimators=220,
        learning_rate=0.08,
        max_depth=4,
        random_state=42,
    )


def build_pipeline(args):
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=args.max_features,
            ngram_range=(1, args.ngram_max),
            stop_words="english",
            sublinear_tf=True,
            min_df=args.min_df,
        )),
        ("clf", build_classifier(args.model)),
    ])


def evaluate_model(model, x_test, y_test, elapsed_train_seconds):
    started = time.perf_counter()
    y_pred = model.predict(x_test)
    inference_seconds = time.perf_counter() - started

    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(x_test)[:, 1]
    else:
        y_score = y_pred

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )
    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )

    try:
        auc_roc = roc_auc_score(y_test, y_score)
    except ValueError:
        auc_roc = None

    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "macro_precision": round(float(macro_precision), 4),
        "macro_recall": round(float(macro_recall), 4),
        "macro_f1": round(float(macro_f1), 4),
        "auc_roc": round(float(auc_roc), 4) if auc_roc is not None else None,
        "train_seconds": round(elapsed_train_seconds, 2),
        "latency_ms_per_email": round((inference_seconds / max(len(x_test), 1)) * 1000, 3),
        "confusion_matrix": {
            "labels": ["legitimate", "phishing_or_spam"],
            "matrix": confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist(),
        },
        "classification_report": classification_report(
            y_test,
            y_pred,
            target_names=["Legitimate", "Phishing/Spam"],
            output_dict=True,
            zero_division=0,
        ),
    }


def train(args):
    df = load_dataset(args.dataset, limit=args.limit)
    sample_weights = build_sample_weights(df, args.manual_weight, args.feedback_weight)
    print(f"Loaded {len(df):,} rows from {args.dataset}")
    print(f"Label distribution:\n{df['label'].value_counts().sort_index()}")

    x_train, x_test, y_train, y_test, weights_train, weights_test = train_test_split(
        df["text_clean"],
        df["label"],
        sample_weights,
        test_size=args.test_size,
        random_state=42,
        stratify=df["label"],
    )

    pipeline = build_pipeline(args)
    print(f"\nTraining {args.model} model...")
    started = time.perf_counter()
    fit_kwargs = {}
    if (weights_train != 1).any():
        fit_kwargs["clf__sample_weight"] = weights_train
    pipeline.fit(x_train, y_train, **fit_kwargs)
    train_seconds = time.perf_counter() - started

    metrics = evaluate_model(pipeline, x_test, y_test, train_seconds)
    report = {
        "dataset": str(args.dataset),
        "model": args.model,
        "sample_size": len(df),
        "train_size": len(x_train),
        "test_size": len(x_test),
        "test_fraction": args.test_size,
        "tfidf": {
            "max_features": args.max_features,
            "ngram_range": [1, args.ngram_max],
            "min_df": args.min_df,
        },
        "source_counts": df["source"].value_counts().to_dict() if "source" in df.columns else {},
        "label_counts": df["label"].value_counts().sort_index().to_dict(),
        "sample_weighting": {
            "manual_weight": args.manual_weight,
            "feedback_weight": args.feedback_weight,
            "weighted_training_rows": int((weights_train != 1).sum()),
            "weighted_test_rows": int((weights_test != 1).sum()),
        },
        "metrics": metrics,
    }

    joblib.dump(pipeline, args.output)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n--- Model Results ---")
    print(json.dumps(metrics, indent=2))
    print(f"\nModel saved to {args.output}")
    print(f"Training report saved to {args.report}")


def main():
    parser = argparse.ArgumentParser(description="Train the PhishGuard email phishing classifier.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--model", choices=["gbm", "random_forest", "xgboost"], default="gbm")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--ngram-max", type=int, choices=[1, 2, 3], default=3)
    parser.add_argument("--min-df", type=int, default=2)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--limit", type=int, default=None, help="Optional row limit for quick test training.")
    parser.add_argument("--manual-weight", type=float, default=1.0, help="Optional weight for rows imported from backend/data/manual.")
    parser.add_argument("--feedback-weight", type=float, default=3.0, help="Optional weight for exported feedback CSV rows.")
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
