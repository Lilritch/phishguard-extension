"""
Build a thesis-ready PhishGuard training dataset.

This script supports two workflows:
1. Merge existing CSV files already in backend/data/datasets and backend/data/manual.
2. Optionally download supported Hugging Face datasets first with --download-hf.

Every output row is normalised to:
    text,label,source

where label is:
    0 = legitimate/safe email
    1 = phishing/spam email
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATASET_DIR = BASE_DIR / "datasets"
MANUAL_DIR = BASE_DIR / "manual"
REPORT_DIR = BASE_DIR / "reports"
COMBINED_PATH = DATASET_DIR / "combined_training.csv"
MANIFEST_PATH = REPORT_DIR / "dataset_manifest.json"

DATASET_DIR.mkdir(parents=True, exist_ok=True)
MANUAL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


HF_SOURCES = {
    "zefang-liu/phishing-email-dataset": {
        "output": "phishing_emails.csv",
        "text_candidates": ["email text", "text", "body", "content", "message"],
        "label_candidates": ["email type", "label", "labels", "class"],
        "label_map": {
            "phishing email": 1,
            "safe email": 0,
            "phishing": 1,
            "safe": 0,
        },
    },
    "cybersectony/PhishingEmailDetectionv2.0": {
        "output": "cybersectony_email.csv",
        "text_candidates": ["content", "text", "body", "message"],
        "label_candidates": ["label", "labels", "class"],
        # The dataset includes URL rows. Keep only email labels 0 and 1.
        "allowed_numeric_labels": {0, 1},
        "label_map": {
            0: 0,
            1: 1,
            "legitimate_email": 0,
            "phishing_email": 1,
        },
    },
}

LABEL_MAP = {
    0: 0,
    1: 1,
    "0": 0,
    "1": 1,
    "ham": 0,
    "legitimate": 0,
    "legit": 0,
    "safe": 0,
    "safe email": 0,
    "legitimate email": 0,
    "legitimate_email": 0,
    "non-phishing": 0,
    "not phishing": 0,
    "spam": 1,
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "phishing email": 1,
    "phishing_email": 1,
    "phishing/spam": 1,
}


def _normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(column).strip().lower() for column in df.columns]
    return df


def _first_existing(columns: list[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return None


def _map_label(value, extra_map=None):
    if pd.isna(value):
        return None
    maps = {}
    maps.update(LABEL_MAP)
    if extra_map:
        maps.update(extra_map)

    if value in maps:
        return maps[value]

    key = str(value).strip().lower()
    return maps.get(key)


def normalise_dataframe(
    df: pd.DataFrame,
    source: str,
    text_candidates: list[str] | None = None,
    label_candidates: list[str] | None = None,
    label_map: dict | None = None,
    allowed_numeric_labels: set[int] | None = None,
) -> pd.DataFrame:
    df = _normalise_columns(df)
    text_candidates = text_candidates or ["text", "message", "body", "content", "email", "email text"]
    label_candidates = label_candidates or ["label", "labels", "class", "target", "spam", "email type"]

    text_col = _first_existing(list(df.columns), text_candidates)
    label_col = _first_existing(list(df.columns), label_candidates)
    if not text_col or not label_col:
        raise ValueError(
            f"{source} must contain text and label columns. "
            f"Found columns: {list(df.columns)}"
        )

    normalised = df[[text_col, label_col]].rename(columns={text_col: "text", label_col: "label"})
    if allowed_numeric_labels is not None:
        numeric_labels = pd.to_numeric(normalised["label"], errors="coerce")
        normalised = normalised[numeric_labels.isin(allowed_numeric_labels)].copy()

    normalised["label"] = normalised["label"].map(lambda value: _map_label(value, label_map))
    normalised["text"] = normalised["text"].astype(str).str.replace("\x00", " ", regex=False).str.strip()
    normalised["source"] = source
    normalised = normalised.dropna(subset=["text", "label"])
    normalised = normalised[normalised["text"].str.len() >= 8]
    normalised["label"] = normalised["label"].astype(int)
    return normalised[["text", "label", "source"]]


def download_huggingface_sources(selected_sources: list[str] | None = None) -> list[Path]:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit(
            "The Hugging Face `datasets` package is not installed.\n"
            "Install it first with:\n"
            "  cd backend && source .venv/bin/activate && pip install datasets pyarrow\n"
            "Then rerun this script with --download-hf."
        ) from exc

    selected = selected_sources or list(HF_SOURCES.keys())
    saved_paths = []
    for source_name in selected:
        if source_name not in HF_SOURCES:
            raise ValueError(f"Unsupported Hugging Face source: {source_name}")

        config = HF_SOURCES[source_name]
        output_path = DATASET_DIR / config["output"]
        print(f"Downloading {source_name}...")
        dataset = load_dataset(source_name, split="train")
        raw_df = dataset.to_pandas()
        normalised = normalise_dataframe(
            raw_df,
            source=source_name,
            text_candidates=config.get("text_candidates"),
            label_candidates=config.get("label_candidates"),
            label_map=config.get("label_map"),
            allowed_numeric_labels=config.get("allowed_numeric_labels"),
        )
        normalised.to_csv(output_path, index=False)
        saved_paths.append(output_path)
        print(f"Saved {len(normalised):,} rows -> {output_path}")
    return saved_paths


def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, encoding_errors="replace", on_bad_lines="skip")


def collect_csv_sources(include_manual: bool = True) -> list[tuple[Path, str]]:
    sources = []
    for path in sorted(DATASET_DIR.glob("*.csv")):
        if path.name == COMBINED_PATH.name:
            continue
        sources.append((path, path.stem))

    if include_manual:
        for path in sorted(MANUAL_DIR.glob("*.csv")):
            sources.append((path, f"manual:{path.stem}"))

    return sources


def build_combined_dataset(include_manual: bool = True) -> pd.DataFrame:
    frames = []
    manifest_sources = []

    for path, source_name in collect_csv_sources(include_manual=include_manual):
        print(f"Loading {path}...")
        raw_df = read_csv(path)
        normalised = normalise_dataframe(raw_df, source=source_name)
        frames.append(normalised)
        manifest_sources.append({
            "source": source_name,
            "path": str(path),
            "rows_after_normalisation": len(normalised),
            "label_counts": normalised["label"].value_counts().sort_index().to_dict(),
        })

    if not frames:
        raise FileNotFoundError(
            "No dataset CSVs found. Put CSV files in backend/data/datasets or "
            "backend/data/manual, or run with --download-hf."
        )

    combined = pd.concat(frames, ignore_index=True)
    combined["dedupe_key"] = combined["text"].str.lower().str.replace(r"\s+", " ", regex=True).str[:500]
    before_dedup = len(combined)
    combined = combined.drop_duplicates(subset=["dedupe_key"]).drop(columns=["dedupe_key"])
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    combined.to_csv(COMBINED_PATH, index=False)

    manifest = {
        "combined_path": str(COMBINED_PATH),
        "rows_before_dedup": before_dedup,
        "rows_after_dedup": len(combined),
        "duplicates_removed": before_dedup - len(combined),
        "label_counts": combined["label"].value_counts().sort_index().to_dict(),
        "sources": manifest_sources,
        "label_definition": {
            "0": "legitimate_or_safe_email",
            "1": "phishing_or_spam_email",
        },
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("\nCombined dataset ready")
    print(f"Rows before dedup: {before_dedup:,}")
    print(f"Rows after dedup:  {len(combined):,}")
    print(f"Label counts: {combined['label'].value_counts().sort_index().to_dict()}")
    print(f"Saved: {COMBINED_PATH}")
    print(f"Manifest: {MANIFEST_PATH}")
    return combined


def main():
    parser = argparse.ArgumentParser(description="Download, import, deduplicate, and merge PhishGuard training data.")
    parser.add_argument("--download-hf", action="store_true", help="Download supported Hugging Face datasets first.")
    parser.add_argument("--hf-source", action="append", choices=sorted(HF_SOURCES), help="Specific Hugging Face source to download. Can be repeated.")
    parser.add_argument("--no-manual", action="store_true", help="Ignore CSV files in backend/data/manual.")
    args = parser.parse_args()

    if args.download_hf:
      download_huggingface_sources(args.hf_source)

    build_combined_dataset(include_manual=not args.no_manual)


if __name__ == "__main__":
    main()
