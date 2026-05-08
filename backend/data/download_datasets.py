"""
Downloads reliable phishing/spam datasets from Hugging Face (Parquet-based,
no deprecated scripts) and saves them as CSV files ready for training.
"""

from datasets import load_dataset
import pandas as pd
import os

SAVE_DIR = os.path.join(os.path.dirname(__file__), 'datasets')
os.makedirs(SAVE_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Dataset 1: Already downloaded successfully ✅
# zefang-liu/phishing-email-dataset — 18,634 rows
# Skip if already exists
# ─────────────────────────────────────────────────────────────
save_path1 = os.path.join(SAVE_DIR, 'phishing_emails.csv')
if os.path.exists(save_path1):
    df1 = pd.read_csv(save_path1)
    print(f"✅ Dataset 1 already exists: {len(df1)} rows — skipping download")
else:
    print("Downloading Dataset 1...")
    ds1 = load_dataset("zefang-liu/phishing-email-dataset", split="train")
    df1 = ds1.to_pandas()
    df1 = df1.rename(columns={'Email Text': 'text', 'Email Type': 'label'})
    df1['label'] = df1['label'].map({'Phishing Email': 1, 'Safe Email': 0})
    df1 = df1[['text', 'label']].dropna()
    df1['label'] = df1['label'].astype(int)
    df1.to_csv(save_path1, index=False)
    print(f"✅ Dataset 1 saved: {len(df1)} rows")


# ─────────────────────────────────────────────────────────────
# Dataset 2: cybersectony/PhishingEmailDetectionv2.0
# 200,000 rows — content + labels (0=legit_email, 1=phishing_email,
# 2=legit_url, 3=phishing_url) — we keep only email rows (0 and 1)
# Native Parquet, no deprecated script ✅
# ─────────────────────────────────────────────────────────────
print("\nDownloading Dataset 2: cybersectony (200k rows)...")
ds2 = load_dataset("cybersectony/PhishingEmailDetectionv2.0", split="train")
df2 = ds2.to_pandas()

print(f"Columns: {df2.columns.tolist()}")
print(f"Label distribution (raw):\n{df2['label'].value_counts()}\n")

# Keep only email rows (0=legitimate_email, 1=phishing_email)
# Drop URL rows (2, 3) — we only want email content
df2 = df2[df2['label'].isin([0, 1])].copy()
df2 = df2.rename(columns={'content': 'text'})
df2 = df2[['text', 'label']].dropna()
df2['label'] = df2['label'].astype(int)

save_path2 = os.path.join(SAVE_DIR, 'spam_ham.csv')
df2.to_csv(save_path2, index=False)
print(f"✅ Dataset 2 saved: {len(df2)} rows → {save_path2}")
print(f"Label distribution:\n{df2['label'].value_counts()}")


# ─────────────────────────────────────────────────────────────
# Merge both into one master training file
# ─────────────────────────────────────────────────────────────
print("\nMerging datasets...")
combined = pd.concat([df1, df2], ignore_index=True)
combined.drop_duplicates(subset=['text'], inplace=True)
combined.dropna(inplace=True)
combined['label'] = combined['label'].astype(int)

# Shuffle the combined dataset
combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

save_combined = os.path.join(SAVE_DIR, 'combined_training.csv')
combined.to_csv(save_combined, index=False)

print(f"\n✅ Combined dataset saved: {len(combined):,} rows → {save_combined}")
print(f"Final label distribution:\n{combined['label'].value_counts()}")
print("\n🎉 All done! You can now run: python ml/train.py") 
