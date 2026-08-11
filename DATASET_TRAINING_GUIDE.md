# Dataset And Training Guide

Use this workflow when you want to add more email datasets and retrain PhishGuard-XAI.

## Do You Need To Download Datasets First?

Yes, if the dataset is not already present locally.

The project trains from:

```text
backend/data/datasets/combined_training.csv
```

So the workflow is:

1. Download or add source datasets.
2. Build `combined_training.csv`.
3. Train the model from `combined_training.csv`.
4. Save metrics for thesis evidence.

## Install Optional Download Tools

The main backend can run without Hugging Face tools. Install these only when downloading datasets:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
pip install -r requirements-data.txt
```

## Download Supported Hugging Face Datasets

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python data/download_datasets.py --download-hf
```

This currently supports:

- `zefang-liu/phishing-email-dataset`
- `cybersectony/PhishingEmailDetectionv2.0`

The script keeps only email rows, normalises labels, removes duplicates, and writes:

```text
backend/data/datasets/combined_training.csv
backend/data/reports/dataset_manifest.json
```

## Add Manual CSV Datasets

For datasets from Kaggle, Zenodo, SpamAssassin, Enron, Nazario, or your own labelled emails:

1. Convert them to CSV.
2. Make sure they have one text column and one label column.
3. Put the CSV files here:

```text
backend/data/manual/
```

Accepted text column names:

```text
text, message, body, content, email, email text
```

Accepted label values:

```text
0, legitimate, safe, ham
1, phishing, spam, malicious
```

Then rebuild the combined dataset:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python data/download_datasets.py
```

## Add Hard Negatives And Hard Positives From Gmail

The extension now has feedback buttons:

```text
Mark safe      -> label 0, hard negative
Mark phishing  -> label 1, hard positive
```

Use `Mark safe` for legitimate emails that the detector wrongly treats as risky, such as:

- university admissions and enrolment emails
- Supabase, GitHub, Vercel, Stripe, or cloud service notifications
- bank notifications that are genuine
- immigration, invoices, support tickets, receipts, and account alerts

Use `Mark phishing` for phishing emails that imitate those same categories:

- fake university application or fee emails
- fake cloud dashboard pause, billing, or login emails
- fake invoice/payment emails
- credential reset, MFA, and account-verification scams

After you collect examples:

1. Open the PhishGuard popup.
2. Click `Export evidence`.
3. A feedback CSV downloads with a name like:

```text
phishguard-feedback-training-2026-08-12.csv
```

4. Move that CSV into:

```text
backend/data/manual/
```

5. Rebuild the combined dataset:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python data/download_datasets.py
```

The feedback CSV already has columns accepted by the importer:

```text
text,label,source,senderDomain,createdAt
```

## Train The Model

Default training uses Gradient Boosting:

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python ml/train.py
```

Feedback rows are weighted by default so your hard examples matter more than a few ordinary public dataset rows. To make them even stronger during experiments:

```bash
python ml/train.py --feedback-weight 5
```

If you put carefully labelled hard examples in other manual CSV files, you can weight all manual rows too:

```bash
python ml/train.py --manual-weight 2 --feedback-weight 5
```

Train XGBoost:

```bash
python ml/train.py --model xgboost
```

Train Random Forest:

```bash
python ml/train.py --model random_forest
```

Quick test training on a small sample:

```bash
python ml/train.py --limit 5000
```

Training saves:

```text
backend/ml/model/phishguard_model.pkl
backend/ml/evaluation/train_metrics.json
```

## Evaluate The Current Saved Model

```bash
cd /Users/apple/Documents/phishguard-extension/backend
source .venv/bin/activate
python ml/evaluate.py --limit 2000
```

## Thesis Advice

Do not judge reliability only by dataset size. For a stronger thesis, report:

- dataset source table
- duplicate-removal count
- label distribution
- train/test split method
- external test dataset results
- precision, recall, F1, macro-F1, AUC-ROC
- confusion matrix
- latency per email

Best method:

```text
Train on several public datasets.
Keep one dataset separate as an external test set.
Use live APIs only as auxiliary CWAF signals, not as the main training label source.
Use your own feedback CSV as a hard-example dataset and report how it changes false positives and false negatives.
```
