"""
Enhanced Training Pipeline for Phishing Detector v2.0
=====================================================
Improvements over v1:
  - TF-IDF with bigrams & sublinear TF
  - Balanced class weights to reduce false positives
  - Stratified K-Fold cross-validation
  - Full classification report (precision, recall, F1, confusion matrix)
  - Combined TF-IDF + structural features

Usage:
    python3 train_model.py
"""

import pandas as pd
import numpy as np
import pickle
import json
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_recall_curve
)
from scipy.sparse import hstack, csr_matrix

from feature_engineering import extract_structural_features

# ── Load dataset ────────────────────────────────────────────────────────
print("🔄 Loading dataset...")

try:
    data = pd.read_csv("dataset.csv")
    text_col = 'text_combined'
except FileNotFoundError:
    # Fallback: try to build from JSON
    print("⚠️  dataset.csv not found. Generating synthetic training data...")
    data = _generate_fallback_dataset()
    text_col = 'text_combined'

# Convert labels if needed
if data['label'].dtype == 'object':
    data['label'] = data['label'].map({'phishing': 1, 'safe': 0})

print(f"📊 Dataset: {len(data)} emails | {data['label'].mean():.1%} phishing")

# ── Extract structural features ─────────────────────────────────────────
print("🔧 Extracting structural features...")
structural_features = []
feature_names = None

for idx, row in data.iterrows():
    feats = extract_structural_features(str(row[text_col]))
    structural_features.append(feats)
    if feature_names is None:
        feature_names = list(feats.keys())

structural_df = pd.DataFrame(structural_features)
print(f"   → {len(feature_names)} structural features: {feature_names}")

# ── Split data ──────────────────────────────────────────────────────────
X_text = data[text_col]
y = data['label']

X_train_text, X_test_text, y_train, y_test, train_idx, test_idx = train_test_split(
    X_text, y, range(len(data)),
    test_size=0.2, random_state=42, stratify=y
)

# ── TF-IDF vectorization (upgraded) ─────────────────────────────────────
print("📝 Vectorizing with TF-IDF (bigrams, sublinear TF)...")
vectorizer = TfidfVectorizer(
    stop_words='english',
    max_features=7000,
    ngram_range=(1, 2),      # Unigrams + bigrams
    sublinear_tf=True,       # Apply log normalization
    min_df=2,                # Ignore very rare terms
    max_df=0.95,             # Ignore terms in >95% of docs
)

X_train_tfidf = vectorizer.fit_transform(X_train_text)
X_test_tfidf = vectorizer.transform(X_test_text)

# ── Combine TF-IDF + structural features ────────────────────────────────
train_structural = csr_matrix(structural_df.iloc[list(train_idx)].values)
test_structural = csr_matrix(structural_df.iloc[list(test_idx)].values)

X_train_combined = hstack([X_train_tfidf, train_structural])
X_test_combined = hstack([X_test_tfidf, test_structural])

print(f"   → Combined feature matrix: {X_train_combined.shape[1]} features "
      f"({X_train_tfidf.shape[1]} TF-IDF + {train_structural.shape[1]} structural)")

# ── Train model (upgraded) ──────────────────────────────────────────────
print("🧠 Training Logistic Regression (balanced, C=0.5)...")
model = LogisticRegression(
    max_iter=2000,
    class_weight='balanced',  # Handles class imbalance → fewer FP
    C=0.5,                    # Stronger regularization
    random_state=42,
)
model.fit(X_train_combined, y_train)

# ── Cross-validation ────────────────────────────────────────────────────
print("\n📊 Cross-validation (5-fold stratified)...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X_train_combined, y_train, cv=cv, scoring='f1')
print(f"   CV F1 scores: {[f'{s:.3f}' for s in cv_scores]}")
print(f"   Mean CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

# ── Evaluate on test set ────────────────────────────────────────────────
print("\n🎯 Test Set Evaluation:")
predictions = model.predict(X_test_combined)
probabilities = model.predict_proba(X_test_combined)[:, 1]
accuracy = accuracy_score(y_test, predictions)

print(f"\n   Accuracy: {accuracy:.2%}")
print(f"\n   Classification Report:")
print(classification_report(y_test, predictions, target_names=['Safe', 'Phishing']))

cm = confusion_matrix(y_test, predictions)
print(f"   Confusion Matrix:")
print(f"   {'':>15} Pred Safe  Pred Phish")
print(f"   {'Actual Safe':>15}   {cm[0][0]:>5}      {cm[0][1]:>5}")
print(f"   {'Actual Phish':>15}   {cm[1][0]:>5}      {cm[1][1]:>5}")

# ── Threshold analysis ──────────────────────────────────────────────────
print(f"\n🔍 Threshold Analysis:")
precisions, recalls, thresholds = precision_recall_curve(y_test, probabilities)

# Find optimal threshold (precision ≥ 90%, maximize recall)
best_thresh = 0.5
for i, (p, r, t) in enumerate(zip(precisions[:-1], recalls[:-1], thresholds)):
    if p >= 0.90 and r >= 0.80:
        best_thresh = t
        print(f"   Optimal threshold: {t:.3f} → Precision={p:.2%}, Recall={r:.2%}")
        break

# ── Save model artifacts ────────────────────────────────────────────────
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

# Update config with calibrated threshold
with open("config.json", "r") as f:
    config = json.load(f)

config['threshold'] = round(float(best_thresh), 3)
config['suspicious_range'] = [round(float(best_thresh) - 0.20, 3), round(float(best_thresh), 3)]
config['structural_feature_names'] = feature_names

with open("config.json", "w") as f:
    json.dump(config, f, indent=4)

print(f"\n✅ Model saved: model.pkl, vectorizer.pkl")
print(f"✅ Config saved: config.json (threshold={config['threshold']})")
print(f"✅ Training complete!")


def _generate_fallback_dataset():
    """Generate a small synthetic dataset for when dataset.csv is missing."""
    phishing_samples = [
        "URGENT: Your account has been suspended. Click here to verify now!",
        "Dear user, your password expires in 24 hours. Reset immediately at http://secure-login.tk/reset",
        "IT Support: Your mailbox is full. Click http://mail-upgrade.ml to fix. Act now!",
        "Your Apple ID has been locked. Verify account at http://apple-verify.xyz/unlock",
        "ALERT!! Credit card charged $499.99. Claim refund at http://secure-refund.ga/claim",
        "CEO here. Purchase gift cards urgently. Wire transfer $500 immediately.",
        "Confirm your social security number to receive your tax refund.",
        "We detected unauthorized access to your account. Confirm banking details now.",
        "Your PayPal account has been limited. Verify your identity: http://paypa1.tk/verify",
        "Action required: Update your billing information within 24 hours or lose access.",
    ]
    safe_samples = [
        "Hi team, here's the Q4 financial report. Best regards, John",
        "Meeting reminder: Project sync at 3pm tomorrow. Regards, Sarah",
        "Hi Mark, following up on our marketing budget conversation. Cheers!",
        "Your Amazon order has shipped! Track at amazon.com. © 2025 Amazon.com, Inc.",
        "Weekly Newsletter: Top 10 tech trends. Unsubscribe: newsletter.com/unsub",
        "Dear Professor, I'd like to discuss my thesis. Best, Alex",
        "Invitation: Annual company picnic June 15th. © Company Inc. All rights reserved.",
        "Your Uber receipt: $12.50. View at uber.com/receipts. Thanks for riding!",
        "Good morning team, please review the updated security policy. Best regards, IT",
        "Your dentist appointment is tomorrow at 2pm. Call 555-1234 to reschedule.",
    ]

    texts = phishing_samples + safe_samples
    labels = [1] * len(phishing_samples) + [0] * len(safe_samples)

    return pd.DataFrame({'text_combined': texts, 'label': labels})
