"""
Threshold Calibration Script
=============================
Sweeps decision thresholds from 0.3 → 0.8 on the existing model
and prints precision/recall/F1 for each. Saves the optimal threshold
(maximizing precision while keeping recall ≥ 85%) to config.json.

Usage:
    python3 calibrate_threshold.py
"""

import pickle
import json
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score

# ── Load artifacts ──────────────────────────────────────────────────────
print("Loading model and vectorizer...")
with open("model.pkl", "rb") as f:
    model = pickle.load(f)
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

# ── Test emails for calibration ─────────────────────────────────────────
# These simulate the kinds of emails that cause false positives
test_emails = [
    # True phishing emails (label = 1)
    ("URGENT: Your account has been suspended. Click here to verify: http://paypa1-secure.xyz/login", 1),
    ("Immediate action required! Your password expires in 24 hours. Reset now at http://secure-login.tk/reset", 1),
    ("Dear customer, we detected unauthorized access. Confirm your banking details at http://bank-verify.top/secure", 1),
    ("IT Support: Your mailbox is full. Click http://mail-upgrade.ml/fix to avoid losing emails. Act now!", 1),
    ("CEO here. I need you to purchase gift cards urgently. Wire transfer $500 immediately.", 1),
    ("Your Apple ID has been locked. Verify account at http://apple-id-verify.xyz/unlock", 1),
    ("ALERT!! Your credit card was charged $499.99. If unauthorized click http://secure-refund.ga/claim", 1),
    ("Confirm your social security number to receive your tax refund: http://irs-refund.pw/ssn", 1),

    # True safe emails (label = 0) — these are the ones that get FALSE POSITIVES
    ("Hi team, here's the Q4 financial report. Best regards, John", 0),
    ("Your monthly bank statement is ready. View it at chase.com/statements. Thank you for banking with us.", 0),
    ("Meeting reminder: Project sync at 3pm tomorrow. Please review the attached slides. Regards, Sarah", 0),
    ("Hi Mark, just following up on our conversation about the marketing budget. Let me know your thoughts. Cheers!", 0),
    ("Your Amazon order #123-456-789 has shipped! Track at amazon.com/tracking. © 2025 Amazon.com, Inc.", 0),
    ("Weekly Newsletter: Top 10 tech trends this week. Unsubscribe: newsletter.techcrunch.com/unsub", 0),
    ("Dear Professor Smith, I wanted to discuss my thesis proposal. Could we schedule a meeting? Best, Alex", 0),
    ("Invitation: You're invited to our annual company picnic on June 15th. RSVP by clicking the link below. © Company Inc. All rights reserved.", 0),
    ("Hi, your Uber receipt for today's trip is $12.50. View details at uber.com/receipts. Thanks for riding!", 0),
    ("Good morning team, please review the updated security policy attached. Contact IT support if you have questions. Best regards, IT Department", 0),
    ("Your LinkedIn connection request was accepted by Jane Doe. See her profile at linkedin.com/in/janedoe", 0),
    ("Reminder: Your dentist appointment is tomorrow at 2pm. Call 555-1234 to reschedule. Thank you!", 0),
]

emails = [e[0] for e in test_emails]
labels = np.array([e[1] for e in test_emails])

# ── Vectorize ───────────────────────────────────────────────────────────
X = vectorizer.transform(emails)
probabilities = model.predict_proba(X)[:, 1]

# ── Sweep thresholds ────────────────────────────────────────────────────
print("\n" + "=" * 65)
print(f"{'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'FP':>5} {'FN':>5}")
print("=" * 65)

best_threshold = 0.5
best_score = 0

thresholds = np.arange(0.30, 0.81, 0.05)

for thresh in thresholds:
    preds = (probabilities >= thresh).astype(int)
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)
    f1 = f1_score(labels, preds, zero_division=0)

    fp = sum((preds == 1) & (labels == 0))
    fn = sum((preds == 0) & (labels == 1))

    print(f"{thresh:>10.2f} {prec:>10.2%} {rec:>10.2%} {f1:>10.2%} {fp:>5} {fn:>5}")

    # Optimize: maximize precision while keeping recall >= 85%
    if rec >= 0.85 and prec > best_score:
        best_score = prec
        best_threshold = round(thresh, 2)

print("=" * 65)
print(f"\n🎯 Optimal threshold: {best_threshold}")
print(f"   (maximizes precision with recall ≥ 85%)")

# ── Save to config ──────────────────────────────────────────────────────
with open("config.json", "r") as f:
    config = json.load(f)

config['threshold'] = float(round(best_threshold, 2))
config['suspicious_range'] = [float(round(best_threshold - 0.20, 2)), float(round(best_threshold, 2))]

with open("config.json", "w") as f:
    json.dump(config, f, indent=4)

print(f"\n✅ Saved to config.json")
print(f"   threshold: {config['threshold']}")
print(f"   suspicious_range: {config['suspicious_range']}")
