# 🛡️ AI Phishing Email Detector v2.1

An intelligent phishing email detection system that combines **Machine Learning** with **rule-based structural analysis** to identify phishing attempts while minimizing false positives. Built with Streamlit, scikit-learn, and a custom multi-layered risk analysis engine.

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install streamlit scikit-learn numpy scipy

# Run the app
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501), paste an email, and get an instant verdict.

---

## 🧠 How It Works

The system uses a **3-layer detection pipeline** that combines statistical ML with structural analysis to produce a calibrated verdict:

```
Email Text
    │
    ├──► Layer 1: ML Model (TF-IDF + Logistic Regression) → Raw Probability
    │
    ├──► Layer 2: Structural Feature Extraction (24 features) → Risk Boost / Safe Adjustment
    │
    └──► Layer 3: Calibrated Decision Engine → Final Verdict
              │
              ├── 🔴 Phishing  (adjusted score ≥ 0.70)
              ├── 🟡 Suspicious (adjusted score 0.50 – 0.70)
              └── 🟢 Safe       (adjusted score < 0.50)
```

### Layer 1: Machine Learning Model

| Component | Details |
|---|---|
| **Algorithm** | Logistic Regression with balanced class weights |
| **Vectorizer** | TF-IDF with unigrams + bigrams, sublinear TF, 7000 max features |
| **Regularization** | C=0.5 (stronger regularization to reduce overfitting) |
| **Validation** | 5-fold stratified cross-validation |
| **Threshold** | Calibrated via precision-recall curve (default: 0.70) |

### Layer 2: Structural Feature Extraction

The system extracts **24 features** from each email, grouped into categories:

---

## 📊 Parameters & Risk Analysis Algorithm

### Phishing Indicators (increase risk score)

#### 1. 🔗 URL & Domain Analysis

| Parameter | What It Detects | How It Works |
|---|---|---|
| `url_count` | Number of links in the email | Phishing often has 1 suspicious link; newsletters have many legitimate ones |
| `avg_url_length` | Average URL character length | Phishing URLs tend to be unusually long to hide the real destination |
| `suspicious_tld_count` | Dangerous top-level domains | Flags `.xyz`, `.tk`, `.top`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.club`, `.pw`, `.cc` |
| `domain_mismatch_count` | Display text ≠ actual link | Detects when visible text says "paypal.com" but the link goes to a different domain |

#### 2. ✉️ Text Structure Signals

| Parameter | What It Detects | How It Works |
|---|---|---|
| `caps_ratio` | Excessive capitalization | Calculates `UPPERCASE / total_alphabetic` — phishing often uses "URGENT!!!" patterns |
| `special_char_density` | Unusual punctuation density | High density of `!@#$%^&*` characters correlates with phishing |
| `exclamation_count` | Exclamation mark overuse | Multiple `!!!` is a strong phishing signal |
| `email_length` | Total character count | Very short, urgent emails are more likely phishing |

#### 3. 🚨 Urgency & Pressure Language

| Parameter | What It Detects | Keyword Patterns |
|---|---|---|
| `urgency_count` | High-pressure language | `urgent`, `immediately`, `act now`, `expires`, `suspended`, `verify`, `confirm`, `warning`, `alert`, `action required`, `limited time`, `within N hours`, `account locked`, `click here`, `do not ignore` |

#### 4. 🎭 Impersonation Signals

| Parameter | What It Detects | Keyword Patterns |
|---|---|---|
| `impersonation_count` | Authority figure references | `ceo`, `finance director`, `hr department`, `security team`, `it support`, `helpdesk`, `system administrator`, `admin team` |

#### 5. 💳 Financial/Credential Requests

| Parameter | What It Detects | Keyword Patterns |
|---|---|---|
| `financial_count` | Sensitive data requests | `verify account`, `update details`, `confirm banking`, `gift cards`, `wire transfer`, `reset password`, `login immediately`, `credit card`, `social security`, `ssn`, `routing number`, `account number`, `billing information` |

---

### 🆕 Advanced Detection Parameters (v2.1)

These 6 parameters detect sophisticated phishing that basic keyword matching misses:

#### 6. 📧 Sender Domain Mismatch

```
Detection: Email claims to be from a known brand (PayPal, Microsoft, Apple, etc.)
           but the sender's domain doesn't match.

Example:   From: security@paypa1-alerts.com  ← claims PayPal, domain is fake
           "Your PayPal account has been limited..."

Algorithm: Extract sender domain from "From:" header → compare against
           brand names mentioned in body → flag if no match found.
```

#### 7. 🎁 Unsolicited Good News

```
Detection: "Congratulations!", "You've been selected!", surprise pay raises,
           prizes, or bonuses with no prior discussion.

Patterns:  congratulations, you've been selected/won/chosen, awarded,
           eligible for a, claim your prize/reward/bonus, exciting news,
           great news, pay raise/increase, salary adjustment, bonus payment,
           promotion, special offer, exclusive deal

Algorithm: Count matching patterns → score = count × 15 (capped at 30).
```

#### 8. ⏰ Deadline Pressure with Date Analysis

```
Detection: Tight deadlines that create panic (e.g., "by February 20" when
           today is February 12 = only 8 days).

Algorithm: Extract dates after "by/before/until/deadline" → parse with
           multiple date formats → calculate days until deadline →
           if ≤ 10 days: pressure_score = 10 - days_remaining.

           Example: 2 days left → score 8/10 (high pressure)
                    8 days left → score 2/10 (moderate pressure)
```

#### 9. 🔗 External Confirm/Review Links

```
Detection: Links to unknown external domains that ask you to "review",
           "confirm", or "verify" personal, employment, or financial info.

Algorithm: For each URL → check if domain is in known-safe list →
           if NOT known → scan 200 chars around the URL for action words
           (review, confirm, verify, validate, update, employment,
           personal info, identity, benefits enrollment, direct deposit)
           → flag if action word found near unknown URL.
```

#### 10. 🎭 Generic Personalization

```
Detection: Email uses your first name ("Hi Sarah") but is vague about
           specifics — no project names, ticket numbers, or order IDs.

Algorithm: Check for "Hi/Hello/Dear [Name]" pattern (case-sensitive) →
           count vague indicators (your account, your profile, your records,
           your employment, as discussed) → count specific indicators
           (project X, ticket #123, invoice #456, order #789) →
           flag if: has_greeting AND vague ≥ 1 AND specific == 0.
```

#### 11. 📵 No Phone Verification

```
Detection: Email requests sensitive actions (password, account, verify,
           confirm, personal, identity, employment) but doesn't offer
           phone/call verification — legitimate security requests usually do.

Algorithm: Check for phone patterns (call us, phone, contact number,
           XXX-XXX-XXXX, dial, verify by calling, speak to) →
           if sensitive_request AND no_phone_patterns → flag.
```

---

### ✅ Safe Indicators (reduce false positives)

These patterns indicate a legitimate email and **reduce** the risk score:

| Parameter | What It Detects | Risk Reduction |
|---|---|---|
| `has_unsubscribe` | "Unsubscribe", "opt out", "email preferences" | -20% |
| `has_company_footer` | ©, copyright, all rights reserved, privacy policy | -15% |
| `newsletter_score` | Multiple newsletter signals combined (≥2 of: unsubscribe + footer + 3+ URLs) | -20% |
| `has_signature` | "Regards", "Sincerely", "Best wishes", "Sent from" | -10% |
| `has_greeting` | "Hi [name]", "Dear Mr/Mrs" | -5% |
| `has_phone_verification` | Phone number or "call us" offered | -10% |
| Long + no urgency | Email > 500 chars with 0 urgency words | -10% |

---

## 🔧 Score Calculation Algorithm

```
Step 1: ML Probability
        raw_score = model.predict_proba(tfidf_vector)[phishing_class]

Step 2: Risk Boost (from structural features)
        boost = Σ(triggered phishing indicators × weight)
        Capped at 60%

Step 3: Safe Adjustment
        safe_reduction = Σ(triggered safe indicators × weight)
        Capped at 50%

Step 4: Final Score
        adjusted = raw_score + (boost × 0.5) - (safe_reduction × 0.15 × 3)
        Clamped to [0.0, 1.0]

Step 5: Three-Tier Verdict
        if adjusted ≥ 0.70  → 🔴 Phishing
        if adjusted ≥ 0.50  → 🟡 Suspicious
        else                → 🟢 Safe
```

---

## 📁 Project Structure

```
phish-detector/
├── app.py                  # Streamlit web UI
├── predict.py              # Unified prediction engine (3-layer pipeline)
├── feature_engineering.py  # 24-feature structural extractor
├── train_model.py          # Training pipeline (TF-IDF + LogReg + CV)
├── calibrate_threshold.py  # Precision-recall threshold optimizer
├── config.json             # Calibrated threshold & settings
├── model.pkl               # Trained ML model
├── vectorizer.pkl          # Trained TF-IDF vectorizer
├── train_xgb.py            # XGBoost training (alternative model)
├── demo_xgb.py             # Gradio demo for XGBoost model
└── README.md               # This file
```

---

## 🏗️ Tech Stack

| Component | Technology |
|---|---|
| Frontend | Streamlit |
| ML Model | scikit-learn (Logistic Regression) |
| Vectorizer | TF-IDF (bigrams, sublinear TF) |
| Feature Engine | Custom Python (regex + NLP) |
| Alt. Model | XGBoost (via `train_xgb.py`) |
| Threshold Calibration | Precision-Recall Curve Analysis |

---

## 📈 Retraining the Model

```bash
# Retrain with your dataset (requires dataset.csv with 'text_combined' and 'label' columns)
python3 train_model.py

# Recalibrate the threshold
python3 calibrate_threshold.py
```

---

## 👥 Team

**HackSavvy-26** — Built for hackathon submission.

---

## 📄 License

MIT License
