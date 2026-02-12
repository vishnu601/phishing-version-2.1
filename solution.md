# 💡 Solution: AI Phishing Email Detector

## The Problem

Phishing emails are the #1 attack vector for cybercrime, costing businesses **$4.76 billion annually**. Existing spam filters catch obvious phishing but fail on sophisticated attacks — emails that use your name, mimic real brands, and create believable urgency. The result: **false positives** (legitimate emails flagged) and **false negatives** (real phishing slipping through).

## Our Solution

We built a **3-layer AI detection engine** that goes beyond keyword matching to understand the *structure* and *intent* of phishing emails:

### Layer 1 — Machine Learning Classification
- Trained a **Logistic Regression** model on TF-IDF vectors (bigrams + sublinear TF)
- Balanced class weights prevent the model from being biased toward either class
- **Output**: A raw phishing probability (0–100%)

### Layer 2 — Structural Feature Analysis
We extract **24 features** from every email across 6 categories:

| Category | What We Detect |
|---|---|
| **URL Analysis** | Suspicious TLDs (`.xyz`, `.tk`), domain mismatches, abnormal URL lengths |
| **Text Structure** | Caps ratio, punctuation density, email length |
| **Urgency Language** | 15 pressure patterns ("act now", "within 24 hours", "account locked") |
| **Sender Spoofing** | Brand name in body doesn't match sender domain |
| **Social Engineering** | Unsolicited good news, generic personalization, tight deadlines with date math |
| **Missing Safeguards** | Sensitive requests without phone verification |

### Layer 3 — Calibrated Decision Engine
- **Risk boost**: Phishing indicators push the score up (capped at +60%)
- **Safe adjustment**: Legitimate signals (unsubscribe links, signatures, copyright footers) pull the score down (capped at -50%)
- **3-tier verdict**: Phishing 🔴 / Suspicious 🟡 / Safe 🟢 instead of a binary yes/no

## How We Built It

1. **Started with a baseline** — Simple TF-IDF + Logistic Regression on a phishing email dataset
2. **Identified false positives** — Legitimate emails (newsletters, bank statements, meeting invites) were being flagged
3. **Engineered structural features** — Built regex-based extractors for URL patterns, urgency language, safe indicators
4. **Calibrated the threshold** — Swept 0.3→0.8 to find the optimal cutoff (0.70) that maximizes precision while keeping recall ≥ 85%
5. **Added advanced parameters** — 6 new detectors for sophisticated phishing: sender domain mismatch, unsolicited good news, deadline pressure (with actual date parsing), external confirm links, generic personalization, and missing phone verification
6. **Built the UI** — Streamlit app with real-time analysis, risk breakdown, and detailed feature panel

## Tech Stack

- **Python** + **Streamlit** for the web interface
- **scikit-learn** for ML (Logistic Regression, TF-IDF)
- **Custom NLP engine** (regex + structural analysis) for feature extraction
- **Precision-recall calibration** for optimal threshold tuning

## Key Results

| Metric | Before | After |
|---|---|---|
| False Positives | 4/12 safe emails flagged | 1/12 safe emails flagged |
| Threshold | 0.50 (default) | 0.70 (calibrated) |
| Detection | Binary (Phishing/Safe) | 3-tier (Phishing/Suspicious/Safe) |
| Features | Text-only (TF-IDF) | 24 structural + TF-IDF |
| Precision | 66.67% | 88.89% |

## What Makes It Different

- **Not just keywords** — We analyze email *structure* (caps ratio, URL patterns, date proximity)
- **False positive reduction** — Safe indicators (unsubscribe, signatures, newsletters) actively reduce the score
- **Explainable AI** — Every verdict comes with a detailed risk breakdown showing *why* we flagged it
- **Date-aware** — The system knows today's date and calculates whether a deadline is suspiciously tight
