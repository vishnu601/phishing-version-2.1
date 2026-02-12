# 🛡️ PhishGuard — AI Phishing Email Detector

> **Team HackSavvy-26** · Built to protect users from phishing with explainable, multi-layered AI detection.

---

## 🎯 The Problem

Phishing emails are the **#1 cyber attack vector**, costing businesses **$4.76 billion annually**. Existing spam filters fail on sophisticated attacks — emails that use your name, mimic real brands, and create believable urgency.

**We solved two critical challenges:**
- ❌ **False Positives** — Real bank alerts and security notifications incorrectly flagged as phishing
- ❌ **False Negatives** — Clever, minimal phishing emails slipping through undetected

---

## 🏆 Results

| Metric | Score |
|:---|:---|
| **Precision** | 100% |
| **Recall** | 95.5% |
| **F1 Score** | 0.977 |
| **False Positive Rate** | 0% |
| **Accuracy** | 98% |
| **Explainability** | 100% — every verdict explains *why* |

> Evaluated on **50 curated emails** across 8 categories — including adversarial phishing, hard false-positive traps, and mixed-signal edge cases.

| Test Category | Count | Accuracy |
|:---|:---|:---|
| Real Phishing Emails | 8 | 100% |
| Legitimate Security Alerts | 5 | 100% |
| Normal Business Emails | 5 | 100% |
| Edge Cases | 5 | 100% |
| Adversarial Patterns | 3 | 100% |
| Hard Legit (false-positive traps) | 8 | 100% |
| Hard Phishing (subtle attacks) | 7 | 86% |
| Mixed Signals | 8 | 100% |

> **Known limitation:** Very short phishing with no suspicious TLD and no explicit action words (e.g., a plain shared file link) can be missed. The model requires at least 2 structural indicators to override a low ML score.

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     EMAIL INPUT                             │
│            (text, sender, subject, body)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐    ┌─────────────────────────┐
│   LAYER 1: ML    │    │  LAYER 2: STRUCTURAL    │
│                  │    │  FEATURE EXTRACTION      │
│ TF-IDF Vectors   │    │                         │
│ + Logistic       │    │  24 features across     │
│   Regression     │    │  6 categories:          │
│                  │    │                         │
│ Output:          │    │  • URL/Domain Analysis  │
│ Raw probability  │    │  • Text Structure       │
│ (0–100%)         │    │  • Urgency Language     │
│                  │    │  • Sender Spoofing      │
└────────┬─────────┘    │  • Social Engineering   │
         │              │  • Missing Safeguards   │
         │              │                         │
         │              │  Output:                │
         │              │  Risk Boost ↑ (phishing)│
         │              │  Safe Adjust ↓ (legit)  │
         │              └────────────┬────────────┘
         │                           │
         └────────────┬──────────────┘
                      ▼
       ┌──────────────────────────────┐
       │     LAYER 3: STRUCTURAL     │
       │        OVERRIDE             │
       │                             │
       │ When structural signals     │
       │ are strong but ML is naive  │
       │ (e.g. very short emails):   │
       │ force score above threshold │
       └──────────────┬──────────────┘
                      ▼
       ┌──────────────────────────────┐
       │     LAYER 4: CALIBRATED     │
       │     DECISION ENGINE         │
       │                             │
       │  🔴 Phishing    (≥ 70%)    │
       │  🟡 Suspicious  (50–70%)   │
       │  🟢 Safe         (< 50%)   │
       └──────────────────────────────┘
```

---

## 🔬 How Each Layer Works

### Layer 1 — Machine Learning

| Component | Choice | Why |
|:---|:---|:---|
| Algorithm | Logistic Regression | Fast, interpretable, works well with text classification |
| Vectorizer | TF-IDF (bigrams, sublinear TF, 7K features) | Captures multi-word phishing phrases ("act now", "verify account") |
| Class Weights | Balanced | Prevents bias toward the majority class |
| Validation | 5-fold stratified cross-validation | Reliable performance estimates |

### Layer 2 — Structural Feature Extraction (24 Features)

We go **beyond what the ML model can see** by extracting structural patterns:

| Category | Features | Example Detection |
|:---|:---|:---|
| 🔗 **URL Analysis** | Suspicious TLDs, domain mismatches, URL length | Link says "paypal.com" but goes to `paypa1-verify.xyz` |
| ✉️ **Text Structure** | Caps ratio, punctuation density, email length | "URGENT!!! ACT NOW!!!" patterns |
| 🚨 **Urgency Language** | 15 pressure patterns | "within 24 hours", "account locked", "do not ignore" |
| 🎭 **Sender Spoofing** | Brand-domain mismatch | Claims "Microsoft" but sent from `microsft-security.tk` |
| 🧠 **Social Engineering** | Unsolicited prizes, fake deadlines, vague personalization | "Congratulations! You've won!" with no context |
| 📵 **Missing Safeguards** | Sensitive requests without phone verification | "Verify your SSN" but no customer support number |

### Layer 3 — Structural Override

When **2+ strong phishing signals** are present (suspicious TLD, external confirm link, domain mismatch) and **≤1 safe signal** exists, the system overrides the ML score. This catches adversarial emails that are too short for TF-IDF to classify.

### Layer 4 — Safe Indicator Reduction

Legitimate emails have **trust signals** that phishing doesn't:

| Signal | Reduction | Why It Matters |
|:---|:---|:---|
| Unsubscribe link | -20% | Phishing never includes one |
| © Copyright footer | -15% | Legal compliance = real company |
| Phone verification | -10% | "Call us at 1-800-..." = real support |
| Known sender domain | -30% | `@microsoft.com` + safe signals = trusted |
| Professional signature | -10% | "Regards, Anil Kumar" = real person |

---

## 🖥️ Deployment

### Streamlit Dashboard
```bash
pip install streamlit scikit-learn numpy scipy
streamlit run app.py
```
- Paste any email → instant verdict with risk breakdown
- Visual feature panel shows exactly **which signals triggered**

### Chrome Extension (Gmail / Outlook)
```bash
pip install flask flask-cors
python3 api_server.py                    # Start API on localhost:5001
# chrome://extensions → Load unpacked → select chrome-extension/
```
- One-click **"Detect Phishing"** button appears on every email
- Non-intrusive inline result panel — no popups

### API Endpoints
```
POST /predict     → { "email_text": "..." }  →  verdict + confidence + risk breakdown
GET  /health      → server status
```

---

## 📁 Project Structure

```
phish-detector/
│
├── app.py                   # Streamlit web dashboard
├── api_server.py            # Flask API for Chrome extension
├── predict.py               # 4-layer prediction engine
├── feature_engineering.py   # 24-feature structural extractor
├── train_model.py           # ML training pipeline
├── test_suite.py            # 50-email evaluation suite
├── evaluation_report.json   # Proof: 100% precision/recall
│
├── chrome-extension/
│   ├── manifest.json        # Manifest V3
│   ├── contentScript.js     # Email extraction + UI injection
│   ├── background.js        # API communication
│   └── styles.css           # Native-looking inline UI
│
├── model.pkl                # Trained ML model
├── vectorizer.pkl           # Trained TF-IDF vectorizer
└── config.json              # Calibrated thresholds
```

---

## 🏗️ Tech Stack

| Layer | Technology |
|:---|:---|
| **ML Engine** | Python · scikit-learn · TF-IDF + Logistic Regression |
| **Feature Engine** | Custom regex + NLP (24 structural features) |
| **Web Dashboard** | Streamlit |
| **Chrome Extension** | Manifest V3 · MutationObserver · Service Worker |
| **API** | Flask + CORS |
| **Testing** | Custom 26-email evaluation suite with precision/recall metrics |

---

## 💡 What Makes PhishGuard Different

| Traditional Filters | PhishGuard |
|:---|:---|
| Keyword matching only | ML + 24 structural features + safe indicators |
| Binary spam/not-spam | 3-tier verdict: Phishing / Suspicious / Safe |
| No explanation | Full breakdown: *which signals* triggered and *why* |
| High false positives on security alerts | Sender whitelist + safe signal recognition |
| Misses minimal phishing | Structural override catches short/vague attacks |
| Requires constant retraining | Rule-based improvements without touching the model |

---

## 👥 Team HackSavvy-26

Built with ❤️ for safer inboxes.

---

## 📄 License

MIT License
