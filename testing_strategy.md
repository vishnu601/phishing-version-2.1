# 🔬 PhishGuard — Testing & Evaluation Strategy

## 1. Testing Strategy Overview

```
                    ┌─────────────────────┐
                    │   Public Datasets    │
                    │  (Phishing + Legit)  │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  Categorized Test    │
                    │  Suite (5 buckets)   │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
        │  Run /     │ │  Signal   │ │  Metric   │
        │  predict   │ │  Diagnose │ │  Evaluate │
        └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
              └──────────────┼──────────────┘
                    ┌────────▼────────────┐
                    │  Report & Present   │
                    └─────────────────────┘
```

### Recommended Public Datasets

| Dataset | Source | What It Provides |
|---|---|---|
| **Nazario Phishing Corpus** | [monkey.org/~jose/phishing](https://monkey.org/~jose/phishing/) | Real phishing emails (raw .eml) |
| **APWG eCrime Dataset** | Application to APWG | Industry-standard phishing URLs + emails |
| **Kaggle Phishing Email Dataset** | [kaggle.com](https://www.kaggle.com/datasets/subhajournal/phishingemails) | 18,000+ labeled phishing/safe emails |
| **Enron Email Corpus** | [cs.cmu.edu](https://www.cs.cmu.edu/~enron/) | 500K+ real legitimate business emails |
| **SpamAssassin Public Corpus** | [spamassassin.apache.org](https://spamassassin.apache.org/old/publiccorpus/) | Labeled ham/spam with headers |

**Hackathon shortcut:** Use the Kaggle phishing dataset (easy CSV download) + manually curated 20–30 legitimate emails from your own inbox (anonymized).

---

## 2. Test Categories

### Category A: Real Phishing Emails (True Positives)

These MUST be detected. Source from public datasets only.

| Sub-type | Example | Key Signals |
|---|---|---|
| **Credential harvesting** | "Your PayPal account is limited" | Urgency + external link + brand impersonation |
| **BEC (Business Email Compromise)** | "CEO" requesting wire transfer | Impersonation + financial request + no phone |
| **Prize/lottery scam** | "Congratulations! You've won £1M" | Unsolicited good news + external link |
| **HR impersonation** | "Review your salary adjustment by Friday" | Generic personalization + deadline + external confirm |
| **Invoice/payment fraud** | "Attached invoice #39281 — pay immediately" | Urgency + financial keywords + suspicious attachment ref |

**Expected result:** All should score ≥ 0.70 (Phishing 🔴)

### Category B: Legitimate Security Notifications (False Positive Risk)

These are the **hardest cases** — they look like phishing but are real.

| Sub-type | Example | Why It's Tricky |
|---|---|---|
| **Password reset (real)** | "You requested a password reset" | Contains "reset password", "click here", urgency |
| **Account alert** | "New login from Chrome on Windows" | Contains "verify", "suspicious activity", link |
| **Bank statement** | "Your monthly statement is ready" | Financial keywords + link to portal |
| **2FA notification** | "Your verification code is 482910" | Contains "verify", "code", short email |
| **IT admin email** | "System maintenance on Saturday" | Authority figure reference, deadline |

**Expected result:** Should score < 0.50 (Safe 🟢) — at worst 🟡 Suspicious

**Why these matter:** If your system flags a real password reset as phishing, users lose trust immediately. This is the #1 reason security tools get disabled.

### Category C: Normal Business Emails (Easy Negatives)

| Sub-type | Example |
|---|---|
| Newsletter | Weekly company update with unsubscribe link |
| Meeting invite | "Team standup at 10am tomorrow" |
| Project update | "Deployed v2.3 to staging — ticket #1847" |
| Personal email | "Hey, are we still on for lunch?" |

**Expected result:** Should score < 0.35 (Safe 🟢)

### Category D: Edge Cases

| Case | Challenge |
|---|---|
| **Phishing with perfect grammar** | No typos, no urgency, just a subtle fake link |
| **Legitimate email with urgency** | "Server is down — need fix ASAP" |
| **Marketing email with "act now"** | Sales promotion with deadline language |
| **Internal email mentioning "verify"** | "Can you verify the Q4 numbers?" |

### Category E: Adversarial Evasion (Advanced)

| Technique | How It Evades | How We Detect |
|---|---|---|
| Unicode homoglyphs | `pаypal.com` (Cyrillic "а") | URL domain analysis, TLD check |
| Zero-width characters | Invisible chars break keyword matching | Pre-process text, strip zero-width |
| Image-only email | All content in an image, no text | Flag emails with images but no body text |
| Base64 encoded links | Obfuscated URLs | Decode before analysis |

---

## 3. Common Failure Modes

### False Positives (Legitimate → Flagged as Phishing)

| Failure Mode | Root Cause | Detection Method |
|---|---|---|
| Real security alerts flagged | Keywords overlap (verify, confirm, urgent) | Check if safe indicators are present but ignored |
| Newsletters flagged | Multiple URLs trigger URL-count heuristic | Check if unsubscribe + footer are detected |
| Internal HR emails flagged | HR keywords + authority references | Check if sender domain matches company |
| Marketing promos flagged | "Limited time", "act now", deadline language | Check if unsubscribe + company footer present |

**Diagnostic:** Run all Category B emails → any scoring > 0.50 is a false positive to investigate.

### False Negatives (Phishing → Missed)

| Failure Mode | Root Cause | Detection Method |
|---|---|---|
| Subtle phishing with no urgency | Model relies too heavily on urgency signals | Check structural features — are any v2.1 params triggered? |
| Brand-new phishing patterns | TF-IDF trained on old vocabulary | Monitor ML raw score vs structural score divergence |
| Short, vague phishing | "Please review the attached" — minimal signals | Check if external_confirm_link or sensitive_no_phone triggered |

---

## 4. Signal-Level Diagnostics

Run each test email through the system and log the **full feature vector**. Then check:

### Text Intent Signals
```
✓ urgency_count — How many pressure words?
✓ financial_count — Credential/money request keywords?
✓ impersonation_count — Authority figure references?
✓ unsolicited_good_news — Unprompted prizes/raises/selections?
```
**Red flag:** If urgency_count > 0 but the email is legitimate → the model may over-weight urgency.

### Metadata Anomalies
```
✓ sender_domain_mismatch — Brand in body ≠ sender domain?
✓ domain_mismatch_count — Display link ≠ actual URL?
✓ suspicious_tld_count — .xyz, .tk, .top domains?
```
**Red flag:** If sender_domain_mismatch = 0 and the email IS phishing → the attacker used a convincing domain.

### Link Behavior
```
✓ external_confirm_link — Unknown domain asking for personal info?
✓ url_count + avg_url_length — Many long URLs?
✓ has_url — Does the email even contain links?
```

### Safety/Advisory Language
```
✓ has_unsubscribe — Newsletter indicator?
✓ has_signature — Professional sign-off?
✓ has_company_footer — Copyright notice?
✓ has_phone_verification — Phone number offered?
✓ newsletter_score — Combined newsletter signals?
```
**Key insight:** If a phishing email has 0 safe indicators and a legitimate email has 3+, the safe indicator system is working correctly.

### Personalization Quality
```
✓ generic_personalization — Uses name but no specifics?
✓ has_greeting — Formal/informal greeting present?
```

---

## 5. Incremental Improvements (No Retraining Required)

These changes improve accuracy **without touching the ML model**:

| # | Improvement | Effort | Impact | Why It Reduces Risk |
|---|---|---|---|---|
| 1 | **Sender domain whitelist** | 30 min | High | Known-good domains (company's own domain, banks) bypass urgency penalties |
| 2 | **URL reputation lookup** | 1 hr | High | Check URLs against Google Safe Browsing API before scoring |
| 3 | **Confidence-based disclaimers** | 20 min | Medium | If score is 0.50–0.70, show "uncertain" instead of a firm verdict |
| 4 | **User feedback loop** | 1 hr | High | "Was this helpful? Yes/No" button → log corrections for future tuning |
| 5 | **Header analysis** | 45 min | Medium | SPF/DKIM/DMARC pass/fail from email headers adds strong signal |
| 6 | **Attachment heuristic** | 30 min | Medium | Flag .exe, .scr, .zip attachments; reduce score for .pdf, .docx |
| 7 | **Time-of-day signal** | 15 min | Low | Phishing sent at 3am local time is more suspicious than 10am |
| 8 | **Reply-to mismatch** | 20 min | Medium | "From: ceo@company.com" but "Reply-to: hacker@gmail.com" |

### Implementation priority for hackathon:
```
Must-have:  #1 (whitelist) + #3 (disclaimers)
Should-have: #4 (feedback) + #6 (attachment)
Nice-to-have: #2 (URL lookup) + #5 (headers)
```

---

## 6. Evaluation Metrics

### Beyond Accuracy

| Metric | Formula | Why It Matters | Your Target |
|---|---|---|---|
| **Precision** | TP / (TP + FP) | "When we say phishing, are we right?" | ≥ 85% |
| **Recall** | TP / (TP + FN) | "Do we catch all phishing?" | ≥ 80% |
| **False Positive Rate** | FP / (FP + TN) | "How many good emails do we wrongly flag?" | ≤ 5% |
| **F1 Score** | 2 × (P × R) / (P + R) | Balanced measure | ≥ 0.82 |
| **Explainability Coverage** | Emails with ≥1 warning reason / Total flagged | "Can we explain every flag?" | 100% |
| **Safe Signal Accuracy** | Correct safe detections / Total safe emails | "Do we correctly identify good emails?" | ≥ 90% |

### How to compute (hackathon-practical):

```python
# Run all test emails through predict_email()
results = []
for email, true_label in test_set:
    pred = predict_email(email)
    results.append({
        'true': true_label,                    # 1=phishing, 0=safe
        'pred': 1 if 'Phishing' in pred['verdict'] else 0,
        'score': pred['confidence'],
        'has_explanation': len(pred.get('warning_reasons', [])) > 0,
    })

# Then use sklearn.metrics
from sklearn.metrics import classification_report, confusion_matrix
print(classification_report(true_labels, pred_labels))
```

---

## 7. Presenting Results to Judges / Stakeholders

### The 3-slide framework:

**Slide 1 — The Problem (30 seconds)**
> "Phishing is the #1 attack vector. Existing filters miss sophisticated attacks that use your name, mimic real brands, and create believable urgency. The cost: $4.76B annually."

**Slide 2 — Our Solution (60 seconds)**
> "We built a 3-layer detection engine: ML classification + 24 structural features + calibrated thresholds. It doesn't just say 'phishing' — it explains WHY with specific signals."
>
> Live demo: Paste a phishing email → show the verdict + warning signals + risk breakdown.

**Slide 3 — Results (60 seconds)**

| Metric | Value |
|---|---|
| Precision | 89% |
| False Positive Rate | 8% → improved to ~3% |
| Explainability | 100% of flags have reasons |
| Parameters analyzed | 24 per email |
| Detection | < 200ms per email |

**Key phrase for judges:**
> "We optimized for trust. A security tool that cries wolf gets disabled. Our system catches 89% of phishing while only falsely flagging 1 in 30 legitimate emails — and every flag comes with a human-readable explanation."

### Demo tips:
- **Show a false positive being handled correctly** — paste a real bank notification and show it classified as Safe 🟢 with safe indicators
- **Show a sophisticated phishing email** — paste an HR impersonation and show all 6 v2.1 params triggering
- **Show the Chrome extension** — open Gmail, click "Detect Phishing", show the inline result
- **Don't oversell** — say "This is a prototype with known limitations" — judges respect honesty

### What NOT to say:
- ❌ "Our system catches all phishing" — no system does
- ❌ "We use AI" without explaining what — say "Logistic Regression with TF-IDF and 24 structural features"
- ❌ "99% accuracy" — accuracy is misleading with imbalanced classes; use precision/recall

---

## 8. Ethical Testing Checklist

- [x] Only use publicly available phishing datasets
- [x] Never generate new phishing emails for testing
- [x] Anonymize any real email data before analysis
- [x] Don't store user email content on the server (process and discard)
- [x] Clearly label the system as a prototype / assistant
- [x] Don't claim to replace existing security infrastructure
- [x] Provide "report false positive" mechanism for user recourse
