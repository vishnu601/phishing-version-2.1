import pickle
import json
import re
import numpy as np
from feature_engineering import extract_structural_features, analyze_risk_distribution


# ── Load model artifacts ────────────────────────────────────────────────
with open("model.pkl", "rb") as f:
    _model = pickle.load(f)

with open("vectorizer.pkl", "rb") as f:
    _vectorizer = pickle.load(f)

with open("config.json", "r") as f:
    _config = json.load(f)


# ── Safe-pattern whitelist ──────────────────────────────────────────────
SAFE_DOMAIN_KEYWORDS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'linkedin.com', 'chase.com', 'wellsfargo.com',
    'bankofamerica.com', 'paypal.com', 'stripe.com', 'slack.com',
    'zoom.us', 'dropbox.com', 'notion.so', 'figma.com',
    'accountprotection.microsoft.com', 'accounts.google.com',
    'flipkart.com', 'amazon.in',
]


def _compute_safe_adjustment(features, email_text=""):
    """Compute how much to reduce the phishing probability based on
    safe indicators found in the email. Returns a value between 0 and 1
    where higher means more safe signals detected."""
    adjustments = []

    # Strong safe signals
    if features['has_unsubscribe']:
        adjustments.append(0.20)
    if features['has_company_footer']:
        adjustments.append(0.15)
    if features['newsletter_score'] >= 2:
        adjustments.append(0.20)

    # Moderate safe signals
    if features['has_signature']:
        adjustments.append(0.10)
    if features['has_greeting']:
        adjustments.append(0.05)

    # Long emails with low urgency are less likely phishing
    if features['email_length'] > 500 and features['urgency_count'] == 0:
        adjustments.append(0.10)

    # No suspicious URLs at all
    if features['suspicious_tld_count'] == 0 and features['domain_mismatch_count'] == 0:
        adjustments.append(0.05)

    # Phone verification = safe signal
    if features.get('has_phone_verification'):
        adjustments.append(0.10)

    # ── NEW: Sender domain whitelist ───────────────────────────────────
    # If the From address matches a known-safe domain AND the email has
    # safe indicators (footer, phone, unsubscribe), apply strong reduction.
    # This fixes false positives on real security alerts from Google, Microsoft, etc.
    from_match = re.search(
        r'from:?\s*[\w\s]*<?[\w.+-]+@([\w.-]+)>?', email_text.lower()
    )
    if from_match:
        sender_domain = from_match.group(1)
        is_whitelisted = any(safe_d in sender_domain for safe_d in SAFE_DOMAIN_KEYWORDS)
        safe_signal_count = sum([
            features.get('has_company_footer', 0),
            features.get('has_phone_verification', 0),
            features.get('has_unsubscribe', 0),
            features.get('has_signature', 0),
        ])
        if is_whitelisted and safe_signal_count >= 2:
            adjustments.append(0.30)  # Strong reduction for verified safe sender

    return min(sum(adjustments), 0.65)  # Raised cap to 65% for whitelist


def _compute_risk_boost(features, email_text=""):
    """Compute additional risk boost based on strong phishing indicators.
    Returns a value between 0 and 1."""
    boosts = []

    if features['suspicious_tld_count'] > 0:
        boosts.append(0.15)
    if features['domain_mismatch_count'] > 0:
        boosts.append(0.25)
    if features['caps_ratio'] > 0.4:
        boosts.append(0.10)
    if features['urgency_count'] >= 3:
        boosts.append(0.10)
    if features['financial_count'] >= 2:
        boosts.append(0.10)

    # --- New v2.1 parameters ---
    if features.get('sender_domain_mismatch'):
        boosts.append(0.20)
    if features.get('unsolicited_good_news', 0) > 0:
        boosts.append(0.15)
    if features.get('deadline_pressure', 0) > 0:
        boosts.append(min(features['deadline_pressure'] * 0.02, 0.15))
    if features.get('external_confirm_link'):
        boosts.append(0.20)
    if features.get('generic_personalization'):
        boosts.append(0.10)
    if features.get('sensitive_no_phone'):
        boosts.append(0.10)

    # ── NEW: Short + vague + external link ─────────────────────────────
    # Very short emails (<200 chars) with an external link asking to
    # review/confirm OR with a suspicious TLD are suspicious.
    email_len = features.get('email_length', 0)
    if (email_len < 200 and
            features.get('has_url', 0) and
            features.get('external_confirm_link', 0)):
        boosts.append(0.20)
    elif (email_len < 200 and
          features.get('has_url', 0) and
          features.get('suspicious_tld_count', 0) > 0):
        # Short email + suspicious TLD = strong phishing signal
        boosts.append(0.25)
    elif (email_len < 150 and
          features.get('has_url', 0) and
          features.get('urgency_count', 0) == 0 and
          features.get('has_signature', 0) == 0):
        # Very short, no urgency, no signature, has link = vague phishing
        boosts.append(0.15)

    # ── NEW: Reply-to mismatch ─────────────────────────────────────────
    # From: ceo@company.com but Reply-To: hacker@gmail.com
    import re as _re
    from_match = _re.search(
        r'from:?\s*[\w\s]*<?[\w.+-]+@([\w.-]+)>?', email_text.lower()
    )
    reply_match = _re.search(
        r'reply-?to:?\s*[\w\s]*<?[\w.+-]+@([\w.-]+)>?', email_text.lower()
    )
    if from_match and reply_match:
        from_domain = from_match.group(1)
        reply_domain = reply_match.group(1)
        if from_domain != reply_domain:
            boosts.append(0.15)

    return min(sum(boosts), 0.60)  # Cap at 60% boost


def predict_email(email_text):
    """
    Unified prediction function that combines ML model probability
    with structural feature analysis for a calibrated verdict.

    Returns:
        dict with keys:
            - verdict: "Phishing 🔴", "Suspicious 🟡", or "Safe 🟢"
            - confidence: float 0-100
            - ml_probability: raw model probability
            - adjusted_probability: probability after safe/risk adjustments
            - risk_data: detailed risk breakdown dict
            - safe_adjustment: how much safe indicators reduced the score
            - safe_reasons: list of safe signal explanations
    """
    # Step 1: ML model prediction
    email_vector = _vectorizer.transform([email_text])
    ml_probability = float(_model.predict_proba(email_vector)[0][1])

    # Step 2: Extract structural features
    features = extract_structural_features(email_text)

    # Step 3: Compute adjustments
    safe_adjustment = _compute_safe_adjustment(features, email_text)
    risk_boost = _compute_risk_boost(features, email_text)

    # Step 4: Combine ML probability with structural adjustments
    # Safe signals pull the score down; risk signals push it up
    weight = _config.get('safe_indicator_weight', 0.15)
    adjusted_probability = ml_probability + (risk_boost * 0.5) - (safe_adjustment * weight * 4)
    adjusted_probability = max(0.0, min(1.0, adjusted_probability))  # Clamp to [0, 1]

    # Step 4b: Structural override — when structural indicators are very strong
    # but ML is naive (e.g. very short emails that TF-IDF can't classify).
    # If we see a suspicious TLD + external confirm link and no safe signals,
    # override the score to guarantee detection.
    strong_phishing_indicators = sum([
        features.get('suspicious_tld_count', 0) > 0,
        features.get('external_confirm_link', 0) > 0,
        features.get('sender_domain_mismatch', 0) > 0,
        features.get('domain_mismatch_count', 0) > 0,
        features.get('unsolicited_good_news', 0) > 0,
    ])
    safe_indicator_count = sum([
        features.get('has_unsubscribe', 0),
        features.get('has_company_footer', 0),
        features.get('has_phone_verification', 0),
        features.get('has_signature', 0),
    ])
    if strong_phishing_indicators >= 2 and safe_indicator_count == 0:
        adjusted_probability = max(adjusted_probability, 0.85)
    elif strong_phishing_indicators >= 2 and safe_indicator_count <= 1:
        adjusted_probability = max(adjusted_probability, 0.75)

    # Step 5: Three-tier verdict using calibrated threshold
    threshold = _config.get('threshold', 0.55)
    suspicious_low = _config.get('suspicious_range', [0.35, 0.55])[0]

    if adjusted_probability >= threshold:
        verdict = "Phishing 🔴"
    elif adjusted_probability >= suspicious_low:
        verdict = "Suspicious 🟡"
    else:
        verdict = "Safe 🟢"

    # Step 6: Build safe reasons list
    safe_reasons = []
    if features['has_unsubscribe']:
        safe_reasons.append("✅ Unsubscribe link detected — newsletter pattern")
    if features['has_company_footer']:
        safe_reasons.append("✅ Company footer / copyright notice found")
    if features['has_signature']:
        safe_reasons.append("✅ Professional email signature present")
    if features['has_greeting']:
        safe_reasons.append("✅ Personal greeting detected")
    if features['newsletter_score'] >= 2:
        safe_reasons.append("✅ Multiple newsletter indicators found")
    if features['email_length'] > 500 and features['urgency_count'] == 0:
        safe_reasons.append("✅ Long email with no urgency — low phishing risk")
    if features.get('has_phone_verification'):
        safe_reasons.append("✅ Phone/call verification offered")

    # Step 6b: Build warning reasons for new v2.1 params
    warning_reasons = []
    if features.get('sender_domain_mismatch'):
        warning_reasons.append("⚠️ Sender domain doesn't match the claimed brand")
    if features.get('unsolicited_good_news', 0) > 0:
        warning_reasons.append(f"⚠️ {features['unsolicited_good_news']} unsolicited 'good news' pattern(s) — no prior discussion")
    if features.get('deadline_pressure', 0) > 0:
        warning_reasons.append(f"⚠️ Tight deadline pressure detected (score: {features['deadline_pressure']}/10)")
    if features.get('external_confirm_link'):
        warning_reasons.append("⚠️ External link asks to review/confirm personal or employment info")
    if features.get('generic_personalization'):
        warning_reasons.append("⚠️ Generic personalization — uses first name but vague on specifics")
    if features.get('sensitive_no_phone'):
        warning_reasons.append("⚠️ Sensitive request with no phone verification offered")

    # Step 7: Risk breakdown for UI
    risk_data = analyze_risk_distribution(email_text, ml_confidence=ml_probability)

    return {
        'verdict': verdict,
        'confidence': round(adjusted_probability * 100, 2),
        'ml_probability': round(ml_probability * 100, 2),
        'adjusted_probability': round(adjusted_probability, 4),
        'risk_data': risk_data,
        'safe_adjustment': round(safe_adjustment * 100, 2),
        'safe_reasons': safe_reasons,
        'warning_reasons': warning_reasons,
        'features': features,
    }
