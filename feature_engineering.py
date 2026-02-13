import re
from datetime import datetime, timedelta
from urllib.parse import urlparse


def extract_structural_features(text):
    """Extract numerical features from email text that help distinguish
    phishing from safe emails. Returns a dict of feature_name → value."""
    text_lower = text.lower()
    words = text.split()
    word_count = max(len(words), 1)

    # --- URL-based features ---
    urls = re.findall(r'http[s]?://\S+', text)
    url_count = len(urls)

    has_url = 1 if url_count > 0 else 0

    avg_url_length = 0
    suspicious_tld_count = 0
    domain_mismatch_count = 0
    suspicious_tlds = {'.xyz', '.tk', '.top', '.ml', '.ga', '.cf', '.gq',
                       '.buzz', '.club', '.info', '.pw', '.cc'}
    if urls:
        total_len = sum(len(u) for u in urls)
        avg_url_length = total_len / len(urls)
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        suspicious_tld_count += 1
                        break
            except Exception:
                pass

        # Domain mismatch: display text says "paypal.com" but link goes elsewhere
        link_patterns = re.findall(
            r'([\w.-]+\.(?:com|org|net|gov|edu))\s*(?:<|>|\[|\(|:)?\s*http[s]?://(\S+)',
            text, re.IGNORECASE
        )
        for display_domain, actual_url in link_patterns:
            try:
                actual_domain = urlparse('http://' + actual_url).netloc.lower()
                if display_domain.lower() not in actual_domain:
                    domain_mismatch_count += 1
            except Exception:
                pass

    # --- Text structure features ---
    caps_count = sum(1 for c in text if c.isupper())
    total_alpha = max(sum(1 for c in text if c.isalpha()), 1)
    caps_ratio = caps_count / total_alpha

    special_chars = sum(1 for c in text if c in '!@#$%^&*()_+-=[]{}|;:,.<>?')
    special_char_density = special_chars / max(len(text), 1)

    email_length = len(text)

    exclamation_count = text.count('!')

    # --- Urgency signals ---
    urgency_words = [
        r'\burgent\b', r'\bimmediately\b', r'\bact now\b', r'\bexpires?\b',
        r'\bsuspended\b', r'\bverify\b', r'\bconfirm\b', r'\bwarning\b',
        r'\balert\b', r'\baction required\b', r'\blimited time\b',
        r'\bwithin \d+ hours?\b', r'\baccount.{0,10}locked\b',
        r'\bclick here\b', r'\bdo not ignore\b'
    ]
    urgency_count = sum(
        len(re.findall(pattern, text_lower)) for pattern in urgency_words
    )

    # --- Impersonation signals ---
    impersonation_keywords = [
        'ceo', 'finance director', 'hr department', 'security team',
        'it support', 'helpdesk', 'system administrator', 'admin team'
    ]
    impersonation_count = sum(1 for kw in impersonation_keywords if kw in text_lower)

    # --- Financial request signals ---
    financial_keywords = [
        'verify account', 'update details', 'confirm banking',
        'gift cards', 'wire transfer', 'reset password', 'login immediately',
        'credit card', 'social security', 'ssn', 'routing number',
        'account number', 'billing information'
    ]
    financial_count = sum(1 for kw in financial_keywords if kw in text_lower)

    # --- NEW PARAM 1: Sender domain mismatch ---
    # Detects when email mentions a company but sender domain doesn't match
    # e.g., claims to be from "PayPal" but sent from @random-domain.com
    sender_domain_mismatch = 0
    sender_match = re.search(r'from:?\s*[\w\s]*<[\w.+-]+@([\w.-]+)>', text_lower)
    if not sender_match:
        sender_match = re.search(r'from:?\s*[\w.+-]+@([\w.-]+)', text_lower)
    claimed_brands = re.findall(
        r'\b(paypal|microsoft|apple|google|amazon|netflix|chase|wellsfargo|'
        r'bank of america|citibank|linkedin|facebook|instagram|twitter|'
        r'dropbox|zoom|slack|github|spotify|adobe)\b', text_lower
    )
    if sender_match and claimed_brands:
        sender_domain = sender_match.group(1)
        for brand in claimed_brands:
            brand_clean = brand.replace(' ', '')
            if brand_clean not in sender_domain and brand not in sender_domain:
                sender_domain_mismatch = 1
                break

    # --- NEW PARAM 2: Unsolicited good news ---
    # "Congratulations!", "You've won!", "You've been selected!" with no context
    good_news_patterns = [
        r'\bcongratulations\b', r'\byou.ve (been selected|won|been chosen)\b',
        r'\bselected for\b', r'\bawarded\b', r'\beligible for a\b',
        r'\bclaim your (prize|reward|bonus|gift)\b',
        r'\bexciting (news|opportunity|offer)\b',
        r'\bgreat news\b', r'\bgood news\b',
        r'\bpay (raise|increase|adjustment|revision)\b',
        r'\bsalary (raise|increase|adjustment|revision)\b',
        r'\bbonus (payment|payout)\b', r'\bpromotion\b',
        r'\bspecial offer\b', r'\bexclusive deal\b'
    ]
    unsolicited_good_news = sum(
        1 for p in good_news_patterns if re.search(p, text_lower)
    )

    # --- NEW PARAM 3: Deadline pressure with date proximity ---
    # Detects specific dates that create a tight deadline
    deadline_pressure = 0
    date_patterns = re.findall(
        r'\b(?:by|before|until|deadline:?)\s*'
        r'(\w+\s+\d{1,2}(?:,?\s*\d{4})?|'
        r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|'
        r'\d{1,2}\s+\w+\s+\d{4})',
        text_lower
    )
    today = datetime.now()
    for date_str in date_patterns:
        for fmt in ['%B %d, %Y', '%B %d %Y', '%b %d, %Y', '%b %d %Y',
                     '%m/%d/%Y', '%d/%m/%Y', '%m-%d-%Y', '%d-%m-%Y',
                     '%B %d', '%b %d']:
            try:
                parsed_date = datetime.strptime(date_str.strip(), fmt)
                # If no year, assume current year
                if parsed_date.year == 1900:
                    parsed_date = parsed_date.replace(year=today.year)
                days_until = (parsed_date - today).days
                if 0 <= days_until <= 10:  # Deadline within 10 days = pressure
                    deadline_pressure = min(days_until + 1, 10)  # Lower = more pressure
                    deadline_pressure = 10 - deadline_pressure  # Invert: 0 days = score 10
                    break
            except ValueError:
                continue

    # --- NEW PARAM 4: External domain asking to review/confirm personal info ---
    external_confirm_link = 0
    confirm_action_words = [
        r'review', r'confirm', r'verify', r'validate', r'update',
        r'complete your profile', r'employment', r'personal info',
        r'personal details', r'identity', r'your information',
        r'benefits enrollment', r'direct deposit'
    ]
    if urls:
        known_internal_patterns = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'linkedin.com', 'slack.com', 'zoom.us'
        ]
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                is_known = any(kd in domain for kd in known_internal_patterns)
                if not is_known:
                    # Check if surrounding text asks to confirm/review personal info
                    url_context = text_lower[
                        max(0, text_lower.find(url.lower()) - 100):
                        text_lower.find(url.lower()) + len(url) + 100
                    ]
                    for action in confirm_action_words:
                        if re.search(action, url_context):
                            external_confirm_link = 1
                            break
            except Exception:
                pass
            if external_confirm_link:
                break

    # --- NEW PARAM 5: Generic personalization ---
    # Uses first name ("Hi John") but is vague on specifics
    generic_personalization = 0
    has_first_name_greeting = bool(re.search(
        r'\b(hi|hello|dear|hey)\s+[A-Z][a-z]+\b', text  # Case-sensitive check
    ))
    vague_indicators = [
        r'\byour account\b', r'\byour profile\b', r'\byour records\b',
        r'\byour information\b', r'\byour details\b', r'\byour employment\b',
        r'\byour benefits\b', r'\byour team\b', r'\byour department\b',
        r'\bas discussed\b',  # No actual discussion reference
    ]
    specific_indicators = [
        r'\bproject \w+\b', r'\bticket #?\d+\b', r'\binvoice #?\d+\b',
        r'\border #?\d+\b', r'\bcase #?\d+\b', r'\bmeeting on \w+day\b',
        r'\bref:?\s*\w+\b'
    ]
    vague_count = sum(1 for p in vague_indicators if re.search(p, text_lower))
    specific_count = sum(1 for p in specific_indicators if re.search(p, text_lower))
    if has_first_name_greeting and vague_count >= 1 and specific_count == 0:
        generic_personalization = 1

    # --- NEW PARAM 6: No phone/call verification encouraged ---
    # Legitimate sensitive requests usually offer phone verification
    has_phone_verification = 0
    phone_patterns = [
        r'\bcall\s+(?:us|our|the)\b', r'\bphone\b', r'\bcontact.{0,15}number\b',
        r'\b\d{3}[-\.]\d{3}[-\.]\d{4}\b',  # US phone number
        r'\b\+?\d{1,3}[-\s]?\d{3,}\b',   # International
        r'\bcall\s+\d', r'\bdial\b', r'\breach out by phone\b',
        r'\bverify by calling\b', r'\bspeak to\b'
    ]
    has_phone_verification = 1 if any(
        re.search(p, text_lower) for p in phone_patterns
    ) else 0
    # Flag: sensitive request without phone = suspicious
    sensitive_no_phone = 0
    has_sensitive_request = (financial_count > 0 or
                             external_confirm_link or
                             any(w in text_lower for w in [
                                 'password', 'account', 'verify', 'confirm',
                                 'personal', 'identity', 'employment'
                             ]))
    if has_sensitive_request and not has_phone_verification:
        sensitive_no_phone = 1

    # --- NEW PARAM 7: Social engineering / compliance conditioning ---
    # Detects subtle trust-building emails that prime the victim for later attacks:
    #   - Vague policy/procedure references from unknown senders
    #   - Requests future acknowledgment or compliance
    #   - Payment/billing language from external domains
    #   - Authority grooming (operations team, accounts dept, etc.)
    social_engineering_score = 0
    se_reasons = []

    # Compliance conditioning: asks for future acknowledgment/compliance
    compliance_patterns = [
        r'acknowledgment\s+(?:may|will|could)\s+be\s+requested',
        r'may\s+be\s+requested\s+during',
        r'compliance\s+cycle',
        r'action\s+(?:may|will|could)\s+be\s+(?:needed|required)',
        r'continued\s+cooperation',
        r'further\s+(?:action|steps|instructions)\s+(?:may|will)',
        r'will\s+(?:follow\s+up|reach\s+out|contact\s+you)',
    ]
    compliance_hits = sum(1 for p in compliance_patterns if re.search(p, text_lower))
    if compliance_hits > 0:
        social_engineering_score += min(compliance_hits * 15, 30)
        se_reasons.append(f"{compliance_hits} compliance conditioning pattern(s)")

    # Vague authority: references to policy/operations teams without specifics
    authority_patterns = [
        r'operations\s+(?:policy|team|desk|department)',
        r'accounts?\s+(?:desk|team|department)',
        r'policy\s+(?:team|update|review|change)',
        r'internal\s+(?:usage|policy|guideline|procedure)',
        r'quarterly\s+review',
        r'usage\s+guidelines?',
        r'operational\s+practices',
        r'volume\s+normalization',
        r'payment\s+batching',
        r'standard\s+processing',
    ]
    authority_hits = sum(1 for p in authority_patterns if re.search(p, text_lower))
    if authority_hits >= 2:
        social_engineering_score += min(authority_hits * 10, 30)
        se_reasons.append(f"{authority_hits} vague authority/policy reference(s)")

    # Unknown sender domain with corporate-sounding name
    # (Not from a known brand/company domain, but uses official-sounding language)
    is_unknown_sender = False
    if sender_match:
        s_domain = sender_match.group(1)
        known_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'linkedin.com', 'slack.com', 'zoom.us',
            'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
        ]
        is_unknown_sender = not any(kd in s_domain for kd in known_domains)
    if is_unknown_sender and authority_hits >= 1:
        social_engineering_score += 15
        se_reasons.append("unknown sender domain with corporate-sounding language")

    # Payment/billing/financial language from external source (without URLs)
    payment_grooming = [
        r'payment\b', r'\binvoice\b', r'\bbilling\b', r'\bbatching\b',
        r'\bremittance\b', r'\btransfer\b', r'\bconfirmation.{0,20}delayed\b',
        r'\btiming\s+differences?\b',
    ]
    payment_hits = sum(1 for p in payment_grooming if re.search(p, text_lower))
    if payment_hits >= 2 and is_unknown_sender:
        social_engineering_score += min(payment_hits * 10, 25)
        se_reasons.append(f"{payment_hits} payment/billing term(s) from unknown sender")

    # No links + no ask + corporate tone = trust priming (only suspicious from unknown sender)
    if (is_unknown_sender and has_url == 0 and urgency_count == 0
            and financial_count == 0 and (compliance_hits > 0 or authority_hits >= 2)):
        social_engineering_score += 10
        se_reasons.append("no links or asks — possible trust priming for follow-up attack")

    social_engineering_score = min(social_engineering_score, 50)  # Cap at 50

    # --- Safe-pattern indicators (reduce false positives) ---
    greeting_patterns = [
        r'\b(hi|hello|hey|dear|good morning|good afternoon)\s+\w+',
        r'\bdear\s+(mr|mrs|ms|dr|professor)\b'
    ]
    has_greeting = 1 if any(
        re.search(p, text_lower) for p in greeting_patterns
    ) else 0

    has_unsubscribe = 1 if re.search(
        r'unsubscribe|opt.out|email preferences|manage.subscriptions',
        text_lower
    ) else 0

    has_signature = 1 if re.search(
        r'(regards|sincerely|best wishes|thank you|cheers|sent from)',
        text_lower
    ) else 0

    has_company_footer = 1 if re.search(
        r'(©|copyright|all rights reserved|privacy policy|terms of service)',
        text_lower
    ) else 0

    # Newsletter indicator: presence of multiple safe signals
    newsletter_score = has_unsubscribe + has_company_footer + (1 if url_count >= 3 else 0)

    return {
        'url_count': url_count,
        'has_url': has_url,
        'avg_url_length': round(avg_url_length, 2),
        'suspicious_tld_count': suspicious_tld_count,
        'domain_mismatch_count': domain_mismatch_count,
        'caps_ratio': round(caps_ratio, 4),
        'special_char_density': round(special_char_density, 4),
        'email_length': email_length,
        'exclamation_count': exclamation_count,
        'urgency_count': urgency_count,
        'impersonation_count': impersonation_count,
        'financial_count': financial_count,
        'has_greeting': has_greeting,
        'has_unsubscribe': has_unsubscribe,
        'has_signature': has_signature,
        'has_company_footer': has_company_footer,
        'newsletter_score': newsletter_score,
        # --- New v2.1 parameters ---
        'sender_domain_mismatch': sender_domain_mismatch,
        'unsolicited_good_news': unsolicited_good_news,
        'deadline_pressure': deadline_pressure,
        'external_confirm_link': external_confirm_link,
        'generic_personalization': generic_personalization,
        'has_phone_verification': has_phone_verification,
        'sensitive_no_phone': sensitive_no_phone,
        # --- New v2.2: Social engineering ---
        'social_engineering_score': social_engineering_score,
        'social_engineering_reasons': se_reasons,
    }


def analyze_risk_distribution(text, ml_confidence=None):
    """Generate a human-readable risk breakdown using both structural
    analysis and (optionally) the ML model's confidence score."""
    features = extract_structural_features(text)

    risk_data = {
        "Impersonation Signals": {"score": 0, "reason": ""},
        "Financial Credential Request": {"score": 0, "reason": ""},
        "Suspicious Domain Similarity": {"score": 0, "reason": ""},
        "Urgency Pressure Language": {"score": 0, "reason": ""},
        "Sender Domain Mismatch": {"score": 0, "reason": ""},
        "Unsolicited Good News": {"score": 0, "reason": ""},
        "Deadline Pressure": {"score": 0, "reason": ""},
        "External Confirm/Review Link": {"score": 0, "reason": ""},
        "Generic Personalization": {"score": 0, "reason": ""},
        "No Phone Verification": {"score": 0, "reason": ""},
        "Social Engineering": {"score": 0, "reason": ""},
        "ML Text Analysis": {"score": 0, "reason": ""},
        "Safe Indicators": {"score": 0, "reason": ""},
    }

    # --- Impersonation ---
    if features['impersonation_count'] > 0:
        risk_data["Impersonation Signals"]["score"] = min(
            features['impersonation_count'] * 20, 40
        )
        risk_data["Impersonation Signals"]["reason"] = (
            f"Detected {features['impersonation_count']} authority/brand references."
        )

    # --- Financial request ---
    if features['financial_count'] > 0:
        risk_data["Financial Credential Request"]["score"] = min(
            features['financial_count'] * 20, 45
        )
        risk_data["Financial Credential Request"]["reason"] = (
            f"Detected {features['financial_count']} sensitive financial action keywords."
        )

    # --- Suspicious domains ---
    domain_score = 0
    reasons = []
    if features['suspicious_tld_count'] > 0:
        domain_score += features['suspicious_tld_count'] * 15
        reasons.append(f"{features['suspicious_tld_count']} suspicious TLDs")
    if features['domain_mismatch_count'] > 0:
        domain_score += features['domain_mismatch_count'] * 25
        reasons.append(f"{features['domain_mismatch_count']} domain mismatches")
    if features['avg_url_length'] > 60:
        domain_score += 10
        reasons.append("unusually long URLs")
    if domain_score > 0:
        risk_data["Suspicious Domain Similarity"]["score"] = min(domain_score, 50)
        risk_data["Suspicious Domain Similarity"]["reason"] = (
            f"Found: {', '.join(reasons)}."
        )

    # --- Urgency ---
    if features['urgency_count'] > 0:
        urgency_score = min(features['urgency_count'] * 10, 35)
        if features['caps_ratio'] > 0.3:
            urgency_score = min(urgency_score + 15, 50)
        if features['exclamation_count'] > 3:
            urgency_score = min(urgency_score + 10, 50)
        risk_data["Urgency Pressure Language"]["score"] = urgency_score
        risk_data["Urgency Pressure Language"]["reason"] = (
            f"{features['urgency_count']} urgency keywords, "
            f"{features['caps_ratio']:.0%} caps ratio, "
            f"{features['exclamation_count']} exclamation marks."
        )

    # --- New v2.1 risk categories ---
    if features['sender_domain_mismatch']:
        risk_data["Sender Domain Mismatch"]["score"] = 35
        risk_data["Sender Domain Mismatch"]["reason"] = (
            "Email claims to be from a known brand but sender domain doesn't match."
        )

    if features['unsolicited_good_news'] > 0:
        risk_data["Unsolicited Good News"]["score"] = min(
            features['unsolicited_good_news'] * 15, 30
        )
        risk_data["Unsolicited Good News"]["reason"] = (
            f"Detected {features['unsolicited_good_news']} unsolicited 'good news' "
            f"patterns (e.g., prizes, selections, pay raises with no prior context)."
        )

    if features['deadline_pressure'] > 0:
        risk_data["Deadline Pressure"]["score"] = min(
            features['deadline_pressure'] * 5, 30
        )
        risk_data["Deadline Pressure"]["reason"] = (
            f"Email sets a tight deadline (pressure score: {features['deadline_pressure']}/10). "
            f"Short-window deadlines are a common phishing tactic."
        )

    if features['external_confirm_link']:
        risk_data["External Confirm/Review Link"]["score"] = 30
        risk_data["External Confirm/Review Link"]["reason"] = (
            "Links to an external/unknown domain asking to review or confirm "
            "personal, employment, or financial information."
        )

    if features['generic_personalization']:
        risk_data["Generic Personalization"]["score"] = 20
        risk_data["Generic Personalization"]["reason"] = (
            "Email uses first name but is vague on specifics — no project, "
            "ticket, or order numbers referenced."
        )

    if features['sensitive_no_phone']:
        risk_data["No Phone Verification"]["score"] = 15
        risk_data["No Phone Verification"]["reason"] = (
            "Email requests sensitive actions but doesn't offer phone/call "
            "verification — legitimate security requests usually do."
        )

    # --- Safe indicators (negative risk = reduces false positives) ---
    safe_parts = []
    safe_deduction = 0
    if features['has_unsubscribe']:
        safe_parts.append("unsubscribe link")
        safe_deduction += 15
    if features['has_signature']:
        safe_parts.append("email signature")
        safe_deduction += 10
    if features['has_company_footer']:
        safe_parts.append("company footer/copyright")
        safe_deduction += 10
    if features['has_greeting']:
        safe_parts.append("personal greeting")
        safe_deduction += 5
    if features['newsletter_score'] >= 2:
        safe_parts.append("newsletter pattern")
        safe_deduction += 15

    if safe_deduction > 0:
        risk_data["Safe Indicators"]["score"] = min(safe_deduction, 50)
        risk_data["Safe Indicators"]["reason"] = (
            f"Legitimate signals detected: {', '.join(safe_parts)}."
        )

    # --- Social Engineering ---
    se_score = features.get('social_engineering_score', 0)
    se_reasons = features.get('social_engineering_reasons', [])
    if se_score > 0:
        risk_data["Social Engineering"]["score"] = min(se_score, 50)
        risk_data["Social Engineering"]["reason"] = (
            f"Detected: {'; '.join(se_reasons)}."
        )

    # --- ML Text Analysis ---
    # When the ML model detects phishing patterns but no structural
    # indicators fire, show the ML contribution so the user understands
    # where the risk score comes from.
    if ml_confidence is not None and ml_confidence > 0.4:
        structural_risk_total = sum(
            v["score"] for k, v in risk_data.items()
            if k not in ("Safe Indicators", "ML Text Analysis")
        )
        # Show ML contribution proportional to its confidence
        ml_risk_score = int(ml_confidence * 50)  # Scale 0-50
        if structural_risk_total == 0:
            # ML is the only signal — make it prominent
            ml_risk_score = max(ml_risk_score, 30)
            risk_data["ML Text Analysis"]["score"] = ml_risk_score
            risk_data["ML Text Analysis"]["reason"] = (
                f"ML model detected text patterns similar to known phishing emails "
                f"(confidence: {ml_confidence:.0%}). This email's wording, tone, and "
                f"structure match patterns seen in phishing campaigns."
            )
        elif structural_risk_total < 20:
            # Some structural signals but ML is a significant contributor
            risk_data["ML Text Analysis"]["score"] = ml_risk_score
            risk_data["ML Text Analysis"]["reason"] = (
                f"ML model flagged text patterns associated with phishing "
                f"(confidence: {ml_confidence:.0%}), reinforcing structural signals."
            )

    # --- Normalize risk scores to percentages (exclude safe indicators) ---
    risk_categories = {k: v for k, v in risk_data.items() if k != "Safe Indicators"}
    total_risk = sum(item["score"] for item in risk_categories.values())

    if total_risk > 0:
        for key in risk_categories:
            if risk_data[key]["score"] > 0:
                risk_data[key]["score"] = round(
                    (risk_data[key]["score"] / total_risk) * 100, 2
                )

    return risk_data
