import streamlit as st
import json
from predict import predict_email

# ── Page config ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Phishing Detector v2.0",
    page_icon="🛡️",
    layout="centered"
)

# ── Load config ─────────────────────────────────────────────────────────
with open("config.json", "r") as f:
    config = json.load(f)

# ── Sidebar ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    show_details = st.checkbox("Show detailed features", value=False)

    st.markdown("---")
    st.caption("🛡️ Phishing Detector v2.1")
    st.caption("Reduced false positives with calibrated thresholds + safe-pattern detection")

# ── Main UI ─────────────────────────────────────────────────────────────
st.title("🛡️ AI Phishing Email Detector")
st.caption("Paste an email below and let AI analyze it for phishing indicators")

email = st.text_area("📧 Email content:", height=250, placeholder="Paste the email content here...")

if st.button("🔍 Analyze Email", use_container_width=True, type="primary"):
    if email.strip() == "":
        st.warning("⚠️ Please enter email content.")
    else:
        with st.spinner("Analyzing email..."):
            result = predict_email(email)

        # ── Verdict ─────────────────────────────────────────────────
        verdict = result['verdict']

        if "Phishing" in verdict:
            st.error(f"### {verdict}")
        elif "Suspicious" in verdict:
            st.warning(f"### {verdict}")
        else:
            st.success(f"### {verdict}")

        # ── Confidence metrics ──────────────────────────────────────
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Adjusted Score", f"{result['confidence']}%")
        with col2:
            st.metric("ML Raw Score", f"{result['ml_probability']}%")
        with col3:
            safe_adj = result['safe_adjustment']
            st.metric("Safe Reduction", f"-{safe_adj}%",
                      delta=f"-{safe_adj}%" if safe_adj > 0 else "0%",
                      delta_color="inverse")

        # ── Safe indicators ─────────────────────────────────────────
        if result['safe_reasons']:
            st.markdown("---")
            st.subheader("🟢 Safe Indicators Found")
            for reason in result['safe_reasons']:
                st.write(reason)

        # ── Warning indicators (v2.1) ──────────────────────────────────
        if result.get('warning_reasons'):
            st.markdown("---")
            st.subheader("⚠️ Suspicious Indicators")
            for reason in result['warning_reasons']:
                st.write(reason)

        # ── Risk breakdown ──────────────────────────────────────────
        risk_data = result['risk_data']
        risk_categories = {k: v for k, v in risk_data.items()
                          if k != "Safe Indicators" and v["score"] > 0}

        if risk_categories:
            st.markdown("---")
            st.subheader("🔎 Risk Breakdown")

            for category, details in risk_categories.items():
                st.write(f"**{category}** — {details['score']}%")
                st.progress(min(int(details["score"]), 100))
                st.caption(f"📋 {details['reason']}")

        # ── Detailed features (optional) ────────────────────────────
        if show_details:
            st.markdown("---")
            st.subheader("🔬 Detailed Feature Analysis")
            features = result['features']

            feat_col1, feat_col2 = st.columns(2)
            with feat_col1:
                st.write("**Text Signals**")
                st.write(f"- Email length: {features['email_length']}")
                st.write(f"- Caps ratio: {features['caps_ratio']:.1%}")
                st.write(f"- Special char density: {features['special_char_density']:.2%}")
                st.write(f"- Exclamation marks: {features['exclamation_count']}")
                st.write(f"- Urgency words: {features['urgency_count']}")
                st.write(f"- Impersonation refs: {features['impersonation_count']}")
                st.write(f"- Financial keywords: {features['financial_count']}")

            with feat_col2:
                st.write("**URL & Safety Signals**")
                st.write(f"- URL count: {features['url_count']}")
                st.write(f"- Avg URL length: {features['avg_url_length']}")
                st.write(f"- Suspicious TLDs: {features['suspicious_tld_count']}")
                st.write(f"- Domain mismatches: {features['domain_mismatch_count']}")
                st.write(f"- Has greeting: {'✅' if features['has_greeting'] else '❌'}")
                st.write(f"- Has unsubscribe: {'✅' if features['has_unsubscribe'] else '❌'}")
                st.write(f"- Has signature: {'✅' if features['has_signature'] else '❌'}")
                st.write(f"- Newsletter score: {features['newsletter_score']}/3")
                st.write(f"- Phone verification: {'✅' if features.get('has_phone_verification') else '❌'}")

            st.markdown("---")
            st.write("**🆕 Advanced Detection (v2.1)**")
            adv_col1, adv_col2 = st.columns(2)
            with adv_col1:
                st.write(f"- Sender domain mismatch: {'🔴' if features.get('sender_domain_mismatch') else '🟢'}")
                st.write(f"- Unsolicited good news: {features.get('unsolicited_good_news', 0)} pattern(s)")
                st.write(f"- Deadline pressure: {features.get('deadline_pressure', 0)}/10")
            with adv_col2:
                st.write(f"- External confirm link: {'🔴' if features.get('external_confirm_link') else '🟢'}")
                st.write(f"- Generic personalization: {'🔴' if features.get('generic_personalization') else '🟢'}")
                st.write(f"- Sensitive w/o phone: {'🔴' if features.get('sensitive_no_phone') else '🟢'}")
