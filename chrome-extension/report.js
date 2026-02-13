/**
 * report.js — PhishGuard Detailed Security Report
 *
 * Reads analysis data from chrome.storage.local and populates the report page.
 */

(function () {
    "use strict";

    // ─── Feature Groupings ───────────────────────────────────────────────
    const FEATURE_GROUPS = {
        "URL Analysis": [
            { key: "url_count", label: "URLs Found", type: "number" },
            { key: "has_url", label: "Contains URL", type: "bool" },
            { key: "avg_url_length", label: "Avg URL Length", type: "number" },
            { key: "suspicious_tld_count", label: "Suspicious TLDs", type: "risk-number" },
            { key: "domain_mismatch_count", label: "Domain Mismatches", type: "risk-number" },
        ],
        "Text Structure": [
            { key: "email_length", label: "Email Length (chars)", type: "number" },
            { key: "caps_ratio", label: "CAPS Ratio", type: "percent" },
            { key: "special_char_density", label: "Special Char Density", type: "percent" },
            { key: "exclamation_count", label: "Exclamation Marks", type: "number" },
        ],
        "Urgency & Pressure": [
            { key: "urgency_count", label: "Urgency Keywords", type: "risk-number" },
            { key: "deadline_pressure", label: "Deadline Pressure", type: "score10" },
        ],
        "Impersonation & Spoofing": [
            { key: "impersonation_count", label: "Authority References", type: "risk-number" },
            { key: "financial_count", label: "Financial Keywords", type: "risk-number" },
            { key: "sender_domain_mismatch", label: "Sender Mismatch", type: "bool-alert" },
        ],
        "Social Engineering": [
            { key: "unsolicited_good_news", label: "Unsolicited Good News", type: "risk-number" },
            { key: "external_confirm_link", label: "External Confirm Link", type: "bool-alert" },
            { key: "generic_personalization", label: "Generic Personalization", type: "bool-alert" },
            { key: "sensitive_no_phone", label: "Sensitive w/o Phone", type: "bool-alert" },
        ],
        "Safety Indicators": [
            { key: "has_greeting", label: "Personal Greeting", type: "bool-safe" },
            { key: "has_unsubscribe", label: "Unsubscribe Link", type: "bool-safe" },
            { key: "has_signature", label: "Email Signature", type: "bool-safe" },
            { key: "has_company_footer", label: "Company Footer", type: "bool-safe" },
            { key: "has_phone_verification", label: "Phone Verification", type: "bool-safe" },
            { key: "newsletter_score", label: "Newsletter Score", type: "number" },
        ],
    };

    // ─── Helpers ─────────────────────────────────────────────────────────
    function getSeverity(classification) {
        if (!classification) return "safe";
        const cl = classification.toLowerCase();
        if (cl.includes("phishing") || cl.includes("🔴")) return "danger";
        if (cl.includes("suspicious") || cl.includes("🟡")) return "warning";
        return "safe";
    }

    function getGaugeColor(severity) {
        switch (severity) {
            case "danger": return "var(--accent-danger)";
            case "warning": return "var(--accent-warn)";
            default: return "var(--accent-safe)";
        }
    }

    function getVerdictDesc(severity) {
        switch (severity) {
            case "danger":
                return "This email exhibits strong phishing indicators. Do not click any links or provide personal information.";
            case "warning":
                return "This email shows some suspicious characteristics. Proceed with caution and verify the sender independently.";
            default:
                return "This email appears legitimate based on structural analysis and ML classification. No significant phishing indicators were detected.";
        }
    }

    function getBarClass(score) {
        if (score === 0) return "bar-neutral";
        if (score >= 50) return "bar-danger";
        if (score >= 20) return "bar-warning";
        return "bar-safe";
    }

    function formatFeatureValue(feat, value) {
        if (value === undefined || value === null) return { html: "—", cls: "val-neutral" };

        switch (feat.type) {
            case "bool":
                return value
                    ? { html: '<span class="feature-chip chip-yes">Yes</span>', cls: "" }
                    : { html: '<span class="feature-chip chip-no">No</span>', cls: "" };
            case "bool-safe":
                return value
                    ? { html: '<span class="feature-chip chip-yes">✓ Present</span>', cls: "" }
                    : { html: '<span class="feature-chip chip-no">Absent</span>', cls: "" };
            case "bool-alert":
                return value
                    ? { html: '<span class="feature-chip chip-alert">⚠ Detected</span>', cls: "" }
                    : { html: '<span class="feature-chip chip-no">Clear</span>', cls: "" };
            case "percent":
                const pctVal = (value * 100).toFixed(1) + "%";
                const pctCls = value > 0.3 ? "val-warn" : value > 0.5 ? "val-danger" : "val-neutral";
                return { html: pctVal, cls: pctCls };
            case "risk-number":
                const rCls = value >= 3 ? "val-danger" : value >= 1 ? "val-warn" : "val-ok";
                return { html: String(value), cls: rCls };
            case "score10":
                const sCls = value >= 7 ? "val-danger" : value >= 4 ? "val-warn" : value > 0 ? "val-neutral" : "val-ok";
                return { html: `${value}/10`, cls: sCls };
            default:
                return { html: String(value), cls: "val-neutral" };
        }
    }

    // ─── Render Report ───────────────────────────────────────────────────
    function renderReport(data) {
        const severity = getSeverity(data.classification);
        const score = data.risk_score ?? 0;

        // Header badge
        const badge = document.getElementById("header-badge");
        badge.textContent = data.classification?.replace(/[🔴🟡🟢]/g, "").trim() || "Unknown";
        badge.className = `header-badge badge-${severity}`;

        // Gauge
        const pct = Math.min(Math.max(score, 0), 100);
        const gaugeColor = getGaugeColor(severity);
        const ring = document.getElementById("gauge-ring");
        ring.style.background = `conic-gradient(${gaugeColor} ${pct}%, rgba(255,255,255,0.05) ${pct}%)`;

        const gaugeVal = document.getElementById("gauge-value");
        gaugeVal.textContent = score.toFixed(1) + "%";
        gaugeVal.style.color = gaugeColor;

        // Meta values
        document.getElementById("ml-raw").textContent =
            data.ml_raw != null ? data.ml_raw.toFixed(1) + "%" : "—";
        document.getElementById("safe-adj").textContent =
            data.safe_adjustment != null ? "-" + data.safe_adjustment.toFixed(1) + "%" : "—";
        document.getElementById("adjusted-prob").textContent =
            data.adjusted_probability != null
                ? (data.adjusted_probability * 100).toFixed(1) + "%"
                : score.toFixed(1) + "%";

        // Verdict card
        const vCard = document.getElementById("verdict-card");
        vCard.className = `verdict-card severity-${severity}`;
        const icons = { danger: "🚨", warning: "⚠️", safe: "🛡️" };
        document.getElementById("verdict-icon").textContent = icons[severity];
        document.getElementById("verdict-text").textContent = data.classification || "Unknown";
        document.getElementById("verdict-desc").textContent = getVerdictDesc(severity);

        // Warning signals
        if (data.explanation && data.explanation.length > 0) {
            document.getElementById("warn-list").innerHTML = data.explanation
                .map((e) => `<li>${e}</li>`)
                .join("");
        }

        // Safe signals
        if (data.safe_signals && data.safe_signals.length > 0) {
            document.getElementById("safe-list").innerHTML = data.safe_signals
                .map((s) => `<li>${s}</li>`)
                .join("");
        }

        // Risk breakdown
        const grid = document.getElementById("breakdown-grid");
        const breakdown = data.risk_breakdown || {};
        const entries = Object.entries(breakdown);
        if (entries.length > 0) {
            grid.innerHTML = entries
                .sort((a, b) => b[1].score - a[1].score)
                .map(([name, info]) => {
                    const barCls = name === "Safe Indicators" ? "bar-safe" : getBarClass(info.score);
                    return `
            <div class="breakdown-row">
              <div class="breakdown-name">${name}</div>
              <div class="breakdown-bar-wrap">
                <div class="breakdown-bar-fill ${barCls}" style="width: ${Math.min(info.score, 100)}%"></div>
              </div>
              <div class="breakdown-pct">${info.score.toFixed(0)}%</div>
              ${info.reason ? `<div class="breakdown-reason">${info.reason}</div>` : ""}
            </div>`;
                })
                .join("");
        }

        // Structural features
        const featGrid = document.getElementById("features-grid");
        const features = data.features || {};
        if (Object.keys(features).length > 0) {
            featGrid.innerHTML = Object.entries(FEATURE_GROUPS)
                .map(([groupName, feats]) => {
                    const rows = feats
                        .map((f) => {
                            const val = features[f.key];
                            const formatted = formatFeatureValue(f, val);
                            return `
                <div class="feature-row">
                  <span class="feature-name">${f.label}</span>
                  <span class="feature-value ${formatted.cls}">${formatted.html}</span>
                </div>`;
                        })
                        .join("");
                    return `
            <div class="feature-group">
              <div class="feature-group-title">${groupName}</div>
              ${rows}
            </div>`;
                })
                .join("");
        }

        // Timestamp
        document.getElementById("report-timestamp").textContent =
            "Report generated: " + new Date().toLocaleString();
    }

    // ─── No Data State ──────────────────────────────────────────────────
    function showNoData() {
        document.getElementById("verdict-text").textContent = "No Data Available";
        document.getElementById("verdict-desc").textContent =
            "Open an email in Gmail or Outlook and click \"Detect Phishing\" first.";
    }

    // ─── Init ────────────────────────────────────────────────────────────
    chrome.storage.local.get("phishguard_report_data", (result) => {
        const data = result.phishguard_report_data;
        if (data) {
            renderReport(data);
        } else {
            showNoData();
        }
    });
})();
