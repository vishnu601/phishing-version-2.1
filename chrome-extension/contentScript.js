/**
 * contentScript.js — PhishGuard Chrome Extension
 *
 * Injects a "Detect Phishing" button into Gmail and Outlook Web email views.
 * Uses MutationObserver because both are SPA apps (no page reloads).
 *
 * DOM PITFALLS & NOTES:
 * ─────────────────────
 * GMAIL:
 *   - Email view container: div with class "nH" and role="list" or "listitem"
 *   - Subject is in an h2 with class "hP"
 *   - Sender name/email is inside spans with class "gD" (display name)
 *     and the email attribute is data-hovercard-id or email attribute on the span
 *   - Email body lives inside div.a3s.aiL (the message body container)
 *   - Gmail aggressively recycles DOM nodes — always check if button already exists
 *   - Class names are obfuscated and may change; use multiple selectors as fallback
 *
 * OUTLOOK WEB:
 *   - Email view: div[role="main"] or the reading pane
 *   - Subject: span with specific role or inside the ConversationReadingPane
 *   - Sender: button or span with the sender's name, often [autoid] attributes
 *   - Body: div[role="document"] or div.wide-content-host
 *   - Outlook also recycles DOM heavily with React-style virtual DOM
 *
 * STRATEGY:
 *   We look for known stable selectors. If they fail, we use fallback heuristics.
 *   The MutationObserver watches for subtree additions and re-injects when needed.
 */

(function () {
    "use strict";

    const BUTTON_ID = "phishguard-detect-btn";
    const PANEL_ID = "phishguard-result-panel";
    const CHECK_INTERVAL = 1500; // ms between DOM checks

    // ─── Platform Detection ───────────────────────────────────────────────
    function getPlatform() {
        const host = window.location.hostname;
        if (host.includes("mail.google.com")) return "gmail";
        if (host.includes("outlook.live.com") ||
            host.includes("outlook.office.com") ||
            host.includes("outlook.office365.com")) return "outlook";
        return null;
    }

    const PLATFORM = getPlatform();
    if (!PLATFORM) return;

    // ─── Gmail Selectors ──────────────────────────────────────────────────
    const GMAIL = {
        // The header row that contains subject
        subjectRow: () =>
            document.querySelector("h2.hP") ||
            document.querySelector('[data-thread-perm-id] h2') ||
            document.querySelector(".ha h2"),

        subject: () => {
            const el = GMAIL.subjectRow();
            return el ? el.textContent.trim() : "";
        },

        sender: () => {
            // data-hovercard-id contains the email address
            const el =
                document.querySelector("span.gD[email]") ||
                document.querySelector("span.gD[data-hovercard-id]") ||
                document.querySelector('[data-hovercard-id]');
            if (!el) return "";
            const name = el.textContent.trim();
            const email = el.getAttribute("email") || el.getAttribute("data-hovercard-id") || "";
            return email ? `${name} <${email}>` : name;
        },

        body: () => {
            // a3s is the message body class; aiL is sometimes added
            const el =
                document.querySelector("div.a3s.aiL") ||
                document.querySelector("div.a3s") ||
                document.querySelector('[data-message-id] .ii.gt div');
            return el ? el.innerText.trim() : "";
        },

        // Where to inject the button (beside the subject)
        injectionTarget: () =>
            document.querySelector("h2.hP")?.parentElement ||
            document.querySelector(".ha") ||
            document.querySelector('[data-thread-perm-id]'),

        // Has an email view open?
        isEmailOpen: () => !!document.querySelector("h2.hP"),
    };

    // ─── Outlook Selectors ────────────────────────────────────────────────
    const OUTLOOK = {
        subject: () => {
            const el =
                document.querySelector('[role="heading"][aria-level="2"]') ||
                document.querySelector(".allowTextSelection.GEMJb") ||
                document.querySelector('[data-app-section="ConversationContainer"] span[title]');
            return el ? el.textContent.trim() : "";
        },

        sender: () => {
            const el =
                document.querySelector('[data-app-section="ConversationContainer"] .OZZZK') ||
                document.querySelector('.lDdSm') ||
                document.querySelector('[role="main"] button[aria-label*="@"]');
            if (!el) return "";
            const ariaLabel = el.getAttribute("aria-label") || "";
            return ariaLabel || el.textContent.trim();
        },

        body: () => {
            const el =
                document.querySelector('[role="document"]') ||
                document.querySelector('.wide-content-host') ||
                document.querySelector('[aria-label="Message body"]');
            return el ? el.innerText.trim() : "";
        },

        injectionTarget: () =>
            document.querySelector('[role="heading"][aria-level="2"]')?.parentElement ||
            document.querySelector('.allowTextSelection')?.parentElement,

        isEmailOpen: () =>
            !!document.querySelector('[role="heading"][aria-level="2"]') ||
            !!document.querySelector('.allowTextSelection'),
    };

    const SELECTORS = PLATFORM === "gmail" ? GMAIL : OUTLOOK;

    // ─── Button Injection ─────────────────────────────────────────────────
    function injectButton() {
        // Don't inject twice
        if (document.getElementById(BUTTON_ID)) return;
        if (!SELECTORS.isEmailOpen()) return;

        const target = SELECTORS.injectionTarget();
        if (!target) return;

        const btn = document.createElement("button");
        btn.id = BUTTON_ID;
        btn.className = "phishguard-btn";
        btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span>Detect Phishing</span>
    `;
        btn.addEventListener("click", handleAnalysis);
        target.appendChild(btn);
    }

    // ─── Remove Stale UI ──────────────────────────────────────────────────
    function cleanupStaleUI() {
        // If email view closed, remove button and panel
        if (!SELECTORS.isEmailOpen()) {
            document.getElementById(BUTTON_ID)?.remove();
            document.getElementById(PANEL_ID)?.remove();
        }
    }

    // ─── Email Analysis Handler ───────────────────────────────────────────
    function handleAnalysis() {
        const btn = document.getElementById(BUTTON_ID);
        if (!btn) return;

        // Extract email data
        const emailData = {
            body: SELECTORS.body(),
            sender: SELECTORS.sender(),
            subject: SELECTORS.subject(),
        };

        if (!emailData.body && !emailData.subject) {
            showResult({
                success: false,
                error: "Could not extract email content. Try scrolling through the email first.",
            });
            return;
        }

        // Set loading state
        btn.classList.add("phishguard-loading");
        btn.innerHTML = `
      <span class="phishguard-spinner"></span>
      <span>Analyzing...</span>
    `;
        btn.disabled = true;

        // Send to background script → API
        chrome.runtime.sendMessage(
            { action: "analyzeEmail", data: emailData },
            (response) => {
                // Reset button
                btn.classList.remove("phishguard-loading");
                btn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>Re-scan</span>
        `;
                btn.disabled = false;

                showResult(response);
            }
        );
    }

    // ─── Result Panel ─────────────────────────────────────────────────────
    function showResult(response) {
        // Remove any existing panel
        document.getElementById(PANEL_ID)?.remove();

        const panel = document.createElement("div");
        panel.id = PANEL_ID;

        if (!response || !response.success) {
            panel.className = "phishguard-panel phishguard-error";
            panel.innerHTML = `
        <div class="phishguard-panel-header">
          <span>⚠️ Analysis Failed</span>
          <button class="phishguard-close" aria-label="Close">&times;</button>
        </div>
        <div class="phishguard-panel-body">
          <p>${response?.error || "Could not reach the PhishGuard server. Is the API running?"}</p>
          <p class="phishguard-hint">Start the server: <code>python3 api_server.py</code></p>
        </div>
      `;
        } else {
            const d = response.data;
            const score = d.risk_score;
            const cls = d.classification;

            // Determine severity
            let severity = "safe";
            if (cls.includes("🔴") || cls.toLowerCase().includes("phishing")) severity = "danger";
            else if (cls.includes("🟡") || cls.toLowerCase().includes("suspicious")) severity = "warning";

            const explanationHTML = (d.explanation || [])
                .map((e) => `<li>${e}</li>`)
                .join("");

            const safeHTML = (d.safe_signals || [])
                .map((s) => `<li>${s}</li>`)
                .join("");

            const breakdownHTML = Object.entries(d.risk_breakdown || {})
                .map(
                    ([cat, info]) => `
            <div class="phishguard-breakdown-row">
              <div class="phishguard-breakdown-label">${cat}</div>
              <div class="phishguard-breakdown-bar">
                <div class="phishguard-breakdown-fill phishguard-${severity}"
                     style="width: ${Math.min(info.score, 100)}%"></div>
              </div>
              <span class="phishguard-breakdown-pct">${info.score}%</span>
            </div>`
                )
                .join("");

            panel.className = `phishguard-panel phishguard-${severity}`;
            panel.innerHTML = `
        <div class="phishguard-panel-header">
          <span class="phishguard-verdict">${cls}</span>
          <span class="phishguard-score">Risk: ${score.toFixed(1)}%</span>
          <button class="phishguard-close" aria-label="Close">&times;</button>
        </div>
        <div class="phishguard-panel-body">
          ${explanationHTML ? `
            <div class="phishguard-section">
              <strong>⚠️ Warning Signals</strong>
              <ul>${explanationHTML}</ul>
            </div>
          ` : ""}
          ${safeHTML ? `
            <div class="phishguard-section">
              <strong>✅ Safe Signals</strong>
              <ul>${safeHTML}</ul>
            </div>
          ` : ""}
          ${breakdownHTML ? `
            <details class="phishguard-details">
              <summary>📊 Risk Breakdown</summary>
              <div class="phishguard-breakdown">${breakdownHTML}</div>
            </details>
          ` : ""}
          <div class="phishguard-footer">
            <span>ML Raw: ${d.ml_raw?.toFixed(1) ?? "–"}%</span>
            <span>•</span>
            <span>PhishGuard v2.1</span>
          </div>
        </div>
      `;
        }

        // Close button handler
        panel.querySelector(".phishguard-close")?.addEventListener("click", () => {
            panel.remove();
        });

        // Insert panel after the injection target
        const target = SELECTORS.injectionTarget();
        if (target && target.parentElement) {
            target.parentElement.insertBefore(panel, target.nextSibling);
        } else {
            // Fallback: insert at top of email view
            const body = PLATFORM === "gmail"
                ? document.querySelector("div.a3s")?.parentElement
                : document.querySelector('[role="document"]')?.parentElement;
            if (body) body.prepend(panel);
        }
    }

    // ─── MutationObserver ─────────────────────────────────────────────────
    // Gmail and Outlook are SPA apps — the DOM mutates when navigating between
    // inbox and email view. We observe the body for child additions and re-inject
    // the button whenever an email opens.
    const observer = new MutationObserver(() => {
        cleanupStaleUI();
        injectButton();
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
    });

    // Also run a periodic check as a safety net (MutationObserver can miss
    // some changes in heavily optimized SPAs)
    setInterval(() => {
        cleanupStaleUI();
        injectButton();
    }, CHECK_INTERVAL);

    // Initial injection attempt
    injectButton();

    console.log(`[PhishGuard] Content script loaded for ${PLATFORM}`);
})();
