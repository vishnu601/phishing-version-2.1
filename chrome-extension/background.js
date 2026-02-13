/**
 * background.js — Service worker (Manifest V3)
 * Handles communication between content script and backend API.
 */

const API_BASE = "http://localhost:5001";

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzeEmail") {
        fetch(`${API_BASE}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email_text: request.data.body,
                sender: request.data.sender,
                subject: request.data.subject,
            }),
        })
            .then((res) => {
                if (!res.ok) throw new Error(`API returned ${res.status}`);
                return res.json();
            })
            .then((data) => sendResponse({ success: true, data }))
            .catch((err) =>
                sendResponse({ success: false, error: err.message })
            );

        return true; // Keep the message channel open for async response
    }

    if (request.action === "openReport") {
        chrome.storage.local.set(
            { phishguard_report_data: request.data },
            () => {
                chrome.tabs.create({
                    url: chrome.runtime.getURL("report.html"),
                });
                sendResponse({ success: true });
            }
        );
        return true;
    }
});
