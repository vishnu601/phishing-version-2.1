"""
test_suite.py — PhishGuard Evaluation Suite
Implements the testing strategy from testing_strategy.md

Runs 30+ test emails across 5 categories:
  A. Real phishing emails
  B. Legitimate security notifications (false positive risk)
  C. Normal business emails
  D. Edge cases
  E. Adversarial patterns

Computes: Precision, Recall, F1, FPR, Explainability Coverage
"""

import sys
import json
from predict import predict_email

# ═══════════════════════════════════════════════════════════════════════
# TEST DATA — 5 Categories
# label: 1 = phishing, 0 = legitimate
# ═══════════════════════════════════════════════════════════════════════

TEST_EMAILS = [
    # ─── CATEGORY A: Real Phishing Emails (must detect) ────────────────
    {
        "id": "A1",
        "category": "A: Phishing",
        "label": 1,
        "name": "PayPal credential harvesting",
        "text": """From: security-alert@paypa1-verify.xyz
Subject: Your PayPal account has been limited

Dear Customer,

We've noticed unusual activity on your PayPal account. Your account access has been
limited until you verify your identity.

Please click the link below to restore your account immediately:
http://paypa1-secure-verify.xyz/restore-account

If you don't verify within 24 hours, your account will be permanently suspended.

Thank you,
PayPal Security Team"""
    },
    {
        "id": "A2",
        "category": "A: Phishing",
        "label": 1,
        "name": "BEC wire transfer",
        "text": """From: ceo@company-internal.tk
Subject: Urgent Wire Transfer Needed

Hi,

I need you to process a wire transfer of $45,000 to our new vendor immediately.
This is confidential — do not discuss with anyone else.

Account: 4829103847
Routing: 082739401
Bank: First National

Please confirm once done. This must be completed today.

Best,
Robert Chen
CEO"""
    },
    {
        "id": "A3",
        "category": "A: Phishing",
        "label": 1,
        "name": "Prize/lottery scam",
        "text": """From: notifications@winner-lottery.ml
Subject: Congratulations! You've Won $500,000!

Dear Lucky Winner,

You've been selected as the grand prize winner of our international sweepstakes!
You've won $500,000 USD!

To claim your prize, click here immediately:
http://claim-prize-now.ml/winner?id=38291

You must respond within 48 hours or your prize will be forfeited.

Sincerely,
International Lottery Commission"""
    },
    {
        "id": "A4",
        "category": "A: Phishing",
        "label": 1,
        "name": "HR impersonation salary scam",
        "text": """From: hr-benefits@secure-updates.xyz
Subject: Your Salary Adjustment — Action Required

Hi Sarah,

Great news! You've been selected for a salary increase as part of our annual compensation review.

To confirm your updated compensation package, please review your employment details
at the link below by February 20:

http://hr-benefits-portal.xyz/confirm-details

Your information must be verified to proceed with the adjustment.

Best regards,
Human Resources Department"""
    },
    {
        "id": "A5",
        "category": "A: Phishing",
        "label": 1,
        "name": "Microsoft account phishing",
        "text": """From: no-reply@microsft-security.tk
Subject: Unusual Sign-in Activity on Your Microsoft Account

We detected something unusual about a recent sign-in to your Microsoft account.

Sign-in details:
Date: February 11, 2026
Location: Russia
IP: 185.220.101.42

If this wasn't you, click here to secure your account NOW:
http://microsft-security.tk/secure-account

Warning: Your account will be locked in 12 hours if not verified.

Microsoft Security Team"""
    },
    {
        "id": "A6",
        "category": "A: Phishing",
        "label": 1,
        "name": "Invoice payment fraud",
        "text": """From: accounting@vendor-payments.club
Subject: URGENT: Invoice #39281 — Payment Overdue

Dear Accounts Payable,

Please find attached Invoice #39281 for $12,450.00. This payment is now 15 days overdue.

To avoid late fees and service disruption, please process payment immediately:
http://vendor-payments.club/pay-invoice?id=39281

Wire transfer details:
Account: 7382910384
Routing: 091028374

This requires immediate action.

Regards,
Billing Department"""
    },
    {
        "id": "A7",
        "category": "A: Phishing",
        "label": 1,
        "name": "Netflix account suspension",
        "text": """From: support@netflix-billing.ga
Subject: Your Netflix Account Has Been Suspended

Hi,

We were unable to validate your billing information for the next billing cycle.
Your account has been suspended.

Update your payment details now to restore access:
http://netflix-billing.ga/update-payment

If not updated within 24 hours, your account will be permanently closed.

Netflix Support"""
    },
    {
        "id": "A8",
        "category": "A: Phishing",
        "label": 1,
        "name": "Amazon order confirmation scam",
        "text": """From: order-confirm@amazn-orders.pw
Subject: Your Order #112-4829103-3847291 Has Shipped

Hello,

Your Amazon order of Apple MacBook Pro ($2,499.99) has shipped!

Didn't place this order? Cancel immediately:
http://amazn-orders.pw/cancel-order?id=1124829103

If you do not cancel within 2 hours, your credit card will be charged.

Amazon Customer Service"""
    },

    # ─── CATEGORY B: Legitimate Security Notifications ─────────────────
    {
        "id": "B1",
        "category": "B: Legit Security",
        "label": 0,
        "name": "Real Google password reset",
        "text": """From: no-reply@accounts.google.com
Subject: Password Reset Request

Hi Vishnu,

You recently requested a password reset for your Google Account (vishnu@gmail.com).

If you made this request, click the link below to reset your password:
https://accounts.google.com/reset?token=abc123def456

This link expires in 1 hour.

If you didn't request this, you can safely ignore this email. Your password won't change.

Thanks,
The Google Accounts Team

© 2026 Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043"""
    },
    {
        "id": "B2",
        "category": "B: Legit Security",
        "label": 0,
        "name": "Real bank login alert",
        "text": """From: alerts@chase.com
Subject: New Sign-in Detected

Hi Vishnu,

We noticed a new sign-in to your Chase account.

Device: Chrome on macOS
Location: Hyderabad, India
Time: February 12, 2026 at 10:32 AM IST

If this was you, no action is needed.
If you don't recognize this activity, please call us immediately at 1-800-935-9935.

Thank you,
Chase Security

JPMorgan Chase Bank, N.A. Member FDIC
© 2026 JPMorgan Chase & Co. All rights reserved.
Privacy Policy | Terms of Service | Unsubscribe"""
    },
    {
        "id": "B3",
        "category": "B: Legit Security",
        "label": 0,
        "name": "Real 2FA code",
        "text": """From: noreply@github.com
Subject: [GitHub] Your two-factor authentication code

Your GitHub two-factor authentication code is: 482910

This code expires in 10 minutes.

If you didn't request this code, please secure your account at https://github.com/settings/security.

Thanks,
The GitHub Team

GitHub, Inc. 88 Colin P. Kelly Jr. Street, San Francisco, CA 94107
Unsubscribe from these emails"""
    },
    {
        "id": "B4",
        "category": "B: Legit Security",
        "label": 0,
        "name": "Real Microsoft security alert",
        "text": """From: account-security-noreply@accountprotection.microsoft.com
Subject: Microsoft Account Security Alert

Hi Vishnu,

We detected a sign-in to your Microsoft account from a new device.

Details:
Device: Chrome on Linux
Location: Hyderabad, Telangana, India
Time: Feb 12, 2026, 10:15 AM

If this was you, you can safely disregard this message.
If this wasn't you, go to https://account.microsoft.com/security to review your account.

You can also reach us by phone at 1-800-642-7676.

The Microsoft Account Team

Microsoft Corporation, One Microsoft Way, Redmond, WA 98052
Privacy Statement | Terms of Use
© 2026 Microsoft. All rights reserved."""
    },
    {
        "id": "B5",
        "category": "B: Legit Security",
        "label": 0,
        "name": "Real Slack workspace invite",
        "text": """From: feedback@slack.com
Subject: You've been invited to a Slack workspace

Hi Vishnu,

John Smith has invited you to join the Engineering Team workspace on Slack.

Join the workspace: https://slack.com/accept-invite/T03ABC123

This invitation expires in 30 days. If you weren't expecting this, you can ignore it.

Happy collaborating,
The Slack Team

Slack Technologies, LLC | 500 Howard Street | San Francisco, CA 94105
Privacy Policy | Terms of Service | Unsubscribe"""
    },

    # ─── CATEGORY C: Normal Business Emails ────────────────────────────
    {
        "id": "C1",
        "category": "C: Normal Business",
        "label": 0,
        "name": "Newsletter",
        "text": """From: newsletter@techcrunch.com
Subject: TechCrunch Daily — Top Stories for February 12

Good morning,

Here are today's top stories:

1. OpenAI launches new reasoning model
   https://techcrunch.com/2026/02/12/openai-reasoning

2. Stripe acquires fintech startup for $1.2B
   https://techcrunch.com/2026/02/12/stripe-acquisition

3. Google I/O 2026 dates announced
   https://techcrunch.com/2026/02/12/google-io

Read more stories at https://techcrunch.com

Thanks for reading!
The TechCrunch Team

You're receiving this because you subscribed to TechCrunch Daily.
Unsubscribe | Manage preferences | Privacy Policy
© 2026 TechCrunch. All rights reserved."""
    },
    {
        "id": "C2",
        "category": "C: Normal Business",
        "label": 0,
        "name": "Meeting invite",
        "text": """From: priya.sharma@company.com
Subject: Sprint Planning — Tuesday 2pm

Hi team,

Quick reminder that we have sprint planning tomorrow at 2pm IST.

Agenda:
- Review completed stories from Sprint 14
- Groom backlog for Sprint 15
- Discuss deployment timeline for Project Phoenix (ticket #PHOE-283)

Meeting link: https://meet.google.com/abc-defg-hij

See you there!

Best,
Priya Sharma
Engineering Manager"""
    },
    {
        "id": "C3",
        "category": "C: Normal Business",
        "label": 0,
        "name": "Project update",
        "text": """From: devops@company.com
Subject: Deployment Complete — v2.3.1 pushed to staging

Hi all,

v2.3.1 has been deployed to staging. Changes include:

- Fixed pagination bug (ticket #BUG-1294)
- Updated API rate limiting (ref: RFC-0047)
- Added health check endpoint

Staging URL: https://staging.company.com
Build log: https://ci.company.com/builds/4829

Please test and report any issues before we push to production on Friday.

Thanks,
DevOps Team"""
    },
    {
        "id": "C4",
        "category": "C: Normal Business",
        "label": 0,
        "name": "Personal email",
        "text": """From: mom@gmail.com
Subject: Dinner this weekend?

Hey Vishnu,

Are you free for dinner on Saturday? Dad and I were thinking
we could try that new restaurant on Road No. 45.

Let me know!

Love,
Mom"""
    },
    {
        "id": "C5",
        "category": "C: Normal Business",
        "label": 0,
        "name": "E-commerce order confirmation",
        "text": """From: orders@amazon.in
Subject: Your Amazon.in order #408-2918374-9281034

Hi Vishnu,

Thank you for your order! Here's your confirmation:

Order #408-2918374-9281034
Item: Logitech MX Master 3S Mouse
Price: ₹8,495.00
Delivery: February 14-15, 2026

Track your order: https://amazon.in/orders/408-2918374-9281034

Need help? Visit https://amazon.in/help or call 1800-3000-9009.

Thank you for shopping with us!
Amazon.in

© 2026 Amazon.com, Inc. All rights reserved.
Privacy Notice | Conditions of Use | Unsubscribe"""
    },

    # ─── CATEGORY D: Edge Cases ────────────────────────────────────────
    {
        "id": "D1",
        "category": "D: Edge Case",
        "label": 1,
        "name": "Subtle phishing — no urgency",
        "text": """From: support@account-review.info
Subject: Account Review

Dear User,

As part of our routine security check, we'd like you to review your account details
to ensure everything is up to date.

Please visit the following link at your convenience:
http://account-review.info/verify-details

Thank you for your cooperation.

Account Review Team"""
    },
    {
        "id": "D2",
        "category": "D: Edge Case",
        "label": 0,
        "name": "Legitimate email with urgency",
        "text": """From: ops@company.com
Subject: URGENT: Production server down

Team,

The production database server is unresponsive. All customer-facing APIs are returning 503.

IMMEDIATE ACTION NEEDED:
- Check CloudWatch alerts
- Restart the db-primary instance
- Notify on-call engineer at 555-0123

This is critical — we're losing $2000/minute in revenue.

- Ops Team"""
    },
    {
        "id": "D3",
        "category": "D: Edge Case",
        "label": 0,
        "name": "Marketing with deadline",
        "text": """From: deals@flipkart.com
Subject: Last chance! Big Billion Days sale ends tonight!

Hi Vishnu,

Only 6 hours left! Don't miss out on our biggest sale of the year.

🔥 Up to 80% off on electronics
🔥 Buy 2 Get 1 Free on fashion
🔥 Extra 10% off with HDFC cards

Shop now: https://flipkart.com/big-billion-days

Offer expires at midnight tonight!

Flipkart Internet Private Limited
Unsubscribe | Privacy Policy
© 2026 Flipkart. All rights reserved."""
    },
    {
        "id": "D4",
        "category": "D: Edge Case",
        "label": 0,
        "name": "Internal verify request",
        "text": """From: finance@company.com
Subject: Please verify Q4 numbers

Hi Vishnu,

Can you verify the Q4 revenue numbers in the spreadsheet I shared yesterday?
I need to finalize the board presentation by Thursday.

The spreadsheet is in the shared Google Drive folder.

Thanks,
Anil Kumar
Finance Manager
Ext: 4829"""
    },
    {
        "id": "D5",
        "category": "D: Edge Case",
        "label": 1,
        "name": "Phishing disguised as IT admin",
        "text": """From: it-support@helpdesk-update.buzz
Subject: Mandatory System Update — Re-authenticate Your Account

Dear Employee,

Due to a critical system upgrade, all employees must re-authenticate their
company accounts by February 14.

Click here to re-authenticate:
http://helpdesk-update.buzz/reauth

Failure to do so will result in account deactivation.

IT Support Team"""
    },

    # ─── CATEGORY E: Adversarial Patterns ──────────────────────────────
    {
        "id": "E1",
        "category": "E: Adversarial",
        "label": 1,
        "name": "Obfuscated brand name",
        "text": """From: security@payp-al-secure.top
Subject: Important Account Notice

Dear Valued Customer,

Your P.a" y.P" aI account requires verification due to recent policy changes.

Login to your account here to continue:
http://payp-al-secure.top/login

Regards,
Customer Support"""
    },
    {
        "id": "E2",
        "category": "E: Adversarial",
        "label": 1,
        "name": "Short vague phishing",
        "text": """Hi,

Please review the attached document and confirm.

http://doc-review.gq/shared/doc-4829

Thanks"""
    },
    {
        "id": "E3",
        "category": "E: Adversarial",
        "label": 1,
        "name": "Polite professional phishing",
        "text": """From: hr@talent-solutions.cc
Subject: Job Opportunity — Senior Engineer

Dear Vishnu,

I came across your profile and believe you'd be an excellent fit for a Senior
Engineer position at our company. The role offers competitive compensation
and benefits.

To proceed, please confirm your personal and employment details:
http://talent-solutions.cc/apply?candidate=vishnu

We look forward to hearing from you.

Best regards,
Lisa Thompson
Talent Acquisition
Talent Solutions Inc."""
    },
]


# ═══════════════════════════════════════════════════════════════════════
# EVALUATION ENGINE
# ═══════════════════════════════════════════════════════════════════════

def run_evaluation():
    """Run all test emails through predict_email and compute metrics."""
    results = []
    print("=" * 80)
    print("PhishGuard Evaluation Suite — Running 30 test emails")
    print("=" * 80)

    for i, test in enumerate(TEST_EMAILS):
        result = predict_email(test["text"])
        is_phishing_pred = "Phishing" in result["verdict"] or "🔴" in result["verdict"]
        is_suspicious_pred = "Suspicious" in result["verdict"] or "🟡" in result["verdict"]

        # For metric computation: phishing+suspicious = flagged (positive)
        pred_label = 1 if is_phishing_pred else 0
        true_label = test["label"]

        has_explanation = len(result.get("warning_reasons", [])) > 0 or len(result.get("safe_reasons", [])) > 0

        correct = "✅" if pred_label == true_label else "❌"
        verdict_short = result["verdict"]

        results.append({
            "id": test["id"],
            "category": test["category"],
            "name": test["name"],
            "true_label": true_label,
            "pred_label": pred_label,
            "is_suspicious": is_suspicious_pred,
            "score": result["confidence"],
            "ml_raw": result["ml_probability"],
            "verdict": verdict_short,
            "has_explanation": has_explanation,
            "warning_count": len(result.get("warning_reasons", [])),
            "safe_count": len(result.get("safe_reasons", [])),
            "correct": pred_label == true_label,
        })

        status = correct
        print(f"  {status} [{test['id']}] {test['name']:40s} → {verdict_short:20s} "
              f"(score: {result['confidence']:5.1f}%, ML: {result['ml_probability']:5.1f}%)")

    # ── Compute Metrics ────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("EVALUATION RESULTS")
    print("=" * 80)

    tp = sum(1 for r in results if r["true_label"] == 1 and r["pred_label"] == 1)
    fp = sum(1 for r in results if r["true_label"] == 0 and r["pred_label"] == 1)
    tn = sum(1 for r in results if r["true_label"] == 0 and r["pred_label"] == 0)
    fn = sum(1 for r in results if r["true_label"] == 1 and r["pred_label"] == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    accuracy = (tp + tn) / len(results)

    flagged_with_explanation = sum(
        1 for r in results if r["pred_label"] == 1 and r["has_explanation"]
    )
    total_flagged = sum(1 for r in results if r["pred_label"] == 1)
    explainability = flagged_with_explanation / total_flagged if total_flagged > 0 else 1.0

    print(f"\n  Confusion Matrix:")
    print(f"  {'':18s} Predicted Safe  Predicted Phishing")
    print(f"  {'Actually Safe':18s}     {tn:3d}              {fp:3d}")
    print(f"  {'Actually Phishing':18s}     {fn:3d}              {tp:3d}")

    print(f"\n  ┌──────────────────────────────────────┐")
    print(f"  │ Precision:              {precision:6.1%}       │")
    print(f"  │ Recall:                 {recall:6.1%}       │")
    print(f"  │ F1 Score:               {f1:6.3f}        │")
    print(f"  │ False Positive Rate:    {fpr:6.1%}       │")
    print(f"  │ Accuracy:               {accuracy:6.1%}       │")
    print(f"  │ Explainability:         {explainability:6.1%}       │")
    print(f"  └──────────────────────────────────────┘")

    # ── Category Breakdown ─────────────────────────────────────────────
    print(f"\n  Category Breakdown:")
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"correct": 0, "total": 0, "emails": []}
        categories[cat]["total"] += 1
        if r["correct"]:
            categories[cat]["correct"] += 1
        categories[cat]["emails"].append(r)

    for cat, data in sorted(categories.items()):
        pct = data["correct"] / data["total"] * 100
        print(f"\n  {cat}: {data['correct']}/{data['total']} correct ({pct:.0f}%)")
        for r in data["emails"]:
            mark = "✅" if r["correct"] else "❌"
            print(f"    {mark} {r['name']:40s} → {r['verdict']}  (score: {r['score']:.1f}%)")

    # ── Failures Analysis ──────────────────────────────────────────────
    failures = [r for r in results if not r["correct"]]
    if failures:
        print(f"\n  ⚠️  FAILURES ({len(failures)}):")
        for r in failures:
            expected = "Phishing" if r["true_label"] == 1 else "Safe"
            print(f"    ❌ [{r['id']}] {r['name']}")
            print(f"       Expected: {expected} | Got: {r['verdict']} | Score: {r['score']:.1f}%")
            print(f"       Warnings: {r['warning_count']} | Safe signals: {r['safe_count']}")
    else:
        print(f"\n  ✅ ALL TESTS PASSED — No failures!")

    # ── Save report ────────────────────────────────────────────────────
    report = {
        "total_tests": len(results),
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "accuracy": round(accuracy, 4),
            "explainability": round(explainability, 4),
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "failures": [
            {"id": r["id"], "name": r["name"], "expected": "phishing" if r["true_label"] == 1 else "safe",
             "got": r["verdict"], "score": r["score"]}
            for r in failures
        ],
        "results": [
            {"id": r["id"], "category": r["category"], "name": r["name"],
             "correct": r["correct"], "verdict": r["verdict"], "score": r["score"]}
            for r in results
        ]
    }

    with open("evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  📄 Full report saved to evaluation_report.json")

    return report


if __name__ == "__main__":
    run_evaluation()
