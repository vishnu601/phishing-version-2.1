label, confidence, risk_data = predict_email(email)

print("\n============================")
print("RESULT:", label)
print("Overall Confidence:", round(confidence * 100, 2), "%")

print("\nRisk Breakdown:")

for category, details in risk_data.items():
    if details["score"] > 0:
        print(f"\n- {category}: {details['score']}%")
        print(f"  Reason: {details['reason']}")

print("============================")
