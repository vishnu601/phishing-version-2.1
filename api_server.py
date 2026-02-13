"""
Flask API server — thin wrapper around predict.py
Provides /predict endpoint for the Chrome extension.
Run:  python3 api_server.py
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from predict import predict_email

app = Flask(__name__)
CORS(app)  # Allow Chrome extension to call this


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    email_text = data.get("email_text", "")
    sender = data.get("sender", "")
    subject = data.get("subject", "")

    # Combine all fields into a single analysis string
    # Prefix sender/subject so the model and feature engine can use them
    combined = ""
    if sender:
        combined += f"From: {sender}\n"
    if subject:
        combined += f"Subject: {subject}\n\n"
    combined += email_text

    result = predict_email(combined)

    return jsonify({
        "risk_score": result["confidence"],
        "classification": result["verdict"],
        "explanation": result.get("warning_reasons", []),
        "safe_signals": result.get("safe_reasons", []),
        "ml_raw": result["ml_probability"],
        "adjusted_probability": result.get("adjusted_probability", 0),
        "safe_adjustment": result.get("safe_adjustment", 0),
        "features": result.get("features", {}),
        "risk_breakdown": {
            k: {"score": v["score"], "reason": v["reason"]}
            for k, v in result["risk_data"].items()
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
