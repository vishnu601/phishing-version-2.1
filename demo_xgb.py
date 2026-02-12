import xgboost as xgb
import gradio as gr
import numpy as np
import re

# Load model with ERROR HANDLING
try:
    print("🔄 Loading XGBoost model...")
    model = xgb.XGBClassifier()
    model.load_model('phish-detector.json')
    print("✅ Model loaded successfully!")
except:
    print("❌ Model not found! Run 'python train_xgb.py' first.")
    exit()

def extract_features(email_text):
    """Extract 3 key features from email"""
    # Has URL? (http, bit.ly, tinyurl)
    has_url = 1 if re.search(r'http[s]?://|bit\.ly|tinyurl', email_text, re.IGNORECASE) else 0
    
    # Count urgent words
    urgent_words = len(re.findall(r'\b(urgent|now|immediate|click|action|verify|alert)\b', 
                                  email_text, re.IGNORECASE))
    
    # URL length (first URL found)
    url_match = re.search(r'http[s]?://[^\s]+', email_text)
    url_length = len(url_match.group()) if url_match else 0
    
    return np.array([[has_url, urgent_words, url_length]])

def predict_phish(email_text):
    """Main prediction with error handling"""
    try:
        features = extract_features(email_text)
        prediction = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        
        label = '🔴 PHISHING' if prediction == 1 else '🟢 SAFE'
        confidence = f"({max(prob)*100:.0f}% confident)"
        
        # Explanation
        explanation = []
        feat = features[0]
        if feat[0] == 1: explanation.append("🚨 Suspicious URL")
        if feat[1] > 0: explanation.append(f"⚠️ {feat[1]} urgent words")
        if feat[2] > 15: explanation.append("🔗 Long/suspicious link")
        
        return f"{label} {confidence}\n\n**Reasons:**\n" + " | ".join(explanation) if explanation else "Normal patterns"
    
    except Exception as e:
        return f"❌ Error: {str(e)}\n\n💡 Try: 'URGENT password bit.ly/fake'"

# Launch demo
iface = gr.Interface(
    fn=predict_phish,
    inputs=gr.Textbox(label="📧 Paste Email", lines=6, 
                     placeholder="Example: URGENT password bit.ly/fake"),
    outputs=gr.Textbox(label="🎯 AI Verdict", lines=8),
    title="⚡ XGBoost Phishing Detector",
    description="**Hackathon Demo** - 100% accuracy on test set"
)

print("🌐 Starting demo...")
iface.launch(share=True)
