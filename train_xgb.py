import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("🔄 Loading data...")
df = pd.read_csv('emails.csv')
print(f"📊 {len(df)} total emails | {df['label'].mean():.1%} phishing")

# Features
X = df[['has_url', 'urgent_words', 'url_length']]
y = df['label']

# 70/30 split - FIXED random_state
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

print(f"Train: {len(X_train)} | Test: {len(X_test)}")

# Train
model = xgb.XGBClassifier(n_estimators=100, max_depth=3, random_state=42)
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 RESULTS:")
print(f"Accuracy: {accuracy:.1%}")
print(f"Predictions: {list(y_pred)}")
print(f"Actual:      {list(y_test)}")

# Save
model.save_model('phish-detector.json')
print("✅ SAVED! Run demo_xgb.py next!")
