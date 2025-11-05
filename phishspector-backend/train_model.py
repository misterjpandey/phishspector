import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import random
import pickle


safe_sources = [
    "Google", "Microsoft", "Amazon", "Apple", "GitHub", "Zoom",
    "Slack", "Dropbox", "MongoDB Atlas", "LinkedIn", "Notion",
    "Stripe", "PayPal", "Bank of America", "HDFC Bank", "ICICI Bank",
    "Trello", "Asana", "Jira", "DigitalOcean", "OpenAI", "Lovable"
]

safe_templates = [
    "{} account security notification",
    "{} 2-Step Verification code",
    "Welcome to {}, your account is ready",
    "Invoice from {} for your recent payment",
    "{} order confirmation",
    "Meeting invite from {} team",
    "Your {} account password was changed successfully",
    "Monthly report attached from {}",
    "New device login detected on your {} account",
    "Your subscription renewal at {} was successful",
    "Payment received confirmation from {}",
    "{} account recovery code",
    "Project update from {} team",
    "{} statement for this month",
    "Hello from {}, your support ticket has been updated",
    "New sign-in on Windows for {}",
    "Thank you for using {}, here’s your invoice",
    "Deployment alert from {} platform",
    "Weekly summary from {} workspace",
]

phish_templates = [
    "Your {} account will be suspended, verify now",
    "Update your {} billing info or your account will close",
    "Urgent! Confirm your {} credentials immediately",
    "Click here to restore access to your {} account",
    "You have won a reward from {}, claim it now",
    "Security alert! {} account has been compromised",
    "Verify your {} account to avoid termination",
    "Suspicious login on your {} account, act now",
    "Limited time offer for {}, click here to get bonus",
    "Payment failed for your {}, update details",
    "Urgent password reset required for {}",
    "Your {} account was used for illegal activity",
    "You are selected for a {} gift, confirm details",
    "Renew your {} subscription by clicking the link below",
    "Confirm your {} account ownership immediately",
]

safe_data = [random.choice(safe_templates).format(random.choice(safe_sources)) for _ in range(1000)]
phish_data = [random.choice(phish_templates).format(random.choice(safe_sources)) for _ in range(1000)]

texts = safe_data + phish_data
labels = [0] * len(safe_data) + [1] * len(phish_data)

df = pd.DataFrame({"text": texts, "label": labels})

# ============================================================
# 2. VECTORIZATION
# ============================================================
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=4000,
    ngram_range=(1, 2),
    sublinear_tf=True
)
X = vectorizer.fit_transform(df["text"])
y = df["label"]

# ============================================================
# 3. MODEL TRAINING
# ============================================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    solver="liblinear"
)
model.fit(X_train, y_train)

# ============================================================
# 4. SAVE MODEL
# ============================================================
with open("phishing_model.pkl", "wb") as f:
    pickle.dump({"model": model, "vectorizer": vectorizer}, f)

print("✅ Model trained successfully with 2000 samples (1000 safe, 1000 phishing)")
print("✅ Model saved as phishing_model.pkl")

# ============================================================
# 5. VALIDATION EXAMPLES
# ============================================================
test_emails = [
    "Google security alert: New sign-in detected on your account",
    "Apple ID verification code",
    "Verify your Microsoft account immediately to restore access",
    "Zoom meeting scheduled at 3 PM",
    "Click here to update your bank account password",
    "Payment received confirmation from Stripe",
]

for t in test_emails:
    prob = model.predict_proba(vectorizer.transform([t]))[0][1]
    print(f"{t[:65]:65s} → Phishing probability: {prob*100:.2f}%")
