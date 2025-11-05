import joblib

m = joblib.load("phishing_model.pkl")
vec = m["vectorizer"]
clf = m["model"]

sample = ["urgent verify your password now"]

X = vec.transform(sample)
y = clf.predict(X)
proba = clf.predict_proba(X)[0][1] * 100

print("✅ Model:", type(clf))
print("Predicted label:", y[0])
print("Risk score:", proba)
