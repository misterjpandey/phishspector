# app.py — PhishSpector backend (ready-to-run, trial-safe SMS, SID logging + SANDBOX)
import os
import re
import time
import json
import pickle
import logging
import hashlib
import base64
from datetime import datetime
from threading import Event, Thread
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS

# Optional external libs (ensure installed in venv)
# gmail monitor is optional; if import fails we keep running without it
try:
    from gmail_monitor import monitor_loop
except Exception:
    monitor_loop = None

# WHOIS is optional; import if available
try:
    import whois
except Exception:
    whois = None

# Twilio (optional: continue without if not installed)
try:
    from twilio.rest import Client
    from twilio.base.exceptions import TwilioRestException
except Exception:
    Client = None
    TwilioRestException = Exception

# Sandbox analyzer (optional)
try:
    from sandbox_analyzer import sandbox
    SANDBOX_AVAILABLE = True
except Exception:
    sandbox = None
    SANDBOX_AVAILABLE = False

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)

# ========== Config ==========
# Twilio / alerting
SID = os.getenv("TWILIO_ACCOUNT_SID")
TOK = os.getenv("TWILIO_AUTH_TOKEN")
FROM_SMS = os.getenv("ALERT_FROM_SMS")          # e.g. +12175133016
FROM_WA = os.getenv("ALERT_FROM_WHATSAPP")      # e.g. whatsapp:+14155238886
TO1 = os.getenv("ALERT_TO_PRIMARY")             # e.g. +91XXXXXXXXXX
TO2 = os.getenv("ALERT_TO_BACKUP")

THRESH = float(os.getenv("ALERT_THRESHOLD", "70"))
USE_SMS = os.getenv("ALERT_ENABLE_SMS", "true").lower() == "true"
USE_WA = os.getenv("ALERT_ENABLE_WHATSAPP", "false").lower() == "true"
COOLDOWN_MIN = int(os.getenv("ALERT_COOLDOWN_MINUTES", "15"))

# Model path
MODEL_PATH = os.getenv("MODEL_PATH", "phishing_model.pkl")

# Sandbox settings
SANDBOX_ENABLED = os.getenv("SANDBOX_ENABLED", "true").lower() == "true" and SANDBOX_AVAILABLE

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ========== Twilio client init ==========
twilio_client = None
TWILIO_ENABLED = False
if SID and TOK and Client is not None:
    try:
        twilio_client = Client(SID, TOK)
        TWILIO_ENABLED = True
        print("✅ Twilio client initialized")
    except Exception as e:
        logging.error("Twilio init failed: %s", e)
else:
    if SID or TOK:
        logging.warning("Twilio lib not available or SID/TOK missing; Twilio disabled.")

# ========== Alerting + dedupe ==========
_last_sent = {}  # key: sha256(message_id) -> epoch

def _hash_msg(message_id: str) -> str:
    return hashlib.sha256((message_id or "").encode("utf-8")).hexdigest()

def _should_alert(score: float) -> bool:
    try:
        return float(score) >= float(THRESH)
    except Exception:
        return False

def _ascii(s: str) -> str:
    """Keep only ASCII to avoid Unicode segmentation/splitting issues."""
    return s.encode("ascii", "ignore").decode()

def _shorten(s: str, n: int) -> str:
    """Trim string to max n chars with ellipsis."""
    return s if len(s) <= n else (s[: max(0, n - 3)] + "...")

def send_alert_if_needed(message_id: str, score: float, subject: str, sender: str, top_link: str = ""):
    """
    Send SMS/WhatsApp if score >= threshold, with cooldown/dedupe.
    Uses trial-safe short ASCII body. Returns (sent, status).
    """
    if not TWILIO_ENABLED:
        return False, "twilio_disabled"
    if not _should_alert(score):
        return False, "below_threshold"

    h = _hash_msg(message_id or f"{sender}|{subject}")
    now = time.time()
    last = _last_sent.get(h, 0)
    if now - last < COOLDOWN_MIN * 60:
        return False, "cooldown"

    # ---- Trial-safe (single segment) message body ----
    summary  = f"Risk {int(round(score))}/100"
    sender_s = _shorten(sender or "", 40)
    subj_s   = _shorten(subject or "", 60)
    link_s   = _shorten(top_link or "", 30)

    body = f"[PhishSpector] {summary} | From: {sender_s} | Subj: {subj_s}"
    if link_s:
        body += f" | Link: {link_s}"
    body = _ascii(body)
    body = _shorten(body, 140)  # hard cap for trial accounts
    logging.info("📨 Twilio alert len=%d: %s", len(body), body)

    try:
        any_sent = False
        if USE_SMS and FROM_SMS and TO1:
            msg = twilio_client.messages.create(from_=FROM_SMS, to=TO1, body=body)
            logging.info("✅ Twilio SMS queued: sid=%s to=%s from=%s", getattr(msg, "sid", "?"), TO1, FROM_SMS)
            if TO2:
                msg2 = twilio_client.messages.create(from_=FROM_SMS, to=TO2, body=body)
                logging.info("✅ Twilio SMS queued: sid=%s to=%s from=%s", getattr(msg2, "sid", "?"), TO2, FROM_SMS)
            any_sent = True

        if USE_WA and FROM_WA and TO1:
            msgw = twilio_client.messages.create(from_=FROM_WA, to=f"whatsapp:{TO1}", body=body)
            logging.info("✅ Twilio WhatsApp queued: sid=%s", getattr(msgw, "sid", "?"))
            any_sent = True

        if any_sent:
            _last_sent[h] = now
            return True, "sent"
        else:
            return False, "no_channel_configured"
    except TwilioRestException as e:
        logging.error("Twilio send failed: %s", e)
        return False, "twilio_error"
    except Exception as e:
        logging.error("Alert error: %s", e)
        return False, "error"

# ========== Load ML model (robust) ==========
model = None
vectorizer = None
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        if isinstance(data, dict):
            # common keys used by training script
            model = data.get("model") or data.get("clf") or data.get("estimator") or data.get("pipeline")
            vectorizer = data.get("vectorizer") or data.get("vec")
        else:
            model = data
            vectorizer = None
        print(f"✅ Loaded ML model: {MODEL_PATH}")
    except Exception as e:
        model = None
        vectorizer = None
        logging.error("Model load error: %s", e)
else:
    logging.warning("Model not found — falling back to heuristics")

# ========== Prediction helper ==========
def safe_predict(text: str) -> float:
    """Return risk score 0-100. Use model if available, else heuristics."""
    try:
        if model is not None and vectorizer is not None:
            X = vectorizer.transform([text])
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba(X)[0][1]
                return float(round(prob * 100, 2))
            pred = model.predict(X)[0]
            return 100.0 if int(pred) == 1 else 0.0
        elif model is not None and vectorizer is None:
            # pipeline or model that handles raw input
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba([text])[0][1]
                return float(round(prob * 100, 2))
            pred = model.predict([text])[0]
            return 100.0 if int(pred) == 1 else 0.0
    except Exception as e:
        logging.error("ML prediction failed: %s", e)

    # fallback heuristic scoring
    low = text.lower()
    score = 30.0
    for kw, add in [("verify", 12), ("urgent", 15), ("password", 10), ("suspended", 18), ("click", 8), ("account", 10)]:
        if kw in low:
            score += add
    return min(100.0, score)

# ========== Feature extraction & URL reputation ==========
def simple_url_reputation(url: str) -> int:
    score = 0
    if not url:
        return 50
    u = url.lower()
    host = urlparse(u).netloc or ""

    # suspicious TLDs
    if re.search(r"\.(xyz|top|club|ru|tk|cf|ga|gq|ml)\b", u):
        score += 25
    # long URL
    if len(u) > 100:
        score += 10
    # many hyphens/digits
    if host.count("-") >= 2:
        score += 10
    if re.search(r"\d{4,}", u):
        score += 6

    # optional WHOIS checks (short timeout, env toggle)
    if os.getenv("URL_WHOIS_ENABLED", "true").lower() == "true" and whois is not None and host:
        try:
            import socket
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3.0)
            try:
                w = whois.whois(host)
            finally:
                socket.setdefaulttimeout(old_to)
            if w and getattr(w, "creation_date", None):
                cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if hasattr(cd, "timestamp"):
                    age_days = (time.time() - cd.timestamp()) / 86400
                    if age_days < 30:
                        score += 20
                    elif age_days < 365:
                        score += 8
        except Exception:
            pass

    return min(100, score)

def extract_email_features(email_data: dict) -> dict:
    features = {}
    sender = email_data.get("sender", "")
    subject = email_data.get("subject", "")
    content = email_data.get("content", "")
    links = email_data.get("links", []) or []
    headers = email_data.get("headers", {}) or {}

    features["sender_domain"] = sender.split("@")[-1] if "@" in sender else ""
    features["suspicious_sender"] = any(dom in sender.lower() for dom in ["noreply", "no-reply", "alert"])

    low_subj = subject.lower()
    features["subject_length"] = len(subject)
    features["subject_urgency"] = any(w in low_subj for w in ["urgent", "immediately", "alert", "important", "action required"])
    features["subject_suspicious"] = any(w in low_subj for w in ["verify", "password", "account", "security", "update"])

    features["content_length"] = len(content)
    features["has_links"] = len(links) > 0
    features["link_count"] = len(links)

    suspicious_links = []
    for link in links:
        try:
            if simple_url_reputation(link) > 50:
                suspicious_links.append(link)
        except Exception:
            pass
    features["suspicious_link_count"] = len(suspicious_links)
    features["has_suspicious_links"] = len(suspicious_links) > 0

    features["spf_pass"] = str(headers.get("spf", "")).lower() == "pass"
    features["dkim_pass"] = str(headers.get("dkim", "")).lower() == "pass"
    features["dmarc_pass"] = str(headers.get("dmarc", "")).lower() == "pass"
    return features

def calculate_fallback_risk(email_data: dict, features: dict) -> int:
    risk = 0
    risk += 15 if features.get("subject_urgency") else 0
    risk += 12 if features.get("subject_suspicious") else 0
    risk += 20 if features.get("has_suspicious_links") else 0
    risk += 10 if features.get("suspicious_sender") else 0
    risk += min(features.get("suspicious_link_count", 0) * 8, 25)
    risk += 15 if not all([features.get("spf_pass"), features.get("dkim_pass")]) else 0
    return min(100, risk)

def apply_rule_based_adjustments(base_score: float, features: dict) -> float:
    adjusted = base_score
    if features.get("suspicious_link_count", 0) >= 3:
        adjusted += 15
    if not features.get("spf_pass") and not features.get("dkim_pass"):
        adjusted += 20
    if features.get("subject_urgency") and features.get("has_suspicious_links"):
        adjusted += 10
    return min(100.0, adjusted)

def get_risk_level(score: float) -> str:
    return "HIGH" if score >= 70 else ("MEDIUM" if score >= 30 else "LOW")

def log_analysis(email_data: dict, risk_score: float, features: dict):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "sender": email_data.get("sender"),
        "subject": email_data.get("subject"),
        "message_id": email_data.get("message_id"),
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "alert_triggered": risk_score >= THRESH,
        "features": features,
    }
    try:
        # append as NDJSON (one JSON per line)
        with open("analysis_log.ndjson", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logging.error("Logging failed: %s", e)

# ========== SANDBOX ENDPOINTS ==========
@app.route('/analyze-link', methods=['POST'])
def analyze_link_sandbox():
    """Analyze a link in sandbox environment"""
    if not SANDBOX_ENABLED:
        return jsonify({'error': 'Sandbox not available'}), 503
        
    try:
        data = request.get_json()
        url = data.get('url')
        email_context = data.get('email_context', {})
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Run sandbox analysis (SYNC - no asyncio)
        analysis_results = sandbox.analyze_url(url, email_context)
        
        if analysis_results.get('status') == 'failed':
            return jsonify({
                'status': 'error',
                'message': analysis_results.get('error', 'Analysis failed')
            }), 500
        
        # Generate report
        report = sandbox.generate_report(analysis_results)
        
        # Read screenshot as base64 for frontend
        screenshot_data = None
        if analysis_results.get('screenshot_path') and os.path.exists(analysis_results['screenshot_path']):
            with open(analysis_results['screenshot_path'], 'rb') as f:
                screenshot_data = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'status': 'success',
            'analysis_id': analysis_results['analysis_id'],
            'risk_score': analysis_results['risk_score'],
            'risk_level': sandbox._get_risk_level(analysis_results['risk_score']),
            'screenshot': screenshot_data,
            'report_files': {
                'json': report['json_report'],
                'text': report['text_report']
            },
            'findings': {
                'redirected': analysis_results.get('has_redirected', False),
                'password_fields': analysis_results['phishing_indicators'].get('password_fields', False),
                'login_forms': analysis_results['phishing_indicators'].get('login_forms', False),
                'suspicious_keywords': analysis_results['phishing_indicators'].get('suspicious_keywords', [])
            },
            'recommendations': report['report_data']['recommendations']
        })
        
    except Exception as e:
        logging.error(f"Sandbox analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/safe-redirect/<path:encoded_url>')
def safe_redirect(encoded_url):
    """Safe redirect endpoint with sandbox analysis"""
    try:
        # Decode URL
        original_url = base64.b64decode(encoded_url).decode('utf-8')
        
        # Quick safety check before sandbox
        quick_risk = simple_url_reputation(original_url)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishSpector - Safe Link Analysis</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .warning {{ background: #fff3cd; border: 2px solid #ffc107; padding: 20px; border-radius: 10px; }}
                .danger {{ background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 10px; }}
                .safe {{ background: #d1ecf1; border: 2px solid #17a2b8; padding: 20px; border-radius: 10px; }}
                button {{ padding: 10px 20px; margin: 5px; border: none; border-radius: 5px; cursor: pointer; }}
                .analyze-btn {{ background: #007bff; color: white; }}
                .proceed-btn {{ background: #28a745; color: white; }}
                .cancel-btn {{ background: #6c757d; color: white; }}
            </style>
        </head>
        <body>
            <h1>🔒 PhishSpector Safe Link Analysis</h1>
            
            <div class="{'danger' if quick_risk > 50 else 'warning'}">
                <h2>{"🚨 High Risk Link Detected" if quick_risk > 50 else "⚠️ Suspicious Link"}</h2>
                
                <p><strong>URL:</strong> {original_url}</p>
                <p><strong>Quick Risk Assessment:</strong> {quick_risk}%</p>
                
                <div id="analysis-section">
                    <p>We recommend analyzing this link in our safe sandbox environment before proceeding.</p>
                    <button class="analyze-btn" onclick="analyzeInSandbox()">🔍 Analyze in Safe Sandbox</button>
                    <button class="proceed-btn" onclick="proceedToSite()">➡️ Proceed Anyway</button>
                    <button class="cancel-btn" onclick="goBack()">❌ Go Back</button>
                </div>
                
                <div id="analysis-results" style="display: none; margin-top: 20px; padding: 15px; background: white; border-radius: 5px;">
                    <!-- Results will be populated here -->
                </div>
            </div>

            <script>
                function analyzeInSandbox() {{
                    document.getElementById('analysis-section').innerHTML = '<p>🕐 Analyzing link in safe environment...</p>';
                    
                    fetch('/analyze-link', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ url: '{original_url}' }})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.status === 'success') {{
                            showAnalysisResults(data);
                        }} else {{
                            document.getElementById('analysis-section').innerHTML = 
                                '<p>❌ Analysis failed. Please try again.</p>' +
                                '<button class="proceed-btn" onclick="proceedToSite()">➡️ Proceed Anyway</button>' +
                                '<button class="cancel-btn" onclick="goBack()">❌ Go Back</button>';
                        }}
                    }})
                    .catch(error => {{
                        document.getElementById('analysis-section').innerHTML = 
                            '<p>❌ Analysis error. Please try again.</p>' +
                            '<button class="proceed-btn" onclick="proceedToSite()">➡️ Proceed Anyway</button>' +
                            '<button class="cancel-btn" onclick="goBack()">❌ Go Back</button>';
                    }});
                }}
                
                function showAnalysisResults(data) {{
                    const resultsHtml = `
                        <h3>🔍 Sandbox Analysis Complete</h3>
                        <p><strong>Risk Score:</strong> <span style="color: ${{data.risk_score > 70 ? 'red' : data.risk_score > 30 ? 'orange' : 'green'}}">${{data.risk_score}}% (${{data.risk_level}})</span></p>
                        
                        <h4>Findings:</h4>
                        <ul>
                            <li>Password Fields: ${{data.findings.password_fields ? '✅ Yes' : '❌ No'}}</li>
                            <li>Login Forms: ${{data.findings.login_forms ? '✅ Yes' : '❌ No'}}</li>
                            <li>Was Redirected: ${{data.findings.redirected ? '✅ Yes' : '❌ No'}}</li>
                            <li>Suspicious Keywords: ${{data.findings.suspicious_keywords.length > 0 ? '✅ ' + data.findings.suspicious_keywords.join(', ') : '❌ None'}}</li>
                        </ul>
                        
                        ${{data.screenshot ? `<h4>Screenshot Preview:</h4><img src="data:image/png;base64,${{data.screenshot}}" style="max-width: 100%; border: 1px solid #ccc;" />` : ''}}
                        
                        <h4>Recommendations:</h4>
                        <ul>
                            ${{data.recommendations.map(rec => `<li>${{rec}}</li>`).join('')}}
                        </ul>
                        
                        <div style="margin-top: 20px;">
                            <button class="proceed-btn" onclick="proceedToSite()">➡️ Proceed to Website</button>
                            <button class="cancel-btn" onclick="goBack()">❌ Go Back</button>
                            <button class="analyze-btn" onclick="downloadReport('${{data.analysis_id}}')">📄 Download Full Report</button>
                        </div>
                    `;
                    
                    document.getElementById('analysis-results').innerHTML = resultsHtml;
                    document.getElementById('analysis-results').style.display = 'block';
                }}
                
                function proceedToSite() {{
                    window.location.href = '{original_url}';
                }}
                
                function goBack() {{
                    window.history.back();
                }}
                
                function downloadReport(analysisId) {{
                    alert('Report download would be implemented here for analysis: ' + analysisId);
                    // In production, this would download the actual report files
                }}
            </script>
        </body>
        </html>
        """
        
    except Exception as e:
        return f"Error processing link: {str(e)}", 400

# ========== EXISTING API endpoints ==========
@app.route("/analyze-email", methods=["POST"])
def analyze_email():
    try:
        data = request.get_json(force=True) or {}
        email_data = {
            "message_id": data.get("message_id", ""),
            "sender": data.get("sender", ""),
            "subject": data.get("subject", ""),
            "links": data.get("links", []),
            "content": data.get("content", ""),
            "headers": data.get("headers", {}),
        }
        if not email_data["sender"] or not email_data["subject"]:
            return jsonify({"error": "Missing sender/subject"}), 400

        logging.info("📧 Analyzing: %s", email_data["subject"][:80])
        features = extract_email_features(email_data)

        feature_text = f"{email_data['subject']} {email_data['content']}"
        ml_score = safe_predict(feature_text)

        final_score = apply_rule_based_adjustments(ml_score, features)
        log_analysis(email_data, final_score, features)

        top_link = (email_data["links"][0] if email_data["links"] else "") or ""
        sent, status = send_alert_if_needed(
            message_id=email_data["message_id"],
            score=final_score,
            subject=email_data["subject"],
            sender=email_data["sender"],
            top_link=top_link,
        )

        color = "red" if final_score >= 70 else ("orange" if final_score >= 40 else "green")
        label = "High" if final_score >= 70 else ("Medium" if final_score >= 40 else "Low")

        return jsonify({
            "risk_score": final_score,
            "risk_level": get_risk_level(final_score),
            "badge": {"color": color, "label": label},
            "alert": {"sent": sent, "status": status},
            "features": {
                "suspicious_links": features.get("suspicious_link_count", 0),
                "urgency_keywords": features.get("subject_urgency", False),
                "auth_headers_pass": all([
                    features.get("spf_pass", False),
                    features.get("dkim_pass", False),
                    features.get("dmarc_pass", False),
                ]),
            },
            "twilio_enabled": TWILIO_ENABLED,
            "sandbox_enabled": SANDBOX_ENABLED,
            "timestamp": datetime.now().isoformat(),
        })
    except Exception as e:
        logging.error("Analysis error: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json(force=True) or {}
    url = data.get("url", "")
    return jsonify({"reputation_score": simple_url_reputation(url)})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "No text provided"}), 400
    try:
        score = safe_predict(text)
        return jsonify({"ml_score": score})
    except Exception as e:
        logging.error("Prediction error: %s", e)
        return jsonify({"ml_score": 50})

@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json(force=True) or {}
    feedback_file = "feedback_log.json"
    entry = {"timestamp": datetime.now().isoformat(), "message_id": data.get("message_id"), "label": data.get("label")}
    try:
        if os.path.exists(feedback_file):
            with open(feedback_file, "r", encoding="utf-8") as f:
                try:
                    lst = json.load(f)
                except json.JSONDecodeError:
                    lst = []
        else:
            lst = []
        lst.append(entry)
        with open(feedback_file, "w", encoding="utf-8") as f:
            json.dump(lst, f, indent=2)
        logging.info("Feedback saved: %s", entry)
        return jsonify({"status": "success", "message": "Feedback recorded"})
    except Exception as e:
        logging.error("Feedback save failed: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "twilio_enabled": TWILIO_ENABLED,
        "model_loaded": model is not None,
        "sandbox_enabled": SANDBOX_ENABLED,
        "service": "PhishSpector Backend"
    })

@app.route("/")
def home():
    return "✅ PhishSpector backend running with Twilio dedupe & cooldown + SANDBOX"

# ========== Startup: Gmail monitor thread + run server ==========
if __name__ == "__main__":
    # Decide if we're in the reloader child (where we want to start threads)
    is_reloader_child = (os.environ.get("WERKZEUG_RUN_MAIN") == "true") or not app.debug

    _monitor_started = False
    gm_enabled = os.getenv("GMAIL_MONITOR_ENABLED", "true").lower() == "true"

    if gm_enabled and is_reloader_child and monitor_loop is not None:
        try:
            # prevent double-start even if this block is hit twice somehow
            if not os.environ.get("PS_MONITOR_ALREADY_STARTED"):
                os.environ["PS_MONITOR_ALREADY_STARTED"] = "1"
                stop_event = Event()
                t = Thread(target=monitor_loop, args=(stop_event,), daemon=True)
                t.start()
                _monitor_started = True
                print("✅ Gmail monitor thread started")
        except Exception as e:
            logging.error("Failed to start Gmail monitor: %s", e)

    print("\n" + "=" * 50)
    print("🚀 PhishSpector Backend Starting...")
    print("=" * 50)
    print(f"✅ Twilio Enabled: {TWILIO_ENABLED}")
    print(f"✅ Model Loaded: {model is not None}")
    print(f"✅ Gmail Monitor: {_monitor_started}")
    print(f"✅ Sandbox Enabled: {SANDBOX_ENABLED}")
    print(f"✅ Service: http://0.0.0.0:5000")
    print("=" * 50 + "\n")

    # IMPORTANT: keep debug=True if you like, but DO NOT disable the reloader here.
    # We already guarded with WERKZEUG_RUN_MAIN so threads start only in the child.
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)