# 🚀 PhishSpector - Advanced Phishing Protection System

🛡️ Overview

**PhishSpector** is a comprehensive browser extension that provides multi-layered protection against sophisticated phishing attacks through real-time analysis, machine learning, and proactive prevention mechanisms.

### Key Capabilities
- 🔍 **Pre-click email analysis** with ML-powered risk scoring
- 📧 **Email header authentication** (SPF/DKIM/DMARC)
- 🔐 **SSL certificate forensic analysis**
- 🛡️ **Active password protection** with auto-fill blocking
- 📱 **Real-time SMS alerts** for high-risk emails
- 🎯 **Safe sandbox environment** for link analysis

---

## ⚡ Features

### Core Protection Layers
| Layer | Technology | Protection Level |
|-------|------------|------------------|
| Email Analysis | Machine Learning | 🚀 Advanced |
| Header Authentication | SPF/DKIM/DMARC | 🚀 Advanced |
| Certificate Forensics | SSL/TLS Analysis | 🚀 Advanced |
| Password Protection | Auto-fill Blocking | 🚀 Advanced |
| Safe Browsing | Sandbox Environment | ⚡ Intermediate |

---

📥 Installation Guide

Prerequisites
- **Python 3.8+**
- **Node.js** (for future enhancements)
- **Chrome Browser** (latest version)
- **Git**

Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/phishspector.git
cd phishspector
```

### Step 2: Backend Setup

Windows
```bash
# Navigate to backend directory
cd phishspector-backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install flask flask-cors scikit-learn joblib python-whois pandas requests

# Train the ML model
python train_model.py

# Start the backend server
python app.py
```

macOS/Linux
```bash
cd phishspector-backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install flask flask-cors scikit-learn joblib python-whois pandas requests
python train_model.py
python app.py
```

Step 3: Chrome Extension Setup

1. **Open Chrome Browser**
2. Navigate to `chrome://extensions/`
3. **Enable Developer Mode** (toggle in top-right)
4. Click **"Load unpacked"**
5. Select the `phishspector-extension` folder
6. **Extension should appear** in your toolbar

---

 ⚙️ Setup & Configuration

Environment Variables

Create a `.env` file in the `phishspector-backend` directory:

```env
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=True
FLASK_PORT=5000

# SMS Service Configuration (Twilio)
TWILIO_ACCOUNT_SID=your_account_sid_here
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_PHONE_NUMBER=+1234567890

# User Phone Number for Alerts
USER_PHONE_NUMBER=+1234567890

# Security Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:5000

# ML Model Path
MODEL_PATH=./models/phishing_model.pkl
```

### Getting SMS Credentials

#### Twilio Setup (Recommended)
1. Sign up at [Twilio](https://www.twilio.com/try-twilio)
2. Get your **Account SID** and **Auth Token**
3. Purchase a phone number
4. Add credentials to `.env` file

#### Alternative SMS Services
- **AWS SNS** - For scalable enterprise use
- **Nexmo/Vonage** - Alternative provider
- **Custom Gateway** - For specific carrier integration

---

## 🚀 Running the Application

### 1. Start Backend Server
```bash
cd phishspector-backend

# Activate virtual environment (if not already active)
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate     # macOS/Linux

# Start Flask server
python app.py
```

**Expected Output:**
```
🚀 PhishSpector Backend Server Starting...
📍 Server running on: http://localhost:5000
📧 ML Model loaded successfully
🔐 Safe sandbox ready
✅ Server is ready to accept requests
```

### 2. Verify Backend is Running
Open your browser and visit: `http://localhost:5000/health`

You should see:
```json
{
  "status": "healthy", 
  "service": "PhishSpector Backend",
  "version": "1.0.0"
}
```

### 3. Test the Safe Sandbox
Visit: `http://localhost:5000/safe-redirect/aHR0cDovL2V4YW1wbGUuY29t`

### 4. Chrome Extension Status
- Look for the **PhishSpector icon** in Chrome toolbar
- Icon should be **colored** (not grayed out)
- Right-click → "Manage extension" should show "Enabled"

---

## 🧪 Testing & Demo

### Demo Scenario 1: Basic Phishing Detection

1. **Send test email** to your Gmail with suspicious content:
   - Subject: "Urgent: Your Account Will Be Suspended"
   - Body: "Click here to verify: http://fake-login.xyz"

2. **Open Gmail** - You should see risk badges on emails

3. **Click suspicious link** - PhishSpector popup should appear

### Demo Scenario 2: Advanced Features

1. **Use ngrok for testing** (optional):
```bash
# Install ngrok
npm install -g ngrok

# Expose your backend
ngrok http 5000
```

2. **Create phishing test page**:
   - Use the provided `phishing-test-site` 
   - Run on port 5001 to avoid conflicts

### Test Endpoints

| Endpoint | Method | Purpose | Test URL |
|----------|--------|---------|----------|
| `/health` | GET | Server status | `http://localhost:5000/health` |
| `/analyze/email` | POST | Email analysis | Use Postman |
| `/safe-redirect/<url>` | GET | Safe browsing | Encode any URL in base64 |
| `/sms/alert` | POST | Send SMS | Requires credentials |

---

## 🔧 Troubleshooting

### Common Issues & Solutions

#### ❌ Backend Server Won't Start
**Problem:** Port 5000 already in use
**Solution:**
```bash
# Find process using port
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # macOS/Linux

# Kill process or use different port
python app.py --port 5001
```

#### ❌ Chrome Extension Not Loading
**Problem:** "Manifest file is missing or unreadable"
**Solution:**
- Ensure you're loading the `phishspector-extension` folder (not parent)
- Check `manifest.json` exists in the folder
- Verify Chrome version supports Manifest V3

#### ❌ Module Import Errors
**Problem:** "No module named 'flask'"
**Solution:**
```bash
# Reinstall dependencies
pip uninstall -r requirements.txt
pip install -r requirements.txt

# Verify virtual environment
where python  # Should show venv path
```

#### ❌ SMS Not Sending
**Problem:** Twilio credentials incorrect
**Solution:**
- Verify `.env` file exists in correct directory
- Check Twilio account is active
- Ensure phone number format: `+1234567890`

### Debug Mode

Enable detailed logging by setting in `.env`:
```env
DEBUG=True
LOG_LEVEL=DEBUG
```

Check logs in:
- **Backend**: Console output from Flask server
- **Extension**: Chrome DevTools → Console
- **Background**: Chrome → Extensions → Service Worker

---

📚 API Documentation

Core Endpoints

 1. Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

 2. Email Analysis
```http
POST /analyze/email
Content-Type: application/json

{
  "subject": "Urgent Security Alert",
  "sender": "security@fake-bank.com",
  "body": "Your account will be suspended...",
  "links": ["http://fake-bank-login.xyz"]
}
```

**Response:**
```json
{
  "risk_score": 0.85,
  "risk_level": "HIGH",
  "warnings": ["Suspicious domain", "Urgency language"],
  "recommendations": ["Do not click links", "Verify sender identity"]
}
```

 3. Safe Redirect
```http
GET /safe-redirect/{base64_encoded_url}
```
**Usage:** `http://localhost:5000/safe-redirect/aHR0cDovL2V4YW1wbGUuY29t`

 4. SMS Alert
```http
POST /sms/alert
Content-Type: application/json

{
  "message": "High-risk phishing email detected",
  "priority": "HIGH",
  "user_id": "user@example.com"
}
```

---

## 🛠️ Development Guide

### Project Structure
```

```

### Adding New Features

#### 1. New ML Feature
1. Add feature extraction in `train_model.py`
2. Retrain model: `python train_model.py`
3. Update analysis in `app.py`

#### 2. New Protection Layer
1. Add detection logic in `content.js`
2. Create UI components in `popup.html`
3. Update backend analysis in `app.py`

### Testing Checklist
- [ ] Backend server starts without errors
- [ ] Chrome extension loads properly
- [ ] Risk badges appear on suspicious emails
- [ ] Popup shows on link click
- [ ] Safe sandbox redirects work
- [ ] SMS alerts send (if configured)
- [ ] All analysis layers work correctly

---

## 📞 Support & Resources

### Documentation
- [Chrome Extensions Documentation](https://developer.chrome.com/docs/extensions/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Twilio SMS API](https://www.twilio.com/docs/sms)

### Getting Help
1. Check troubleshooting section above
2. Verify all setup steps completed
3. Check console logs for errors
4. Ensure all services are running

### Contributing
1. Fork the repository
2. Create feature branch
3. Submit pull request with description

---

## 🎯 Next Steps

After successful setup:
1. ✅ Test with sample phishing emails
2. ✅ Configure SMS alerts with real credentials  
3. ✅ Train ML model with your email data
4. ✅ Customize detection thresholds
5. ✅ Deploy to production environment

