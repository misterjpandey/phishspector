import os, time, hashlib, logging
from twilio.rest import Client

# --- Load environment ---
SID = os.getenv("TWILIO_ACCOUNT_SID")
TOK = os.getenv("TWILIO_AUTH_TOKEN")
FROM_SMS = os.getenv("ALERT_FROM_SMS")
TO1 = os.getenv("ALERT_TO_PRIMARY")
TO2 = os.getenv("ALERT_TO_BACKUP")
THRESH = int(os.getenv("ALERT_THRESHOLD", "80"))
USE_SMS = os.getenv("ALERT_ENABLE_SMS", "true").lower() == "true"
COOLDOWN_MIN = int(os.getenv("ALERT_COOLDOWN_MINUTES", "15"))

_twilio = Client(SID, TOK) if SID and TOK else None
_last_sent = {}  # simple dedupe

def send_alert_if_needed(message_id: str, score: float, subject: str, sender: str, top_link: str = ""):
    """Send SMS alert only if score ≥ THRESH."""
    if not _twilio:
        return False, "twilio_disabled"
    if not USE_SMS:
        return False, "sms_disabled"
    if score < THRESH:
        return False, "below_threshold"

    # dedupe cooldown
    key = hashlib.sha256((message_id or f"{sender}|{subject}").encode()).hexdigest()
    now = time.time()
    if now - _last_sent.get(key, 0) < COOLDOWN_MIN * 60:
        return False, "cooldown"

    body = (
        f"🚨 PhishSpector Alert\n"
        f"Risk: {int(score)} / 100\n"
        f"From: {sender}\n"
        f"Subject: {subject[:80]}\n"
        f"Link: {top_link[:120] if top_link else '—'}\n"
        f"Action: DO NOT click. Report/Quarantine."
    )

    try:
        _twilio.messages.create(from_=FROM_SMS, to=TO1, body=body)
        if TO2:
            _twilio.messages.create(from_=FROM_SMS, to=TO2, body=body)
        _last_sent[key] = now
        logging.info(f"✅ SMS alert sent to {TO1} for {subject}")
        return True, "sent"
    except Exception as e:
        logging.error(f"❌ SMS alert failed: {e}")
        return False, f"error:{e}"
