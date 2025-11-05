
from dotenv import load_dotenv
load_dotenv()

import os, traceback
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

sid = os.getenv("TWILIO_ACCOUNT_SID")
tok = os.getenv("TWILIO_AUTH_TOKEN")
from_sms = os.getenv("ALERT_FROM_SMS")
from_wa  = os.getenv("ALERT_FROM_WHATSAPP")
to = os.getenv("ALERT_TO_PRIMARY")

print("ENV:", {"sid": bool(sid), "tok": bool(tok), "from_sms": from_sms, "from_wa": from_wa, "to": to})

c = Client(sid, tok)

print("\nTesting SMS send...")
try:
    m = c.messages.create(from_=from_sms, to=to, body="PhishSpector TEST SMS — ignore")
    print("✅ SMS sent, sid:", m.sid)
except TwilioRestException as e:
    print("❌ TwilioRestException (SMS):", getattr(e, "code", ""), e.msg)
    traceback.print_exc()
except Exception as e:
    print("❌ Exception (SMS):", e)
    traceback.print_exc()

print("\nTesting WhatsApp send...")
try:
    m2 = c.messages.create(from_=from_wa, to=f"whatsapp:{to}", body="PhishSpector TEST WA — ignore")
    print("✅ WhatsApp sent, sid:", m2.sid)
except TwilioRestException as e:
    print("❌ TwilioRestException (WA):", getattr(e, "code", ""), e.msg)
    traceback.print_exc()
except Exception as e:
    print("❌ Exception (WA):", e)
    traceback.print_exc()
