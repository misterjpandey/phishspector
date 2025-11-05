# gmail_monitor.py — integrated with config.yaml, score labels, SQLite logging, initial scan
import os, re, threading, time, logging
from typing import Dict, Any, Set, Optional
import requests
import yaml

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from db_logger import DBLogger

# --- Label cache (id <-> name) ---
_LABEL_ID2NAME = {}
_LABEL_NAME2ID = {}

def _refresh_label_cache(service):
    global _LABEL_ID2NAME, _LABEL_NAME2ID
    _LABEL_ID2NAME, _LABEL_NAME2ID = {}, {}
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for lb in labels:
        _LABEL_ID2NAME[lb["id"]] = lb["name"]
        _LABEL_NAME2ID[lb["name"]] = lb["id"]

def _label_names_from_ids(ids):
    return [_LABEL_ID2NAME.get(i, i) for i in (ids or [])]

# ---------- defaults (env fallback if no config.yaml) ----------
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

# env defaults
ENV = {
    "GMAIL_QUERY": os.getenv("GMAIL_QUERY", "category:primary newer_than:1d"),
    "GMAIL_ONLY_UNREAD": os.getenv("GMAIL_ONLY_UNREAD", "true").lower() == "true",
    "GMAIL_POLL_SECONDS": int(os.getenv("GMAIL_POLL_SECONDS", "20")),
    "ANALYZE_URL": os.getenv("ANALYZE_URL", "http://127.0.0.1:5000/analyze-email"),
    "ANALYZE_TIMEOUT": int(os.getenv("ANALYZE_TIMEOUT", "30")),
    "GMAIL_MAX_RESULTS": int(os.getenv("GMAIL_MAX_RESULTS", "50")),
    "PS_SCAN_LABEL": os.getenv("PS_SCAN_LABEL", "PHISHSPECTOR_SCANNED"),
    "INITIAL_FULL_SCAN": os.getenv("INITIAL_FULL_SCAN", "false").lower() == "true",
    "APPLY_SCORE_LABEL": os.getenv("APPLY_SCORE_LABEL", "true").lower() == "true",
    "SCORE_LABEL_PREFIX": os.getenv("SCORE_LABEL_PREFIX", "PHISHING-SUSPECT"),
    "DB_ENABLED": os.getenv("DB_ENABLED", "true").lower() == "true",
    "DB_SQLITE_PATH": os.getenv("DB_SQLITE_PATH", "phish_logs.db"),
}

# ---------- optional config.yaml overrides ----------
CFG_PATH = os.getenv("CONFIG_YAML", "config.yaml")
if os.path.exists(CFG_PATH):
    try:
        cfg = yaml.safe_load(open(CFG_PATH, "r", encoding="utf-8")) or {}
    except Exception:
        cfg = {}
else:
    cfg = {}

gmail_cfg = cfg.get("gmail", {})
an_cfg    = cfg.get("analyzer", {})
labels    = cfg.get("labels", {})
db_cfg    = cfg.get("db", {})
worker    = cfg.get("worker", {})

QUERY              = gmail_cfg.get("query", ENV["GMAIL_QUERY"])
ONLY_UNREAD        = gmail_cfg.get("only_unread", ENV["GMAIL_ONLY_UNREAD"])
POLL_SECONDS       = worker.get("poll_interval_seconds", ENV["GMAIL_POLL_SECONDS"])
SELF_ANALYZE_URL   = an_cfg.get("url", ENV["ANALYZE_URL"])
ANALYZE_TIMEOUT    = an_cfg.get("timeout", ENV["ANALYZE_TIMEOUT"])
MAX_RESULTS        = gmail_cfg.get("max_results", ENV["GMAIL_MAX_RESULTS"])
LABEL_NAME         = labels.get("processed", ENV["PS_SCAN_LABEL"])
INITIAL_FULL_SCAN  = gmail_cfg.get("initial_full_scan", ENV["INITIAL_FULL_SCAN"])
APPLY_SCORE_LABEL  = labels.get("apply_score_label", ENV["APPLY_SCORE_LABEL"])
SCORE_LABEL_PREFIX = labels.get("score_prefix", ENV["SCORE_LABEL_PREFIX"])
DB_ENABLED         = db_cfg.get("enabled", ENV["DB_ENABLED"])
DB_SQLITE_PATH     = db_cfg.get("sqlite_path", ENV["DB_SQLITE_PATH"])

# ✅ YAML-based credentials
CRED_FILE  = gmail_cfg.get("credentials_file", os.getenv("GOOGLE_CREDENTIALS_FILE", "credentials.json"))
TOKEN_FILE = gmail_cfg.get("token_path",       os.getenv("GOOGLE_TOKEN_FILE", "token.json"))

log = logging.getLogger("gmail_monitor")
URL_RE = re.compile(r"(https?://[^\s<>\)\"']+)", re.IGNORECASE)

# ---------- Gmail helpers ----------
def _build_gmail():
    token_file = TOKEN_FILE
    cred_file  = CRED_FILE
    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            from google.auth.transport.requests import Request
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(cred_file, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def _ensure_label(service, name: str) -> Optional[str]:
    try:
        if not _LABEL_NAME2ID:
            _refresh_label_cache(service)
        if name in _LABEL_NAME2ID:
            return _LABEL_NAME2ID[name]
        body = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
        new_lb = service.users().labels().create(userId="me", body=body).execute()
        # update caches
        _LABEL_ID2NAME[new_lb["id"]] = new_lb["name"]
        _LABEL_NAME2ID[new_lb["name"]] = new_lb["id"]
        return new_lb.get("id")
    except Exception as e:
        log.warning("Label ensure failed (%s): %s", name, e)
        return None

def _has_score_label(existing_label_ids: list, prefix: str) -> bool:
    """True if any existing label name starts with prefix (e.g., 'PHISHING-SUSPECT')."""
    # make sure cache has names
    if not _LABEL_ID2NAME:
        # we cannot refresh without service here; callers refresh once at loop start
        pass
    names = _label_names_from_ids(existing_label_ids or [])
    return any((n or "").startswith(prefix) for n in names)

def _extract_field(headers, name):
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value", "")
    return ""

def _extract_links(payload: Dict[str, Any]) -> list:
    import base64
    text_parts = []
    def walk(p):
        if not p: return
        mime = p.get("mimeType", "")
        data = p.get("body", {}).get("data")
        if data and ("text/plain" in mime or "text/html" in mime):
            try:
                text = base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")
                text_parts.append(text)
            except Exception:
                pass
        for child in p.get("parts", []) or []:
            walk(child)
    walk(payload)
    blob = "\n".join(text_parts)
    return list(set(URL_RE.findall(blob)))

def _mark_processed(service, msg_id, label_id):
    if not label_id: return
    try:
        service.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"addLabelIds": [label_id]}
        ).execute()
    except Exception as e:
        log.warning("Mark processed failed for %s: %s", msg_id, e)

def _apply_score_label(service, msg_id: str, score: float, prefix: str, existing_label_ids: list):
    try:
        # SKIP if a score label already exists on this message
        if _has_score_label(existing_label_ids, prefix):
            log.info("Skip label (already present) for %s", msg_id)
            return

        bucket = int(round(score / 5.0) * 5)  # e.g., 83 -> 85
        label_name = f"{prefix} ({bucket})"
        lid = _ensure_label(service, label_name)
        if lid:
            service.users().messages().modify(
                userId="me",
                id=msg_id,
                body={"addLabelIds": [lid]}
            ).execute()
            log.info("Applied label '%s' to %s", label_name, msg_id)
    except Exception as e:
        log.warning("Score label failed for %s: %s", msg_id, e)

def _build_query() -> str:
    base_q = (QUERY or "").strip()
    if ONLY_UNREAD:
        return f"({base_q}) is:unread" if base_q else "is:unread"
    return base_q or ""

# ---------- Analyzer POST with retry ----------
def _post_analyze(body: dict) -> Optional[dict]:
    tries = 2
    last_err = None
    for attempt in range(1, tries + 1):
        try:
            r = requests.post(SELF_ANALYZE_URL, json=body, timeout=ANALYZE_TIMEOUT)
            r.raise_for_status()
            if r.headers.get("content-type", "").lower().startswith("application/json"):
                return r.json()
            return {}
        except requests.exceptions.Timeout as e:
            last_err = e
            log.error("Analyze timeout (attempt %s/%s) for %s", attempt, tries, body.get("message_id"))
            if attempt < tries: time.sleep(1.0)
        except Exception as e:
            last_err = e
            log.error("Analyze POST fail for %s: %s", body.get("message_id"), e)
            break
    if last_err:
        log.error("Analyze ultimately failed for %s: %s", body.get("message_id"), last_err)
    return None

# ---------- initial full scan (optional) ----------
def _initial_full_scan(service, processed: Set[str], label_processed_id: Optional[str], dblog: Optional[DBLogger]):
    q = _build_query().replace(" is:unread", "")  # scan even read ones for initial sweep
    log.info("Initial full scan enabled; scanning with query=%r", q)
    next_token = None
    while True:
        res = service.users().messages().list(
            userId="me", q=q, maxResults=MAX_RESULTS, pageToken=next_token
        ).execute()
        msgs = res.get("messages", []) or []
        next_token = res.get("nextPageToken")
        if not msgs:
            break
        for m in msgs:
            mid = m["id"]
            if mid in processed: continue
            full = service.users().messages().get(userId="me", id=mid, format="full").execute()
            headers = full.get("payload", {}).get("headers", [])
            sender  = _extract_field(headers, "From")
            subject = _extract_field(headers, "Subject")
            snippet = full.get("snippet", "")
            links   = _extract_links(full.get("payload", {}))

            body = {
                "message_id": mid, "sender": sender or "", "subject": subject or "(no subject)",
                "links": links, "content": snippet or ""
            }
            out = _post_analyze(body) or {}
            log.info("Initial analyzed %s -> score=%s level=%s alert=%s",
                     mid, out.get("risk_score"), out.get("risk_level"),
                     (out.get("alert") or {}).get("sent"))

            try:
                if APPLY_SCORE_LABEL and out.get("risk_score") is not None:
                    _apply_score_label(
                        service,
                        mid,
                        float(out["risk_score"]),
                        SCORE_LABEL_PREFIX,
                        full.get("labelIds", [])
                    )
            except Exception:
                pass

            processed.add(mid)
            _mark_processed(service, mid, label_processed_id)

            if dblog:
                try:
                    dblog.log(
                        message_id=mid,
                        sender=sender or "",
                        subject=subject or "",
                        score=int(out.get("risk_score") or 0),
                        level=out.get("risk_level") or "",
                        alert=out.get("alert") or {},
                        features=out.get("features") or {},
                        reasons=None
                    )
                except Exception as e:
                    log.warning("DB log failed for %s: %s", mid, e)

        if not next_token:
            break
    log.info("Initial full scan complete; switching to live monitoring.")

# ---------- main loop ----------
def monitor_loop(stop_event: threading.Event):
    try:
        service = _build_gmail()
        # refresh label-name cache once up-front
        _refresh_label_cache(service)

        processed: Set[str] = set()
        label_processed_id = _ensure_label(service, LABEL_NAME)

        dblog = DBLogger(DB_SQLITE_PATH) if DB_ENABLED else None

        log.info("Gmail monitor started: poll=%ss, query=%r, only_unread=%s, label=%r, timeout=%ss",
                 POLL_SECONDS, _build_query(), ONLY_UNREAD, LABEL_NAME, ANALYZE_TIMEOUT)

        if INITIAL_FULL_SCAN:
            _initial_full_scan(service, processed, label_processed_id, dblog)

        while not stop_event.is_set():
            try:
                res = service.users().messages().list(
                    userId="me", q=_build_query(), maxResults=MAX_RESULTS
                ).execute()
                msgs = res.get("messages", []) or []

                for m in msgs:
                    mid = m["id"]
                    if mid in processed: continue

                    full = service.users().messages().get(userId="me", id=mid, format="full").execute()
                    headers = full.get("payload", {}).get("headers", [])
                    sender  = _extract_field(headers, "From")
                    subject = _extract_field(headers, "Subject")
                    snippet = full.get("snippet", "")
                    links   = _extract_links(full.get("payload", {}))

                    body = {
                        "message_id": mid,
                        "sender": sender or "",
                        "subject": subject or "(no subject)",
                        "links": links,
                        "content": snippet or ""
                    }
                    out = _post_analyze(body) or {}
                    log.info("Analyzed %s -> score=%s level=%s alert=%s",
                             mid, out.get("risk_score"), out.get("risk_level"),
                             (out.get("alert") or {}).get("sent"))

                    try:
                        if APPLY_SCORE_LABEL and out.get("risk_score") is not None:
                            _apply_score_label(
                                service,
                                mid,
                                float(out["risk_score"]),
                                SCORE_LABEL_PREFIX,
                                full.get("labelIds", [])
                            )
                    except Exception:
                        pass

                    processed.add(mid)
                    _mark_processed(service, mid, label_processed_id)

                    if dblog:
                        try:
                            dblog.log(
                                message_id=mid,
                                sender=sender or "",
                                subject=subject or "",
                                score=int(out.get("risk_score") or 0),
                                level=out.get("risk_level") or "",
                                alert=out.get("alert") or {},
                                features=out.get("features") or {},
                                reasons=None
                            )
                        except Exception as e:
                            log.warning("DB log failed for %s: %s", mid, e)

                stop_event.wait(POLL_SECONDS)

            except Exception as e:
                log.error("Monitor loop error: %s", e)
                stop_event.wait(POLL_SECONDS)

    except Exception as e:
        log.exception("Gmail monitor could not start: %s", e)
