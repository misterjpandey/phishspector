# db_logger.py
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS phish_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT,
    sender TEXT,
    subject TEXT,
    score INTEGER,
    level TEXT,
    alert_sent INTEGER,
    status TEXT,
    reasons TEXT,
    features TEXT,
    timestamp TEXT
);
"""

class DBLogger:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute(SCHEMA)
        self.conn.commit()

    def log(self,
            message_id: str,
            sender: str,
            subject: str,
            score: int,
            level: str,
            alert: Dict[str, Any],
            features: Dict[str, Any],
            reasons: Optional[str] = None):
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO phish_logs(message_id,sender,subject,score,level,alert_sent,status,reasons,features,timestamp)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                message_id,
                sender,
                subject,
                int(score),
                level,
                1 if (alert or {}).get("sent") else 0,
                (alert or {}).get("status") or "",
                reasons or "",
                str(features or {}),
                ts
            )
        )
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
