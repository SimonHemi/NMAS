# run_detection.py
# ---------------------------------------------------------------------------
# Network Monitoring & Alert System (NMAS)
# Capstone Project – Liberty University
#
# Copyright (c) 2025 Simon Peter Hemingway. All rights reserved.
#
# This code was developed as part of an academic course at Liberty University.
# It is provided for educational purposes only. Unauthorized use,
# reproduction, or distribution of this code without express written
# permission is prohibited.
# ---------------------------------------------------------------------------

import json, sys
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta
from Capstone.alerts.notifier import log_alerts, export_json, send_email, post_webhook

#exe path

def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

APP_ROOT = app_root()
DB = str(APP_ROOT / "events.db")
CONFIG_PATH = APP_ROOT / "config.json"


def load_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

# Config from your FRs
FAILED_LOGIN_THRESHOLD = 5       # >=5
FAILED_LOGIN_WINDOW_SEC = 180    # 3 min
PORTSCAN_DISTINCT_PORTS = 12     # >=12
PORTSCAN_WINDOW_SEC = 60         # 60s

def ensure_alerts(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, type TEXT, source TEXT, username TEXT,
            window_start TEXT, window_end TEXT, count INTEGER, details TEXT
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_dedupe
        ON alerts(type, source, window_start, window_end)
    """)
    conn.commit()

def iso(dt): return dt.isoformat(timespec="seconds")

def detect_failed_login_bursts(conn, now):
    win_start = now - timedelta(seconds=FAILED_LOGIN_WINDOW_SEC)

    rows = conn.execute(
        """
        SELECT source, username, COUNT(*) as cnt
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
          AND username IS NOT NULL
          AND message LIKE 'Failed password%'
        GROUP BY source, username
        HAVING cnt >= ?
        """,
        (iso(win_start), iso(now), FAILED_LOGIN_THRESHOLD)
    ).fetchall()

    alerts = []
    for source, username, cnt in rows:
        alerts.append({
            "ts": iso(now),
            "type": "FAILED_LOGIN_BURST",
            "source": source,
            "username": username,
            "window_start": iso(win_start),
            "window_end": iso(now),
            "count": int(cnt),
            "details": f"{cnt} failed logins for user={username} within {FAILED_LOGIN_WINDOW_SEC}s"
        })
    return alerts

def detect_port_scans(conn, now):
    win_start = now - timedelta(seconds=PORTSCAN_WINDOW_SEC)
    rows = conn.execute(
        """
        SELECT source, COUNT(DISTINCT port) as distinct_ports
        FROM logs
        WHERE timestamp BETWEEN ? AND ?
          AND port IS NOT NULL
        GROUP BY source
        HAVING distinct_ports >= ?
        """,
        (iso(win_start), iso(now), PORTSCAN_DISTINCT_PORTS)
    ).fetchall()

    alerts = []
    for source, distinct_ports in rows:
        alerts.append({
            "ts": iso(now),
            "type": "PORT_SCAN",
            "source": source,
            "username": None,
            "window_start": iso(win_start),
            "window_end": iso(now),
            "count": int(distinct_ports),
            "details": f"{distinct_ports} distinct destination ports within {PORTSCAN_WINDOW_SEC}s"
        })
    return alerts

def upsert_alerts(conn, found):
    if not found: return 0
    inserted = 0
    for a in found:
        # Deduplicate by unique index (type, source, window_start, window_end)
        try:
            conn.execute(
                """
                INSERT INTO alerts (ts, type, source, username, window_start, window_end, count, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (a["ts"], a["type"], a["source"], a["username"], a["window_start"], a["window_end"], a["count"], a["details"])
            )
            inserted += 1
        except sqlite3.IntegrityError:
            # already recorded; ignore
            pass
    conn.commit()
    return inserted

def main():
    now = datetime.utcnow()
    conn = sqlite3.connect(DB)

    fl = detect_failed_login_bursts(conn, now)
    ps = detect_port_scans(conn, now)

    new_alerts = fl + ps
    added = upsert_alerts(conn, new_alerts)

    config = load_config()

    # Logging to file/console/JSON
    if config["logging"]["enabled"]:
        log_alerts(new_alerts)
        export_json(new_alerts)

    # Email
    if config["email"]["enabled"]:
        send_email(
            new_alerts,
            host=config["email"]["host"],
            port=config["email"]["port"],
            sender=config["email"]["sender"],
            to=config["email"]["to"],
        )

    # Webhook
    if config["webhook"]["enabled"] and config["webhook"]["url"]:
        post_webhook(new_alerts, config["webhook"]["url"])

    print(f"Detection run @ {now.isoformat(timespec='seconds')} -> {added} new alerts")
    conn.close()

if __name__ == "__main__":
    main()