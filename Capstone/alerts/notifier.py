# notifier.py
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

import json, smtplib, ssl, sys
from pathlib import Path
from typing import List, Dict
from email.message import EmailMessage
import urllib.request

ALERT_LOG = (Path(__file__).resolve().parents[1] / "alerts.log")
ALERT_JSON = (Path(__file__).resolve().parents[1] / "alerts.json")

#exe path
def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

# ---- Console & file ----
def log_alerts(alerts: List[Dict]):
    if not alerts: return 0
    lines = []
    for a in alerts:
        line = f"{a['ts']} | {a['type']} | src={a['source']} | user={a.get('username')} | cnt={a['count']} | {a['details']}"
        print(line)
        lines.append(line)
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        for l in lines: f.write(l + "\n")
    return len(lines)

# ---- JSON export (append to an array) ----
def export_json(alerts: List[Dict]):
    if not alerts: return
    existing = []
    if ALERT_JSON.exists():
        try:
            existing = json.loads(ALERT_JSON.read_text(encoding="utf-8"))
        except Exception:
            existing = []
    existing.extend(alerts)
    ALERT_JSON.write_text(json.dumps(existing, indent=2), encoding="utf-8")

# ---- Email (optional) ----
def send_email(alerts: List[Dict], *, host="localhost", port=1025,
               sender="noreply@nmas.local", to=("admin@nmas.local",)):
    if not alerts: return 0
    subject = f"[NMAS] {len(alerts)} new alert(s)"
    body = "\n".join(
        f"{a['ts']} | {a['type']} | src={a['source']} | user={a.get('username')} | cnt={a['count']} | {a['details']}"
        for a in alerts
    )
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port) as smtp:
        smtp.send_message(msg)
    return len(alerts)

# ---- Webhook (optional: Slack/Discord/etc.) ----
def post_webhook(alerts: List[Dict], url: str):
    if not alerts or not url: return 0
    payload = {
        "text": "\n".join(
            f"{a['ts']} | {a['type']} | src={a['source']} | user={a.get('username')} | cnt={a['count']} | {a['details']}"
            for a in alerts
        )
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as _:
        pass
    return len(alerts)
