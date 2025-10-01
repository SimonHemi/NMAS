#test_detection.py
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

import os, sqlite3, sys
from datetime import datetime, timedelta
from detect.run_detection import detect_failed_login_bursts, detect_port_scans

#exe path

def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

DB = "events_test.db"

def setup_module(_):
    if os.path.exists(DB): os.remove(DB)
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            message TEXT,
            username TEXT,
            port TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, type TEXT, source TEXT, username TEXT,
            window_start TEXT, window_end TEXT, count INTEGER, details TEXT
        )
    """)
    conn.close()

def test_failed_login_detection():
    conn = sqlite3.connect(DB)
    now = datetime.utcnow()
    iso = lambda dt: dt.isoformat(timespec="seconds")

    # 5 failed logins within 3 minutes
    for i in range(5):
        conn.execute(
            "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?, ?, ?, ?, ?)",
            (iso(now - timedelta(seconds=100-i*10)), "1.2.3.4", "Failed password for admin", "admin", None)
        )
    conn.commit()

    alerts = detect_failed_login_bursts(conn, now)
    conn.close()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "FAILED_LOGIN_BURST"
    assert alerts[0]["source"] == "1.2.3.4"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["count"] >= 5

def test_port_scan_detection():
    conn = sqlite3.connect(DB)
    now = datetime.utcnow()
    iso = lambda dt: dt.isoformat(timespec="seconds")

    # 12 distinct ports within 60s
    for p in range(1000, 1012):
        conn.execute(
            "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?, ?, ?, ?, ?)",
            (iso(now - timedelta(seconds=30)), "5.6.7.8", f"port {p}", None, str(p))
        )
    conn.commit()

    alerts = detect_port_scans(conn, now)
    conn.close()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "PORT_SCAN"
    assert alerts[0]["source"] == "5.6.7.8"
    assert alerts[0]["count"] >= 12
