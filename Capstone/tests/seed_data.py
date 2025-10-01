# seed_data.py
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

import sqlite3, sys
from datetime import datetime, timedelta
from pathlib import Path

#exe path

def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

# Resolve DB path to project root
DB = (Path(__file__).resolve().parents[1] / "events.db")

def iso(dt): 
    return dt.isoformat(timespec="seconds")

# Ensure table exists 
conn = sqlite3.connect(DB)
conn.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source TEXT,
    message TEXT,
    username TEXT,
    port TEXT
)
""")

now = datetime.utcnow()

# 5 failed logins in < 3 min from same source/user
for i in range(5):
    conn.execute(
        "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?, ?, ?, ?, ?)",
        (iso(now - timedelta(seconds=120 - i*10)), "10.0.0.50", "Failed password for admin", "admin", None)
    )

# 12 distinct ports in < 60s from same source
for p in range(20, 32):  # 12 ports
    conn.execute(
        "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?, ?, ?, ?, ?)",
        (iso(now - timedelta(seconds=30)), "10.0.0.99", f"Connection attempt port {p}", None, str(p))
    )

conn.commit()
conn.close()
print(f"Seeded sample data into: {DB}")
