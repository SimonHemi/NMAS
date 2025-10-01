# syslog_listener.py
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

import socket, sqlite3, sys, re, json
from datetime import datetime
from pathlib import Path

#exe path

def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

# ------------ Paths ------------
APP_ROOT = app_root()
DB_PATH = APP_ROOT / "events.db"
CONFIG_PATH = APP_ROOT / "config.json"


# ------------ Config helpers ------------
def load_config():
    default = {
        "listener": {"bind_host": "0.0.0.0", "port": 5514}
    }
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        # shallow merge
        listener = {**default["listener"], **data.get("listener", {})}
        return {"listener": listener}
    except Exception as e:
        print(f"[CONFIG] Using defaults ({e})")
        return default

def get_primary_ip():
    """Discover the host's primary LAN IP (no traffic actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

# ------------ DB Setup & Migration ------------
def ensure_db():
    print(f"[INFO] Python: {sys.executable}")
    print(f"[INFO] DB path: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            message TEXT
        )
    """)
    conn.commit()
    # add columns if missing
    cur.execute("PRAGMA table_info(logs)")
    cols = {row[1] for row in cur.fetchall()}
    if "username" not in cols:
        cur.execute("ALTER TABLE logs ADD COLUMN username TEXT")
    if "port" not in cols:
        cur.execute("ALTER TABLE logs ADD COLUMN port TEXT")
    conn.commit()
    conn.close()
    print("[INFO] Table 'logs' ready (id,timestamp,source,message,username,port).")

# ------------ Regex Parsers ------------
FAILED_LOGIN = re.compile(r"Failed password for (?:invalid user )?([A-Za-z0-9_\-.$]+)", re.IGNORECASE)
PORT_GENERIC  = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)
PORT_FW       = re.compile(r"\bDPT=(\d{1,5})\b")

def parse_fields(msg: str):
    username, port = None, None
    m1 = FAILED_LOGIN.search(msg)
    if m1: username = m1.group(1)
    m2 = PORT_GENERIC.search(msg) or PORT_FW.search(msg)
    if m2: port = m2.group(1)
    return username, port

# ------------ Listener ------------
def main():
    ensure_db()

    cfg = load_config()
    bind_host = cfg["listener"]["bind_host"]
    port = int(cfg["listener"]["port"])
    primary_ip = get_primary_ip()

    print(f"[LISTENER] Primary host IP (tell devices to send here): {primary_ip}:{port}")
    print(f"[LISTENER] Binding on {bind_host}:{port} (set in config.json: listener.bind_host/port)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_host, port))
    sock.settimeout(1.0)  # allows Ctrl+C to break the loop

    print("[INFO] Listening for syslog messages... (Ctrl+C to stop)")
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            msg = data.decode(errors="replace")
            ts = datetime.now().isoformat(timespec="seconds")
            username, dport = parse_fields(msg)

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?, ?, ?, ?, ?)",
                    (ts, addr[0], msg, username, dport)
                )
            print(f"[INSERT] {ts} {addr[0]} user={username} port={dport} :: {msg}")
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        sock.close()
        print("[INFO] Socket closed.")

if __name__ == "__main__":
    main()

