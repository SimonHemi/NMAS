# app.py
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

import sqlite3, base64, json, os, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from flask import Flask, request, render_template, make_response, Response, jsonify

def app_root() -> Path:
    # exe dir when frozen, repo root in source
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]

APP_ROOT   = app_root()
DB_PATH    = APP_ROOT / "events.db"
CONFIG_PATH= APP_ROOT / "config.json"

# templates live next to this file
TEMPLATES = Path(__file__).resolve().parent / "templates"
app = Flask(__name__, template_folder=str(TEMPLATES))

# -------- Config loader ----------
def load_config():
    cfg = {
        "auth": {"username": "admin", "password": "admin"},
        "dashboard": {"enable_simulate": True}
    }
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if "dashboard" in data and "auth" in data["dashboard"]:
                cfg["auth"] = data["dashboard"]["auth"]
            elif "auth" in data:
                cfg["auth"] = data["auth"]
            if "dashboard" in data and "enable_simulate" in data["dashboard"]:
                cfg["dashboard"]["enable_simulate"] = data["dashboard"]["enable_simulate"]
        except Exception:
            pass
    return cfg

CONFIG = load_config()

# -------- DB ----------
def ensure_alerts(conn):
    """Make sure alerts table + index exist."""
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

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    ensure_alerts(conn)   # ✅ ensure alerts table exists
    return conn

def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _ins(conn, ts, src, msg, user=None, port=None):
    conn.execute(
        "INSERT INTO logs (timestamp, source, message, username, port) VALUES (?,?,?,?,?)",
        (ts, src, msg, user, port)
    )

# -------- Basic Auth ----------
def check_auth(auth_header: str) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    try:
        userpass = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
        u, p = userpass.split(":", 1)
    except Exception:
        return False
    return (u == CONFIG["auth"]["username"] and p == CONFIG["auth"]["password"])

def require_auth():
    resp = make_response("Authentication required", 401)
    resp.headers["WWW-Authenticate"] = 'Basic realm="NMAS Dashboard"'
    return resp

@app.before_request
def _auth_gate():
    if request.path in ("/healthz",):
        return
    if not check_auth(request.headers.get("Authorization", "")):
        return require_auth()

# -------- Routes ----------
@app.get("/healthz")
def healthz():
    return {"ok": True, "db": str(DB_PATH)}, 200

@app.get("/")
def index():
    # filters
    alert_type = request.args.get("type", "ALL").upper()
    hours = int(request.args.get("hours", "24") or 24)
    if hours < 1 or hours > 24*30: hours = 24
    since = datetime.utcnow() - timedelta(hours=hours)

    # paging/sort
    page = max(1, int(request.args.get("page", 1)))
    page_size = 50
    offset = (page-1) * page_size
    sort = request.args.get("sort", "ts")
    dir_ = request.args.get("dir", "desc").lower()
    direction = "DESC" if dir_ == "desc" else "ASC"
    ALLOWED_SORT = {"id","ts","type","source","count"}
    if sort not in ALLOWED_SORT: sort = "ts"

    params = [since.isoformat(timespec="seconds")]
    where = "WHERE ts >= ?"
    if alert_type in ("FAILED_LOGIN_BURST", "PORT_SCAN"):
        where += " AND type = ?"
        params.append(alert_type)

    q = f"""
      SELECT id, ts, type, source, IFNULL(username,'') AS username,
             window_start, window_end, count, details
      FROM alerts
      {where}
      ORDER BY {sort} {direction}
      LIMIT ? OFFSET ?
    """
    params += [page_size+1, offset]

    with get_db() as conn:
        rows = conn.execute(q, params).fetchall()
        has_more = len(rows) > page_size
        rows = rows[:page_size]

        # chart buckets
        buckets = {}
        for r in rows:
            t = r["ts"][:13] + ":00:00"
            buckets[t] = buckets.get(t, 0) + 1
        series = sorted(buckets.items())

    return render_template(
        "index.html",
        rows=rows,
        selected_type=alert_type,
        hours=hours,
        series=series,
        page=page,
        page_size=page_size,
        has_more=has_more,
        sort=sort,
        dir=dir_
    )

@app.get("/export.csv")
def export_csv():
    q_type = request.args.get("type","ALL")
    hours = int(request.args.get("hours",24))
    sort = request.args.get("sort","ts")
    dir_ = request.args.get("dir","desc").lower()
    direction = "DESC" if dir_=="desc" else "ASC"
    ALLOWED_SORT = {"id","ts","type","source","count"}
    if sort not in ALLOWED_SORT: sort="ts"

    since = datetime.utcnow() - timedelta(hours=hours)
    params = [since.isoformat(timespec="seconds")]
    where = "WHERE ts >= ?"
    if q_type in ("FAILED_LOGIN_BURST","PORT_SCAN"):
        where += " AND type=?"; params.append(q_type)

    sql = f"""
      SELECT id, ts, type, source, username, count, window_start, window_end, details
      FROM alerts
      {where}
      ORDER BY {sort} {direction}
    """
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()

    def gen():
        yield "id,ts,type,source,username,count,window_start,window_end,details\r\n"
        for r in rows:
            vals = [str(r[k] or "") for k in r.keys()]
            yield ",".join(v.replace("\n"," ").replace(",",";") for v in vals) + "\r\n"

    return Response(gen(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=alerts_export.csv"})

# -------- Simulate endpoints ----------
@app.post("/api/simulate/failed-login")
def simulate_failed_login():
    if not CONFIG.get("dashboard",{}).get("enable_simulate",True):
        return jsonify({"ok":False,"error":"disabled"}),403
    p = request.get_json(force=True) or {}
    src = (p.get("source") or "10.0.0.50")[:64]
    user = (p.get("username") or "admin")[:64]
    count = max(1, min(int(p.get("count",6)),50))
    ts = utcnow()
    with get_db() as conn:
        for _ in range(count):
            _ins(conn, ts, src, f"Failed password for {user}", user, None)
        conn.commit()
    return jsonify({"ok":True,"inserted":count})

@app.post("/api/simulate/port-scan")
def simulate_port_scan():
    if not CONFIG.get("dashboard",{}).get("enable_simulate",True):
        return jsonify({"ok":False,"error":"disabled"}),403
    p = request.get_json(force=True) or {}
    src = (p.get("source") or "10.0.0.99")[:64]
    start = max(1,min(int(p.get("startPort",20)),65535))
    n = max(1,min(int(p.get("n",20)),60))
    ts = utcnow()
    with get_db() as conn:
        for i in range(n):
            port = str(start+i)
            _ins(conn, ts, src, f"Connection attempt port {port}", None, port)
        conn.commit()
    return jsonify({"ok":True,"inserted":n})

@app.post("/api/detect-now")
def detect_now():
    from Capstone.detect.run_detection import main as run_detect
    run_detect()
    return jsonify({"ok":True})

# -------- Entrypoint ----------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)