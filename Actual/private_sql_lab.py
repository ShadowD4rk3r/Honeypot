"""Loopback-only SQL teaching lab; synthetic SQLite data only."""
import csv, re, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, abort, request, render_template_string

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DB = BASE / "shadownet_lab.db"
LOG = BASE / "lab_events.csv"

@app.before_request
def loopback_only():
    if request.remote_addr not in ("127.0.0.1", "::1"): abort(403)

def connect():
    c = sqlite3.connect(DB, timeout=3); c.row_factory = sqlite3.Row; return c

def initialize_db():
    with connect() as c:
        c.execute("CREATE TABLE IF NOT EXISTS demo_users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, demo_password TEXT NOT NULL, display_name TEXT NOT NULL)")
        if c.execute("SELECT COUNT(*) FROM demo_users").fetchone()[0] == 0:
            c.executemany("INSERT INTO demo_users(username,demo_password,display_name) VALUES(?,?,?)", [("alice_demo","northstar-demo-123","Alice Example"),("bob_demo","training-only-456","Bob Example"),("guest_demo","not-a-real-password","Guest Example")])

def suspicious(value):
    patterns = [r"(--|/\*|\*/|;)", r"\bOR\b\s+['\"0-9]", r"\bUNION\b\s+\bSELECT\b", r"\b(DROP|ALTER|DELETE|UPDATE|INSERT)\b"]
    return bool(value) and any(re.search(p, value, re.I) for p in patterns)

def log_event(mode, outcome, flag):
    fields = ["timestamp","source_ip","event_type","mode","outcome","suspicious_pattern"]
    new = not LOG.exists() or LOG.stat().st_size == 0
    with LOG.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new: w.writerow(fields)
        w.writerow([datetime.now(timezone.utc).isoformat(), request.remote_addr or "unknown", "sql_lab_attempt", mode, outcome, int(flag)])

PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShadowNet | Private SQL Lab</title><style>body{margin:0;background:#0b1020;color:#e5e7eb;font:16px/1.6 system-ui,sans-serif}main{max-width:900px;margin:36px auto;padding:0 18px}.panel{background:#141d33;border:1px solid #303b59;border-radius:14px;padding:22px;margin:18px 0}label{display:block;margin-top:10px}input{width:100%;padding:10px;border-radius:7px;border:1px solid #3b4764;background:#0c1428;color:#fff;box-sizing:border-box}button{padding:11px 14px;border:0;border-radius:7px;background:#818cf8;font-weight:700;margin:12px 8px 0 0;cursor:pointer}.notice{padding:12px;border-left:3px solid #fbbf24;background:#2b2519}.muted{color:#aab5ce}.result{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1428;padding:12px;border-radius:8px}</style></head><body><main><p class="muted">SHADOWNET / LOCAL TRAINING ONLY</p><h1>SQL authentication lab</h1><p class="notice"><b>Private lab only.</b> Use synthetic inputs only. The database contains fictional records; never enter real passwords or personal data.</p><div class="panel"><h2>Test authentication</h2><form method="post" action="/test"><label for="username">Synthetic username</label><input id="username" name="username" maxlength="120" value="alice_demo" autocomplete="off"><label for="password">Synthetic demo password</label><input id="password" name="password" maxlength="120" value="northstar-demo-123" autocomplete="off"><p><button name="mode" value="secure">Run secure parameterized query</button><button name="mode" value="vulnerable">Run vulnerable SELECT demonstration</button></p></form><p class="muted">Vulnerable mode is an intentionally unsafe comparison limited to one SELECT against this synthetic database. Keep this service local.</p></div>{% if result %}<div class="panel"><h2>Result</h2><div class="result">{{ result }}</div><p><b>Mode:</b> {{ mode }} · <b>Suspicious-pattern flag:</b> {{ suspicious }}</p></div>{% endif %}<div class="panel"><h2>Learning points</h2><ul><li>Parameterized queries separate input from SQL syntax.</li><li>The vulnerable example is for local education only.</li><li>Logs never store submitted values or full SQL.</li></ul><a href="/">Reset lab</a></div></main></body></html>'''

@app.get("/")
def home(): return render_template_string(PAGE, result=None, mode=None, suspicious=None)

@app.post("/test")
def test():
    username = request.form.get("username", "")[:120]
    password = request.form.get("password", "")[:120]
    mode = request.form.get("mode", "secure")
    if mode not in ("secure", "vulnerable"): mode = "secure"
    flag = suspicious(username) or suspicious(password)
    outcome, result = "error", ""
    try:
        with connect() as c:
            if mode == "secure":
                row = c.execute("SELECT username,display_name FROM demo_users WHERE username=? AND demo_password=?", (username,password)).fetchone()
            else:
                # Intentionally vulnerable SELECT against fictional rows only. execute() rejects stacked statements.
                sql = "SELECT username,display_name FROM demo_users WHERE username='" + username + "' AND demo_password='" + password + "'"
                row = c.execute(sql).fetchone()
        if row: outcome, result = "match", "Demo authentication matched synthetic user: " + row["display_name"]
        else: outcome, result = "no_match", "No matching synthetic account."
    except sqlite3.Error:
        outcome, result = "sql_error", "SQLite rejected the query. Detailed errors are intentionally hidden."
    log_event(mode, outcome, flag)
    return render_template_string(PAGE, result=result, mode=mode, suspicious="yes" if flag else "no")

if __name__ == "__main__":
    initialize_db()
    app.run(host="127.0.0.1", port=8081, debug=False)
