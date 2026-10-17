"""Read-only, loopback-only dashboard for decoy/lab metadata."""
import csv
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, abort, request, render_template_string

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
LOGS = {"Public decoy": BASE / "web_events.csv", "Private SQL lab": BASE / "lab_events.csv"}

@app.before_request
def loopback_only():
    if request.remote_addr not in ("127.0.0.1", "::1"): abort(403)

def read_rows(path, source, limit=150):
    rows = []
    if not path.exists(): return rows
    try:
        with path.open("r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                row["log_source"] = source
                rows.append(row)
    except (OSError, csv.Error, UnicodeError): return []
    return rows[-limit:]

PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShadowNet | Local Dashboard</title><style>body{margin:0;background:#0b1020;color:#e5e7eb;font:15px/1.5 system-ui,sans-serif}main{max-width:1200px;margin:32px auto;padding:0 16px}.muted{color:#aab5ce}.stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.card{background:#141d33;border:1px solid #303b59;border-radius:12px;padding:18px}table{width:100%;border-collapse:collapse;background:#141d33}th,td{text-align:left;padding:10px;border-bottom:1px solid #303b59;overflow-wrap:anywhere}th{color:#c7d2fe}.wrap{overflow-x:auto}.notice{padding:12px;border-left:3px solid #fbbf24;background:#2b2519;margin:16px 0}@media(max-width:650px){.stats{grid-template-columns:1fr}td,th{padding:7px}}</style></head><body><main><p class="muted">SHADOWNET / PRIVATE LOCAL VIEW</p><h1>Event dashboard</h1><p class="notice"><b>Local only:</b> this dashboard is bound to 127.0.0.1. Never expose it through a tunnel.</p><div class="stats"><div class="card"><p class="muted">Public decoy events shown</p><h2>{{ decoy_count }}</h2></div><div class="card"><p class="muted">Private lab events shown</p><h2>{{ lab_count }}</h2></div></div><p class="muted">Refreshed {{ refreshed }} · Up to 150 newest metadata events. Refresh to update.</p><div class="wrap"><table><thead><tr><th>Timestamp</th><th>Source</th><th>IP</th><th>Event</th><th>Method / Mode</th><th>Route / Outcome</th><th>Status / Flag</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{r.get('timestamp','')}}</td><td>{{r.get('log_source','')}}</td><td>{{r.get('source_ip','')}}</td><td>{{r.get('event_type','')}}</td><td>{{r.get('method',r.get('mode',''))}}</td><td>{{r.get('route',r.get('outcome',''))}}</td><td>{{r.get('status_code',r.get('suspicious_pattern',''))}}</td></tr>{% else %}<tr><td colspan="7">No events yet. Visit the decoy or run a local lab test, then refresh.</td></tr>{% endfor %}</tbody></table></div></main></body></html>'''

@app.get("/")
def index():
    rows = []
    for source, path in LOGS.items(): rows.extend(read_rows(path, source))
    rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    rows = rows[:150]
    return render_template_string(PAGE, rows=rows,
        decoy_count=sum(r["log_source"] == "Public decoy" for r in rows),
        lab_count=sum(r["log_source"] == "Private SQL lab" for r in rows),
        refreshed=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

if __name__ == "__main__": app.run(host="127.0.0.1", port=5051, debug=False)
