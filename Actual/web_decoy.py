import csv
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from flask import Flask, make_response, render_template_string, request

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
LOG_FILE = BASE / "web_events.csv"
log_lock = Lock()

PAGE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Research | Portal</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0b1020;color:#e5e7eb;font:16px/1.6 system-ui,sans-serif}header{padding:22px 8%;border-bottom:1px solid #28324d;background:#11182b}header strong{color:#a5b4fc;font-size:1.2rem}main{width:min(980px,90%);margin:64px auto;display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center}.panel{background:#141d33;padding:28px;border-radius:16px;border:1px solid #303b59}h1{font-size:clamp(2rem,5vw,3.2rem);line-height:1.1}.muted{color:#aab5ce}.notice{border-left:3px solid #818cf8;padding:10px 14px;background:#1b2641;font-size:.9rem}label{display:block;margin:14px 0 5px}input{width:100%;padding:12px;border-radius:8px;border:1px solid #3b4764;background:#0c1428;color:#fff;font:inherit}button{width:100%;padding:13px;border:0;border-radius:8px;background:#818cf8;color:#11152a;font-weight:700;cursor:pointer;margin-top:16px;font:inherit}.status{margin-top:14px;min-height:1.5em;color:#c7d2fe}@media(max-width:700px){main{grid-template-columns:1fr;margin:35px auto;gap:22px}}</style></head><body>
<header><strong>NORTHSTAR / RESEARCH PORTAL</strong></header><main><section><p class="muted">NORTHSTAR RESEARCH SYSTEMS</p><h1>Research securely. Build what's next.</h1><p class="muted">A fictional company portal for the ShadowNet security-monitoring demonstration.</p><p class="notice"><b>Research demo:</b> Do not enter real credentials or sensitive information. These fields are visual only. Their contents stay in your browser and are never sent to this server.</p></section>
<section class="panel"><h2>Portal access</h2><p class="muted">Use fake test values to see the simulated response. No account is created and no authentication occurs.</p><form id="login-form" autocomplete="off"><label for="demo-user">Demo username</label><input id="demo-user" type="text" placeholder="example: test-researcher" maxlength="64"><label for="demo-pass">Demo password</label><input id="demo-pass" type="password" placeholder="Fake value only" maxlength="64"><button type="submit">Simulate sign-in</button></form><p id="status" class="status" role="status" aria-live="polite"></p><small>Northstar Research · Fictional demo environment</small></section></main>
<script>/* Never read input values or serialize the form. Only an empty POST is sent. */document.getElementById('login-form').addEventListener('submit',async function(e){e.preventDefault();const s=document.getElementById('status');s.textContent='Recording simulation…';try{const r=await fetch('/simulate-signin',{method:'POST',headers:{'Content-Type':'text/plain'},body:''});s.textContent=r.ok?'Simulation recorded. Field contents were not sent or stored.':'Could not record simulation.'}catch(_){s.textContent='Connection failed. Field contents were not sent by this page.'}});</script></body></html>'''

def log_event(event_type, method, route, status):
    fields = ["timestamp", "source_ip", "event_type", "method", "route", "status_code"]
    with log_lock:
        new = not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0
        with LOG_FILE.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new: w.writerow(fields)
            w.writerow([datetime.now(timezone.utc).isoformat(), request.remote_addr or "unknown", event_type, method, route[:160], status])

@app.after_request
def after(response):
    log_event(getattr(request, "_event_type", "http_request"), request.method, request.path, response.status_code)
    response.headers.update({"X-Content-Type-Options":"nosniff", "X-Frame-Options":"DENY", "Referrer-Policy":"no-referrer", "Cache-Control":"no-store", "Content-Security-Policy":"default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"})
    return response

@app.get("/")
def home(): return render_template_string(PAGE)

@app.post("/simulate-signin")
def simulate_signin():
    # Do not inspect request.form, request.data, or the request body.
    request._event_type = "decoy_signin_simulation"
    return make_response("Simulation recorded", 200)

@app.errorhandler(404)
def not_found(_): return "Not found", 404

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)
