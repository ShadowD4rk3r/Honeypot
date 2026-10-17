from __future__ import annotations

import csv
import os
import socket
import subprocess
import sys
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
HONEYPOT_SCRIPT = BASE_DIR / "honeypot.py"
CSV_PATH = BASE_DIR / "events.csv"
ANALYZER_EXE = BASE_DIR / "analyzer.exe"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# This dashboard is deliberately local-only.
HOST = "127.0.0.1"
DEFAULT_HONEYPOT_PORT = 9000
MIN_PORT, MAX_PORT = 1024, 65535

process_lock = threading.Lock()
honeypot_process: subprocess.Popen | None = None
honeypot_port = DEFAULT_HONEYPOT_PORT


def process_running() -> bool:
    global honeypot_process
    with process_lock:
        return honeypot_process is not None and honeypot_process.poll() is None


def read_events(limit: int = 500) -> list[dict]:
    """Read the CSV written by the honeypot without changing it."""
    if not CSV_PATH.exists():
        return []
    rows: list[dict] = []
    try:
        with CSV_PATH.open("r", newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Accept the expected timestamp, ip, event, bytes columns.
                timestamp = row.get("timestamp", row.get("time", ""))
                ip = row.get("ip", row.get("source_ip", ""))
                event = row.get("event", row.get("type", "event"))
                byte_count = row.get("bytes", row.get("byte_count", "0"))
                try:
                    byte_count = int(byte_count or 0)
                except (TypeError, ValueError):
                    byte_count = 0
                rows.append({
                    "timestamp": timestamp or "Unknown",
                    "ip": ip or "Unknown",
                    "event": event or "event",
                    "bytes": byte_count,
                })
    except (OSError, csv.Error):
        return []
    return rows[-limit:]


def get_stats() -> dict:
    events = read_events(limit=100000)
    connections = [e for e in events if e["event"].strip().lower() == "connection"]
    ips = Counter(e["ip"] for e in connections if e["ip"] and e["ip"] != "Unknown")
    event_types = Counter(e["event"] for e in events)
    # Group event rows by hour using their timestamp where it can be parsed.
    hourly = Counter()
    for event in events:
        parsed = None
        stamp = event["timestamp"]
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(stamp, fmt)
                break
            except (ValueError, TypeError):
                continue
        if parsed:
            hourly[parsed.strftime("%H:00")] += 1
    return {
        "total_events": len(events),
        "total_connections": len(connections),
        "unique_ips": len(ips),
        "event_types": dict(event_types),
        "top_ips": [{"ip": ip, "count": count} for ip, count in ips.most_common(8)],
        "hourly": [{"hour": hour, "count": count} for hour, count in sorted(hourly.items())[-12:]],
    }


@app.get("/")
def index():
    return render_template("index.html", host=HOST, default_port=honeypot_port)


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify({
        "running": process_running(),
        "host": HOST,
        "port": honeypot_port,
        "events": list(reversed(read_events(100))),
        "stats": get_stats(),
    })


@app.post("/api/start")
def api_start():
    global honeypot_process
    if not HONEYPOT_SCRIPT.exists():
        return jsonify({"ok": False, "error": "honeypot.py was not found beside app.py."}), 404
    if process_running():
        return jsonify({"ok": True, "message": "Honeypot is already running."})
    # Existing honeypot.py must read HONEYPOT_HOST/HONEYPOT_PORT for this
    # configuration to take effect. See README_SETUP.md.
    env = os.environ.copy()
    env["HONEYPOT_HOST"] = HOST
    env["HONEYPOT_PORT"] = str(honeypot_port)
    try:
        with process_lock:
            if honeypot_process is not None and honeypot_process.poll() is None:
                return jsonify({"ok": True, "message": "Honeypot is already running."})
            honeypot_process = subprocess.Popen(
                [sys.executable, str(HONEYPOT_SCRIPT)],
                cwd=str(BASE_DIR),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        return jsonify({"ok": True, "message": f"Started local honeypot on {HOST}:{honeypot_port}."})
    except OSError as exc:
        return jsonify({"ok": False, "error": f"Could not start honeypot: {exc}"}), 500


@app.post("/api/stop")
def api_stop():
    global honeypot_process
    with process_lock:
        proc = honeypot_process
        if proc is None or proc.poll() is not None:
            return jsonify({"ok": True, "message": "Honeypot is not running under this dashboard."})
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        honeypot_process = None
    return jsonify({"ok": True, "message": "Honeypot stopped."})


@app.post("/api/config")
def api_config():
    global honeypot_port
    data = request.get_json(silent=True) or {}
    try:
        port = int(data.get("port", DEFAULT_HONEYPOT_PORT))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Port must be a number."}), 400
    if not MIN_PORT <= port <= MAX_PORT:
        return jsonify({"ok": False, "error": f"Choose a port from {MIN_PORT} to {MAX_PORT}."}), 400
    if process_running():
        return jsonify({"ok": False, "error": "Stop the honeypot before changing its port."}), 409
    honeypot_port = port
    return jsonify({"ok": True, "message": f"Port set to {port}. Start the honeypot to apply it."})


@app.post("/api/analyze")
def api_analyze():
    if not ANALYZER_EXE.exists():
        return jsonify({"ok": False, "error": "analyzer.exe not found. Compile analyzer.cpp first."}), 404
    try:
        result = subprocess.run(
            [str(ANALYZER_EXE)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )
        output = result.stdout + (("\n" + result.stderr) if result.stderr else "")
        return jsonify({
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "output": output.strip() or "(Analyzer returned no output.)",
        })
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"ok": False, "error": f"Analyzer failed: {exc}"}), 500


if __name__ == "__main__":
    # Debug is intentionally off; never expose the development server externally.
    app.run(host=HOST, port=5000, debug=False)
