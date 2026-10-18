
from __future__ import annotations

import csv
import os
import subprocess
import sys
import threading
import time
from functools import wraps
from flask import session
from werkzeug.security import check_password_hash
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
ACTUAL_DIR = BASE_DIR / "Actual"

HONEYPOT_SCRIPT = BASE_DIR / "honeypot.py"
ANALYZER_EXE = BASE_DIR / "analyzer.exe"
PACKET_ANALYZER_EXE = BASE_DIR / "packet_analyzer.exe"
PCAP_PATH = BASE_DIR / "lab_capture.pcap"

# Each component writes to its own CSV. Do not merge the files on disk.
LOG_FILES = {
    "TCP Honeypot": BASE_DIR / "events.csv",
    "Web Decoy": ACTUAL_DIR / "web_events.csv",
    "SQL Lab": ACTUAL_DIR / "lab_events.csv",
}

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

app.secret_key = os.environ.get("SHADOWNET_SESSION_KEY")

PASSWORD_HASH = os.environ.get("SHADOWNET_PASSWORD_HASH", "")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

auth_lock = threading.Lock()
failed_attempts = 0
locked_until = 0.0


def require_analyzer_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("analyzer_authenticated"):
            return jsonify({
                "ok": False,
                "error": "Authenticate before using packet analysis."
            }), 401
        return fn(*args, **kwargs)
    return wrapper


@app.post("/api/analyze-packets")
@require_analyzer_auth
def api_analyze_packets():
    if not PACKET_ANALYZER_EXE.exists():
        return jsonify({
            "ok": False,
            "error": "packet_analyzer.exe was not found. Compile packet_analyzer.cpp first."
        }), 404

    if not PCAP_PATH.exists():
        return jsonify({
            "ok": False,
            "error": "lab_capture.pcap was not found in the project root."
        }), 404

    try:
        result = subprocess.run(
            [str(PACKET_ANALYZER_EXE), str(PCAP_PATH)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            encoding="utf-8",
            errors="replace",
        )

        output = result.stdout + (
            ("\n" + result.stderr) if result.stderr else ""
        )

        return jsonify({
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "output": output.strip() or "(No analyzer output.)",
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "ok": False,
            "error": "Packet analysis exceeded the 30-second limit."
        }), 504
    except OSError as exc:
        return jsonify({
            "ok": False,
            "error": f"Could not run packet analyzer: {exc}"
        }), 500
        
        
@app.post("/api/auth/login")
def analyzer_login():
    global failed_attempts, locked_until

    if not app.secret_key or not PASSWORD_HASH:
        return jsonify({
            "ok": False,
            "error": "Authentication is not configured. Set the required environment variables."
        }), 503

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str) or len(password) > 1024:
        password = ""

    with auth_lock:
        now = time.monotonic()

        if now < locked_until:
            remaining = max(1, int(locked_until - now))
            return jsonify({
                "ok": False,
                "error": f"Too many failed attempts. Try again in {remaining} seconds."
            }), 429

        if check_password_hash(PASSWORD_HASH, password):
            failed_attempts = 0
            locked_until = 0.0
            session.clear()
            session["analyzer_authenticated"] = True
            session.permanent = True
            app.permanent_session_lifetime = __import__("datetime").timedelta(minutes=15)
            return jsonify({"ok": True, "message": "Analyzer access granted."})

        failed_attempts += 1

        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            failed_attempts = 0
            locked_until = time.monotonic() + LOCKOUT_SECONDS
            return jsonify({
                "ok": False,
                "error": "Too many failed attempts. Access is locked for 5 minutes."
            }), 429

    return jsonify({
        "ok": False,
        "error": "Invalid password."
    }), 401


@app.post("/api/auth/logout")
def analyzer_logout():
    session.pop("analyzer_authenticated", None)
    return jsonify({"ok": True, "message": "Logged out."})

# The main administrative dashboard must remain local-only.
HOST = "127.0.0.1"
DEFAULT_HONEYPOT_PORT = 9000
MIN_PORT, MAX_PORT = 1024, 65535

process_lock = threading.Lock()
honeypot_process: subprocess.Popen | None = None
honeypot_port = DEFAULT_HONEYPOT_PORT


def process_running() -> bool:
    with process_lock:
        return (
            honeypot_process is not None
            and honeypot_process.poll() is None
        )


def first_value(row: dict, *names: str, default: str = "") -> str:
    """Return the first non-empty field found, ignoring case."""
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def read_log(path: Path, source: str, limit: int = 100000) -> list[dict]:
    """Normalize one component's CSV without modifying its contents."""
    if not path.exists():
        return []

    rows = []
    try:
        with path.open(
            "r", newline="", encoding="utf-8-sig", errors="replace"
        ) as file:
            reader = csv.DictReader(file)

            for row in reader:
                if not row:
                    continue

                timestamp = first_value(
                    row, "timestamp", "time", "created_at", "datetime",
                    default="Unknown",
                )
                ip = first_value(
                    row, "ip", "source_ip", "client_ip", "remote_ip",
                    "src_ip", "address", default="Unknown",
                )
                event = first_value(
                    row, "event", "event_type", "type", "action",
                    "event_name", default="event",
                )
                raw_bytes = first_value(
                    row, "bytes", "byte_count", "bytes_received",
                    "size", default="0",
                )

                try:
                    byte_count = int(raw_bytes)
                except (TypeError, ValueError):
                    byte_count = 0

                rows.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "event": event,
                    "bytes": byte_count,
                    "source": source,
                })

    except (OSError, csv.Error):
        # A missing or temporarily unreadable log should not crash the UI.
        return []

    return rows[-limit:]


def read_all_events(limit: int = 100000) -> list[dict]:
    events = []
    for source, path in LOG_FILES.items():
        events.extend(read_log(path, source, limit=limit))

    # Sort chronologically when timestamps use the expected text format.
    # Unparseable timestamps are kept rather than discarded.
    def sort_key(event):
        stamp = event["timestamp"]
        try:
            return (0, datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
        except (ValueError, TypeError, OverflowError):
            return (1, stamp)

    events.sort(key=sort_key)
    return events[-limit:]


def get_stats() -> dict:
    events = read_all_events()

    event_types = Counter(e["event"] for e in events)
    source_counts = Counter(e["source"] for e in events)

    # Count TCP connections separately from web and SQL events.
    connections = [
        e for e in events
        if e["source"] == "TCP Honeypot"
        and e["event"].strip().lower() == "connection"
    ]
    ips = Counter(
        e["ip"] for e in connections
        if e["ip"] and e["ip"] != "Unknown"
    )

    hourly = Counter()
    for event in events:
        stamp = event["timestamp"]
        parsed = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ):
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
        "source_counts": dict(source_counts),
        "top_ips": [
            {"ip": ip, "count": count}
            for ip, count in ips.most_common(8)
        ],
        "hourly": [
            {"hour": hour, "count": count}
            for hour, count in sorted(hourly.items())[-12:]
        ],
    }


@app.get("/")
def index():
    return render_template(
        "index.html", host=HOST, default_port=honeypot_port
    )


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify({
        "running": process_running(),
        "host": HOST,
        "port": honeypot_port,
        "events": list(reversed(read_all_events(100))),
        "stats": get_stats(),
        "sources": {
            source: {
                "available": path.exists(),
                "path": str(path.relative_to(BASE_DIR)),
            }
            for source, path in LOG_FILES.items()
        },
    })


@app.post("/api/start")
def api_start():
    global honeypot_process

    if not HONEYPOT_SCRIPT.exists():
        return jsonify({
            "ok": False,
            "error": "honeypot.py was not found beside app.py.",
        }), 404

    if process_running():
        return jsonify({
            "ok": True, "message": "Honeypot is already running."
        })

    env = os.environ.copy()
    env["HONEYPOT_HOST"] = HOST
    env["HONEYPOT_PORT"] = str(honeypot_port)

    try:
        with process_lock:
            if (
                honeypot_process is not None
                and honeypot_process.poll() is None
            ):
                return jsonify({
                    "ok": True,
                    "message": "Honeypot is already running.",
                })

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

        return jsonify({
            "ok": True,
            "message": f"Started local honeypot on {HOST}:{honeypot_port}.",
        })
    except OSError as exc:
        return jsonify({
            "ok": False, "error": f"Could not start honeypot: {exc}"
        }), 500


@app.post("/api/stop")
def api_stop():
    global honeypot_process

    with process_lock:
        proc = honeypot_process
        if proc is None or proc.poll() is not None:
            return jsonify({
                "ok": True,
                "message": "Honeypot is not running under this dashboard.",
            })

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
        return jsonify({
            "ok": False,
            "error": f"Choose a port from {MIN_PORT} to {MAX_PORT}.",
        }), 400

    if process_running():
        return jsonify({
            "ok": False,
            "error": "Stop the honeypot before changing its port.",
        }), 409

    honeypot_port = port
    return jsonify({
        "ok": True,
        "message": f"Port set to {port}. Start the honeypot to apply it.",
    })


@app.post("/api/analyze")
@require_analyzer_auth
def api_analyze():
    if not ANALYZER_EXE.exists():
        return jsonify({
            "ok": False,
            "error": "analyzer.exe not found. Compile analyzer.cpp first.",
        }), 404

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
        output = result.stdout + (
            ("\n" + result.stderr) if result.stderr else ""
        )
        return jsonify({
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "output": output.strip() or "(Analyzer returned no output.)",
        })
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({
            "ok": False, "error": f"Analyzer failed: {exc}"
        }), 500


if __name__ == "__main__":
    app.run(host=HOST, port=5000, debug=False)
