
import csv
import socketserver
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

HOST = "127.0.0.1"
PORT = 9000
LOG_FILE = Path(__file__).parent / "events.csv"
log_lock = Lock()


def log_event(source_ip, event_type, byte_count=0):
    new_file = not LOG_FILE.exists()

    with log_lock, LOG_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow([
                "timestamp", "source_ip",
                "event_type", "byte_count"
            ])

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            source_ip, event_type, byte_count
        ])


class HoneypotHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        log_event(ip, "connection")

        self.request.sendall(
            b"Research Service - Connection Recorded\r\n"
        )
        self.request.settimeout(3)

        try:
            data = self.request.recv(512)
            if data:
                log_event(ip, "data_received", len(data))
        except TimeoutError:
            log_event(ip, "read_timeout")
        except OSError:
            log_event(ip, "read_error")


class HoneypotServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with HoneypotServer((HOST, PORT), HoneypotHandler) as server:
        print(f"Honeypot listening on {HOST}:{PORT}")
        print("Bound to localhost only. Press Ctrl+C to stop.")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nHoneypot stopped.")
