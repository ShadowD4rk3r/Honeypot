import socket
import datetime
import threading

HOST = "0.0.0.0"
PORT = 2222

log_file = "honeypot.log"

def log_attempt(addr, username, password):
    with open(log_file, "a") as f:
        time = datetime.datetime.now()
        f.write(f"{time} - {addr} - Username: {username} | Password: {password}\n")

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    try:
        conn.send(b"Welcome to the server\n")
        conn.send(b"Username: ")

        username = conn.recv(1024).decode().strip()

        conn.send(b"Password: ")
        password = conn.recv(1024).decode().strip()

        print(f"[!] Login attempt from {addr} -> {username}:{password}")

        log_attempt(addr, username, password)

        conn.send(b"Invalid credentials. Connection closing.\n")

    except:
        print(f"[-] Error handling connection from {addr}")

    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print(f"[+] Honeypot listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()

            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

start_server()