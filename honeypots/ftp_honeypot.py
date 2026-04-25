#!/usr/bin/env python3
"""
FTP Honeypot — Simulates an FTP server.
Captures credential spray attacks, directory traversal,
and file upload/download attempts.
"""

import socket
import threading
import json
import logging
import os
from datetime import datetime, timezone

HOST     = "0.0.0.0"
PORT     = 2121
LOG_FILE = "../logs/ftp_honeypot.json"

os.makedirs("../logs", exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("ftp_honeypot")

FAKE_DIRS = ["pub", "incoming", "upload", "backup", "private", "www"]
FAKE_FILES = [
    "-rw-r--r-- 1 ftp ftp  1024 Jan 01 00:00 readme.txt",
    "-rw-r--r-- 1 ftp ftp  4096 Jan 01 00:00 backup.tar.gz",
    "-rw-r--r-- 1 ftp ftp  2048 Jan 01 00:00 config.bak",
]


def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    logger.info(f"[FTP] {event.get('event_type')} | {event.get('src_ip')}")


def handle_client(conn: socket.socket, addr: tuple):
    src_ip, src_port = addr
    log_event({"event_type": "connection", "protocol": "ftp",
                "src_ip": src_ip, "src_port": src_port})

    username = ""
    password = ""

    def send(msg: str):
        conn.send((msg + "\r\n").encode())

    try:
        send("220 Microsoft FTP Service")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            line = data.decode("utf-8", errors="replace").strip()
            parts = line.split(" ", 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                log_event({"event_type": "username", "protocol": "ftp",
                            "src_ip": src_ip, "username": username})
                send("331 Password required for user.")

            elif cmd == "PASS":
                password = arg
                log_event({"event_type": "auth_attempt", "protocol": "ftp",
                            "src_ip": src_ip, "username": username, "password": password})
                # Always fail auth
                send("530 Login incorrect.")

            elif cmd == "QUIT":
                send("221 Goodbye.")
                break

            elif cmd == "SYST":
                send("215 UNIX Type: L8")

            elif cmd == "FEAT":
                send("211-Features:\r\n PASV\r\n SIZE\r\n211 End")

            elif cmd in ("LIST", "NLST"):
                log_event({"event_type": "list_attempt", "protocol": "ftp",
                            "src_ip": src_ip, "path": arg or "/"})
                send("530 Please login with USER and PASS.")

            elif cmd == "CWD":
                log_event({"event_type": "cwd_attempt", "protocol": "ftp",
                            "src_ip": src_ip, "path": arg})
                send("530 Please login with USER and PASS.")

            elif cmd in ("RETR", "STOR"):
                log_event({"event_type": f"file_{cmd.lower()}_attempt",
                            "protocol": "ftp", "src_ip": src_ip, "filename": arg})
                send("530 Please login with USER and PASS.")

            elif cmd == "NOOP":
                send("200 NOOP ok.")

            else:
                log_event({"event_type": "unknown_command", "protocol": "ftp",
                            "src_ip": src_ip, "command": line})
                send("502 Command not implemented.")

    except Exception as e:
        log_event({"event_type": "error", "protocol": "ftp",
                    "src_ip": src_ip, "error": str(e)})
    finally:
        conn.close()
        log_event({"event_type": "disconnect", "protocol": "ftp", "src_ip": src_ip})


def run_ftp_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(50)
    logger.info(f"[*] FTP Honeypot listening on {HOST}:{PORT}")

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Accept error: {e}")
    sock.close()


if __name__ == "__main__":
    run_ftp_honeypot()
