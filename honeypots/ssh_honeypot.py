#!/usr/bin/env python3
"""
SSH Honeypot - Simulates a real SSH server to capture attacker behavior
Uses Paramiko to handle SSH protocol handshake and session logging
"""

import socket
import threading
import paramiko
import json
import logging
import os
import sys
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
HOST       = "0.0.0.0"
PORT       = 2222          # Use 22 only if running as root; 2222 for dev
LOG_FILE   = "../logs/ssh_honeypot.json"
BANNER     = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
MAX_TRIES  = 5             # Log up to N auth attempts per connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("ssh_honeypot")

os.makedirs("../logs", exist_ok=True)


# ──────────────────────────────────────────────
# Generate / reuse RSA host key
# ──────────────────────────────────────────────
HOST_KEY_PATH = "../config/ssh_host_rsa.key"

def get_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    logger.info("[*] Generated new RSA host key")
    return key

HOST_KEY = get_host_key()


# ──────────────────────────────────────────────
# JSON Logger
# ──────────────────────────────────────────────
def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    logger.info(f"[EVENT] {event.get('event_type')} | {event.get('src_ip')} | {event.get('username','')}")


# ──────────────────────────────────────────────
# SSH Server Interface
# ──────────────────────────────────────────────
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.attempts    = 0
        self.event       = threading.Event()

    # Always reject auth — but log every attempt
    def check_auth_password(self, username: str, password: str) -> int:
        self.attempts += 1
        log_event({
            "event_type"  : "auth_attempt",
            "protocol"    : "ssh",
            "src_ip"      : self.client_ip,
            "src_port"    : self.client_port,
            "username"    : username,
            "password"    : password,
            "attempt_num" : self.attempts,
        })
        # Occasionally accept to study post-auth behavior (set False for pure honeypot)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        log_event({
            "event_type" : "pubkey_attempt",
            "protocol"   : "ssh",
            "src_ip"     : self.client_ip,
            "username"   : username,
            "key_type"   : key.get_name(),
            "key_fp"     : key.get_fingerprint().hex(),
        })
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_request(self, kind: str, chanid: int):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        log_event({
            "event_type" : "command_exec",
            "protocol"   : "ssh",
            "src_ip"     : self.client_ip,
            "command"    : command.decode("utf-8", errors="replace"),
        })
        self.event.set()
        return True


# ──────────────────────────────────────────────
# Client Handler (runs in its own thread)
# ──────────────────────────────────────────────
def handle_client(client_sock: socket.socket, addr: tuple):
    src_ip, src_port = addr
    log_event({"event_type": "connection", "protocol": "ssh",
                "src_ip": src_ip, "src_port": src_port})

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(src_ip, src_port)
        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            return

        # Send a fake shell prompt and capture input
        server.event.wait(10)
        channel.send(b"Welcome to Ubuntu 20.04 LTS\r\nroot@ubuntu:~# ")

        cmd_buffer = b""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            cmd_buffer += data
            if b"\n" in cmd_buffer or b"\r" in cmd_buffer:
                cmd = cmd_buffer.decode("utf-8", errors="replace").strip()
                if cmd:
                    log_event({"event_type": "shell_command", "protocol": "ssh",
                                "src_ip": src_ip, "command": cmd})
                channel.send(b"bash: command not found\r\nroot@ubuntu:~# ")
                cmd_buffer = b""

    except Exception as e:
        log_event({"event_type": "error", "protocol": "ssh",
                    "src_ip": src_ip, "error": str(e)})
    finally:
        if transport:
            transport.close()
        client_sock.close()
        log_event({"event_type": "disconnect", "protocol": "ssh", "src_ip": src_ip})


# ──────────────────────────────────────────────
# Main Server Loop
# ──────────────────────────────────────────────
def run_ssh_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logger.info(f"[*] SSH Honeypot listening on {HOST}:{PORT}")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            logger.info("[!] Shutting down SSH honeypot")
            break
        except Exception as e:
            logger.error(f"Accept error: {e}")

    sock.close()


if __name__ == "__main__":
    run_ssh_honeypot()
