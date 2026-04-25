#!/usr/bin/env python3
"""
HTTP Honeypot — Mimics a real web server (Apache/Nginx).
Captures exploit attempts: SQL injection, path traversal,
command injection, scanner fingerprints, and admin panel probes.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
HOST     = "0.0.0.0"
PORT     = 8080
LOG_FILE = "../logs/http_honeypot.json"
SERVER_BANNER = "Apache/2.4.41 (Ubuntu)"

os.makedirs("../logs", exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("http_honeypot")


# ──────────────────────────────────────────────
# Threat Signature Patterns
# ──────────────────────────────────────────────
SIGNATURES = {
    "sql_injection": [
        r"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into|'--)",
        r"(?i)(or\s+1=1|and\s+1=1|benchmark\(|sleep\()",
    ],
    "path_traversal": [
        r"\.\./",
        r"(?i)(%2e%2e%2f|%252e%252e|\.\.%5c)",
    ],
    "command_injection": [
        r"(?i)(\||;|&&|\$\(|`)(ls|cat|whoami|wget|curl|bash|sh)\b",
        r"(?i)(system|exec|passthru|shell_exec)\s*\(",
    ],
    "xss": [
        r"(?i)(<script|javascript:|onerror=|onload=|alert\()",
    ],
    "scanner_probe": [
        r"(?i)(nikto|nmap|masscan|sqlmap|dirbuster|gobuster|wfuzz)",
    ],
    "admin_probe": [
        r"(?i)(/admin|/wp-admin|/phpmyadmin|/config|/.env|/backup)",
    ],
    "file_inclusion": [
        r"(?i)(php://|file://|data://|expect://)",
        r"(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/self)",
    ],
}


def classify_request(path: str, body: str, ua: str) -> list:
    """Return list of threat categories detected in this request."""
    combined = f"{path} {body} {ua}"
    found = []
    for threat_type, patterns in SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, combined):
                found.append(threat_type)
                break
    return found or ["unknown_probe"]


# ──────────────────────────────────────────────
# JSON Event Logger
# ──────────────────────────────────────────────
def log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    logger.info(f"[EVENT] {event.get('method')} {event.get('path')} | {event.get('src_ip')}"
                f" | threats={event.get('threats')}")


# ──────────────────────────────────────────────
# Fake Response Pages
# ──────────────────────────────────────────────
FAKE_INDEX = b"""<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page</title></head>
<body><h1>Apache2 Ubuntu Default Page</h1>
<p>It works! This is the default welcome page for Apache2.</p>
</body></html>"""

FAKE_404 = b"""<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body></html>"""

FAKE_403 = b"""<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body><h1>Forbidden</h1><p>You don't have permission to access this resource.</p>
</body></html>"""


# ──────────────────────────────────────────────
# HTTP Handler
# ──────────────────────────────────────────────
class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version    = ""

    def log_message(self, format, *args):
        pass  # Suppress default stdout logging; we do our own

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def _build_event(self, method: str, body: str = "") -> dict:
        path    = unquote(self.path)
        ua      = self.headers.get("User-Agent", "")
        threats = classify_request(path, body, ua)
        return {
            "event_type"  : "http_request",
            "protocol"    : "http",
            "method"      : method,
            "path"        : path,
            "query_string": urlparse(self.path).query,
            "src_ip"      : self.client_address[0],
            "src_port"    : self.client_address[1],
            "user_agent"  : ua,
            "referer"     : self.headers.get("Referer", ""),
            "host_header" : self.headers.get("Host", ""),
            "body"        : body[:2000],  # Cap body size stored
            "threats"     : threats,
            "headers"     : dict(self.headers),
        }

    def _send_fake_response(self, path: str):
        if path in ("/", "/index.html", "/index.php"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", SERVER_BANNER)
            self.end_headers()
            self.wfile.write(FAKE_INDEX)
        elif any(kw in path.lower() for kw in ["/admin", "/wp-admin", "/phpmyadmin"]):
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(FAKE_403)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(FAKE_404)

    def do_GET(self):
        event = self._build_event("GET")
        log_event(event)
        self._send_fake_response(urlparse(self.path).path)

    def do_POST(self):
        body  = self._read_body()
        event = self._build_event("POST", body)
        log_event(event)
        self._send_fake_response(urlparse(self.path).path)

    def do_HEAD(self):
        event = self._build_event("HEAD")
        log_event(event)
        self.send_response(200)
        self.send_header("Server", SERVER_BANNER)
        self.end_headers()

    def do_PUT(self):
        body  = self._read_body()
        event = self._build_event("PUT", body)
        log_event(event)
        self.send_response(405)
        self.end_headers()

    def do_OPTIONS(self):
        event = self._build_event("OPTIONS")
        log_event(event)
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST")
        self.end_headers()


# ──────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────
def run_http_honeypot():
    server = HTTPServer((HOST, PORT), HoneypotHTTPHandler)
    logger.info(f"[*] HTTP Honeypot listening on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[!] HTTP Honeypot stopped")


if __name__ == "__main__":
    run_http_honeypot()
