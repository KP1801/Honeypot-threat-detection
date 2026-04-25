#!/usr/bin/env python3
"""
Master Orchestrator
====================
Starts all honeypot services + analytics + dashboard in one command.
Each service runs in its own subprocess / thread.

Usage:
  python3 run_all.py

Stop with: Ctrl+C
"""

import subprocess
import threading
import time
import os
import sys
import signal

BASE = os.path.dirname(os.path.abspath(__file__))

# Process tracking
procs = []


def run_service(name: str, script: str, cwd: str):
    print(f"[START] {name}")
    p = subprocess.Popen(
        [sys.executable, script],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    procs.append((name, p))
    for line in p.stdout:
        print(f"[{name}] {line.decode().rstrip()}")


def start_thread(name, script, cwd):
    t = threading.Thread(target=run_service, args=(name, script, cwd), daemon=True)
    t.start()
    return t


def graceful_shutdown(sig, frame):
    print("\n[STOP] Shutting down all services...")
    for name, p in procs:
        p.terminate()
        print(f"  [STOP] {name}")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT,  graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    print("=" * 60)
    print("  Honeypot Intelligence System — Starting")
    print("=" * 60)

    # Start honeypots
    start_thread("SSH-Honeypot",  "ssh_honeypot.py",  os.path.join(BASE, "honeypots"))
    time.sleep(0.5)
    start_thread("HTTP-Honeypot", "http_honeypot.py", os.path.join(BASE, "honeypots"))
    time.sleep(0.5)
    start_thread("FTP-Honeypot",  "ftp_honeypot.py",  os.path.join(BASE, "honeypots"))
    time.sleep(1)

    # Start dashboard
    start_thread("Dashboard",     "dashboard.py",     os.path.join(BASE, "dashboard"))

    print("\n" + "=" * 60)
    print("  All services started!")
    print("  Dashboard → http://localhost:5000")
    print("  SSH  honeypot   → port 2222")
    print("  HTTP honeypot   → port 8080")
    print("  FTP  honeypot   → port 2121")
    print("\n  To run analytics:  python3 analytics/analytics_engine.py")
    print("  To generate test data: python3 scripts/generate_test_logs.py")
    print("\n  Press Ctrl+C to stop all services")
    print("=" * 60 + "\n")

    # Keep main thread alive
    while True:
        time.sleep(1)
