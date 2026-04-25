#!/usr/bin/env python3
"""
Auto Blocklist Engine
=====================
Reads enriched events and automatically blocks high-risk IPs
using iptables. Also maintains a persistent blocklist file.

IMPORTANT: Run as root (or with CAP_NET_ADMIN capability).
On a test machine only — never run on production without review.

Usage:
  sudo python3 auto_block.py              # Block all HIGH+ risk IPs
  sudo python3 auto_block.py --dry-run    # Preview only
  sudo python3 auto_block.py --unblock-all # Remove all honeypot blocks
"""

import json
import os
import subprocess
import argparse
import logging
from datetime import datetime, timezone

ENRICHED_LOG    = "../logs/enriched_events.jsonl"
BLOCKLIST_FILE  = "../config/ip_blacklist.txt"
BLOCK_LOG       = "../logs/blocked_ips.json"
IPTABLES_CHAIN  = "HONEYPOT_BLOCK"  # Custom chain so we don't pollute INPUT
BLOCK_THRESHOLD = 60                 # Block IPs with risk >= this

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("auto_block")

os.makedirs("../config", exist_ok=True)
os.makedirs("../logs",   exist_ok=True)


# ──────────────────────────────────────────────
# iptables helpers
# ──────────────────────────────────────────────
def run_iptables(*args, dry_run=False) -> bool:
    cmd = ["iptables"] + list(args)
    if dry_run:
        logger.info(f"[DRY RUN] {' '.join(cmd)}")
        return True
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.debug(f"iptables: {result.stderr.strip()}")
        return result.returncode == 0
    except FileNotFoundError:
        logger.error("[!] iptables not found — are you running as root on Linux?")
        return False


def setup_chain(dry_run=False):
    """Create HONEYPOT_BLOCK chain if it doesn't exist and hook into INPUT."""
    run_iptables("-N", IPTABLES_CHAIN, dry_run=dry_run)  # May fail if exists, that's OK
    # Hook into INPUT (idempotent check first)
    check = subprocess.run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN],
                           capture_output=True)
    if check.returncode != 0:
        run_iptables("-I", "INPUT", "-j", IPTABLES_CHAIN, dry_run=dry_run)
    logger.info(f"[*] iptables chain '{IPTABLES_CHAIN}' ready")


def is_already_blocked(ip: str) -> bool:
    result = subprocess.run(
        ["iptables", "-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0


def block_ip(ip: str, dry_run=False, reason: str = ""):
    if not dry_run and is_already_blocked(ip):
        logger.debug(f"[SKIP] {ip} already blocked")
        return

    success = run_iptables("-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP",
                            dry_run=dry_run)
    if success:
        logger.info(f"[BLOCK] {ip} | {reason}")

        # Persist to blacklist file
        with open(BLOCKLIST_FILE, "a") as f:
            f.write(f"{ip}\n")

        # Append to block log
        entry = {
            "ip"        : ip,
            "reason"    : reason,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "dry_run"   : dry_run,
        }
        with open(BLOCK_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")


def unblock_all(dry_run=False):
    """Flush the HONEYPOT_BLOCK chain."""
    run_iptables("-F", IPTABLES_CHAIN, dry_run=dry_run)
    logger.info("[*] All honeypot IP blocks removed")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def process_blocklist(dry_run=False):
    if not os.path.exists(ENRICHED_LOG):
        logger.warning(f"[!] {ENRICHED_LOG} not found — run analytics first")
        return

    if not dry_run:
        setup_chain(dry_run=False)

    blocked_count = 0

    with open(ENRICHED_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ep = json.loads(line)
            except json.JSONDecodeError:
                continue

            score  = ep.get("risk_score", 0)
            ip     = ep.get("ip", "")
            label  = ep.get("risk_label", "INFO")
            a_type = ep.get("attacker_type", "unknown")

            if not ip or score < BLOCK_THRESHOLD:
                continue

            reason = f"risk={score} label={label} type={a_type}"
            block_ip(ip, dry_run=dry_run, reason=reason)
            blocked_count += 1

    logger.info(f"\n[✓] Blocked {blocked_count} IPs (dry_run={dry_run})")


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto IP Blocker for Honeypot")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Preview blocks without applying them")
    parser.add_argument("--unblock-all", action="store_true",
                        help="Remove all honeypot IP blocks")
    args = parser.parse_args()

    if args.unblock_all:
        unblock_all(dry_run=False)
    else:
        process_blocklist(dry_run=args.dry_run)
