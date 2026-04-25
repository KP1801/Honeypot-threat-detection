#!/usr/bin/env python3
"""
AI Analytics Engine
===================
Reads all honeypot JSON logs and applies:
  1. Rule-based threat classification
  2. IP reputation enrichment (AbuseIPDB / local blacklist)
  3. GeoIP location lookup
  4. Isolation Forest anomaly detection
  5. Behavioral clustering (KMeans)
  6. Risk scoring (0-100)
  7. Outputs enriched JSONL + summary report
"""

import json
import os
import glob
import hashlib
import math
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────
LOG_DIR        = "../logs"
MODEL_DIR      = "../models"
OUTPUT_FILE    = "../logs/enriched_events.jsonl"
SUMMARY_FILE   = "../logs/threat_summary.json"
BLACKLIST_FILE = "../config/ip_blacklist.txt"

os.makedirs(MODEL_DIR, exist_ok=True)


# ──────────────────────────────────────────────
# 1. Load all raw logs
# ──────────────────────────────────────────────
def load_all_logs() -> List[Dict]:
    events = []
    for fpath in glob.glob(f"{LOG_DIR}/*.json"):
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    events.sort(key=lambda e: e.get("timestamp", ""))
    print(f"[+] Loaded {len(events)} raw events from {LOG_DIR}")
    return events


# ──────────────────────────────────────────────
# 2. IP Reputation Check
# ──────────────────────────────────────────────
def load_blacklist() -> set:
    bl = set()
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    bl.add(ip)
    return bl

BLACKLIST = load_blacklist()

def check_ip_reputation(ip: str) -> Dict:
    """
    In production: call AbuseIPDB API.
    Here: local blacklist + heuristics.
    """
    result = {
        "is_blacklisted"   : ip in BLACKLIST,
        "is_tor_exit"      : False,         # Extend: check dan.me.uk/torlist
        "is_known_scanner" : False,
        "reputation_score" : 0,             # 0 = clean, 100 = known malicious
    }
    # Heuristics: known scanner ranges (example — Shodan, Censys, etc.)
    scanner_prefixes = ["198.20.", "66.240.", "71.6.", "162.142.", "167.248."]
    for prefix in scanner_prefixes:
        if ip.startswith(prefix):
            result["is_known_scanner"] = True
            result["reputation_score"]  = max(result["reputation_score"], 60)

    if result["is_blacklisted"]:
        result["reputation_score"] = 100

    return result


# ──────────────────────────────────────────────
# 3. GeoIP (offline — extend with maxmind DB)
# ──────────────────────────────────────────────
def geoip_lookup(ip: str) -> Dict:
    """
    Placeholder — integrate python-geoip or maxminddb-geolite2 for real data.
    Returns dummy data for demo.
    """
    # Private/loopback ranges
    for prefix in ["127.", "192.168.", "10.", "172.16."]:
        if ip.startswith(prefix):
            return {"country": "LOCAL", "city": "localhost", "asn": "LOCAL"}

    # In prod: geoip2.database.Reader("GeoLite2-City.mmdb").city(ip)
    return {"country": "UNKNOWN", "city": "UNKNOWN", "asn": "UNKNOWN"}


# ──────────────────────────────────────────────
# 4. Feature Extraction for ML
# ──────────────────────────────────────────────
def build_ip_profiles(events: List[Dict]) -> Dict[str, Dict]:
    """Aggregate per-IP behavioral profile."""
    profiles = defaultdict(lambda: {
        "total_events"      : 0,
        "auth_attempts"     : 0,
        "unique_usernames"  : set(),
        "unique_passwords"  : set(),
        "unique_paths"      : set(),
        "threat_types"      : Counter(),
        "protocols"         : Counter(),
        "first_seen"        : None,
        "last_seen"         : None,
        "commands"          : [],
    })

    for ev in events:
        ip = ev.get("src_ip", "unknown")
        p  = profiles[ip]

        p["total_events"] += 1

        ts = ev.get("timestamp")
        if ts:
            if p["first_seen"] is None or ts < p["first_seen"]:
                p["first_seen"] = ts
            if p["last_seen"] is None or ts > p["last_seen"]:
                p["last_seen"] = ts

        proto = ev.get("protocol", "unknown")
        p["protocols"][proto] += 1

        evt = ev.get("event_type", "")
        if "auth" in evt:
            p["auth_attempts"] += 1
        if "username" in ev:
            p["unique_usernames"].add(ev["username"])
        if "password" in ev:
            p["unique_passwords"].add(ev["password"])
        if "path" in ev:
            p["unique_paths"].add(ev["path"])
        if "command" in ev:
            p["commands"].append(ev["command"])

        for threat in ev.get("threats", []):
            p["threat_types"][threat] += 1

    # Convert sets to counts for serialisation
    result = {}
    for ip, p in profiles.items():
        result[ip] = {
            **p,
            "unique_usernames" : len(p["unique_usernames"]),
            "unique_passwords" : len(p["unique_passwords"]),
            "unique_paths"     : len(p["unique_paths"]),
            "threat_types"     : dict(p["threat_types"]),
            "protocols"        : dict(p["protocols"]),
            "command_count"    : len(p["commands"]),
        }
    return result


def extract_features(profile: Dict) -> np.ndarray:
    """Convert an IP profile into a numeric feature vector."""
    return np.array([
        profile.get("total_events", 0),
        profile.get("auth_attempts", 0),
        profile.get("unique_usernames", 0),
        profile.get("unique_passwords", 0),
        profile.get("unique_paths", 0),
        profile.get("command_count", 0),
        len(profile.get("threat_types", {})),
        len(profile.get("protocols", {})),
    ], dtype=float)


# ──────────────────────────────────────────────
# 5. Anomaly Detection (Isolation Forest)
# ──────────────────────────────────────────────
def train_isolation_forest(X: np.ndarray) -> IsolationForest:
    model = IsolationForest(
        n_estimators  = 200,
        contamination = 0.1,   # Assume 10 % of traffic is anomalous
        random_state  = 42,
    )
    model.fit(X)
    joblib.dump(model, f"{MODEL_DIR}/isolation_forest.pkl")
    print("[+] Isolation Forest trained and saved")
    return model


# ──────────────────────────────────────────────
# 6. Behavioral Clustering
# ──────────────────────────────────────────────
CLUSTER_LABELS = {
    0: "credential_sprayer",
    1: "vulnerability_scanner",
    2: "targeted_attacker",
    3: "web_crawler",
}

def cluster_ips(X: np.ndarray, n_clusters: int = 4) -> np.ndarray:
    if len(X) < n_clusters:
        return np.zeros(len(X), dtype=int)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    km = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = km.fit_predict(X_scaled)
    joblib.dump((scaler, km), f"{MODEL_DIR}/kmeans.pkl")
    print("[+] KMeans clustering done")
    return labels


# ──────────────────────────────────────────────
# 7. Risk Scoring
# ──────────────────────────────────────────────
def compute_risk_score(profile: Dict, rep: Dict, anomaly_score: float) -> int:
    """
    Risk = weighted sum, clamped to [0, 100].
    anomaly_score from IsolationForest: negative = more anomalous.
    """
    score = 0

    # Volume
    score += min(profile.get("total_events", 0)  * 0.5, 20)
    score += min(profile.get("auth_attempts", 0)  * 1.0, 20)
    score += min(profile.get("unique_passwords", 0) * 0.5, 10)

    # Threat variety
    score += len(profile.get("threat_types", {})) * 5

    # Reputation
    score += rep.get("reputation_score", 0) * 0.3
    if rep.get("is_tor_exit"):
        score += 15
    if rep.get("is_known_scanner"):
        score += 10

    # ML anomaly boost (more negative = more anomalous)
    if anomaly_score < -0.2:
        score += 20
    elif anomaly_score < 0:
        score += 10

    return min(int(score), 100)


def risk_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


# ──────────────────────────────────────────────
# 8. Main Pipeline
# ──────────────────────────────────────────────
def run_analytics():
    print("\n=== Honeypot Analytics Engine ===\n")

    events  = load_all_logs()
    if not events:
        print("[!] No events found. Run honeypots first.")
        return

    profiles = build_ip_profiles(events)
    ips      = list(profiles.keys())

    if not ips:
        print("[!] No IP profiles built.")
        return

    # Feature matrix
    X = np.array([extract_features(profiles[ip]) for ip in ips])

    # Anomaly detection
    iso = train_isolation_forest(X)
    anomaly_scores = iso.score_samples(X)  # Lower = more anomalous

    # Clustering
    cluster_ids = cluster_ips(X)

    # Enrich each IP
    enriched_profiles = []
    for i, ip in enumerate(ips):
        profile  = profiles[ip]
        rep      = check_ip_reputation(ip)
        geo      = geoip_lookup(ip)
        a_score  = float(anomaly_scores[i])
        risk     = compute_risk_score(profile, rep, a_score)
        cluster  = int(cluster_ids[i])

        enriched = {
            "ip"              : ip,
            "risk_score"      : risk,
            "risk_label"      : risk_label(risk),
            "attacker_type"   : CLUSTER_LABELS.get(cluster, f"cluster_{cluster}"),
            "anomaly_score"   : round(a_score, 4),
            "geo"             : geo,
            "reputation"      : rep,
            "profile"         : {k: v for k, v in profile.items()
                                 if k not in ("commands",)},  # Skip raw commands
            "analyzed_at"     : datetime.now(timezone.utc).isoformat(),
        }
        enriched_profiles.append(enriched)

    # Sort by risk descending
    enriched_profiles.sort(key=lambda x: x["risk_score"], reverse=True)

    # Write enriched output
    with open(OUTPUT_FILE, "w") as f:
        for ep in enriched_profiles:
            f.write(json.dumps(ep) + "\n")
    print(f"\n[+] Enriched profiles saved → {OUTPUT_FILE}")

    # Summary report
    threat_counter = Counter()
    for ev in events:
        for t in ev.get("threats", []):
            threat_counter[t] += 1

    summary = {
        "generated_at"       : datetime.now(timezone.utc).isoformat(),
        "total_events"       : len(events),
        "unique_ips"         : len(ips),
        "top_threats"        : threat_counter.most_common(10),
        "risk_distribution"  : Counter(ep["risk_label"] for ep in enriched_profiles),
        "attacker_types"     : Counter(ep["attacker_type"] for ep in enriched_profiles),
        "top_attackers"      : [
            {"ip": ep["ip"], "score": ep["risk_score"], "label": ep["risk_label"]}
            for ep in enriched_profiles[:10]
        ],
    }
    summary["risk_distribution"] = dict(summary["risk_distribution"])
    summary["attacker_types"]    = dict(summary["attacker_types"])

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Summary report saved → {SUMMARY_FILE}")

    # Console output
    print("\n── Top 5 Attackers ──")
    for ep in enriched_profiles[:5]:
        print(f"  {ep['ip']:<18} Risk={ep['risk_score']:>3} [{ep['risk_label']:<8}]"
              f" Type={ep['attacker_type']}")

    print("\n── Threat Distribution ──")
    for threat, count in threat_counter.most_common(8):
        print(f"  {threat:<25} {count}")

    print("\n[✓] Analytics complete.\n")
    return enriched_profiles


if __name__ == "__main__":
    run_analytics()
