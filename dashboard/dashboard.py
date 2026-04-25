#!/usr/bin/env python3
"""
Honeypot Intelligence Dashboard
================================
Flask-based web dashboard to visualize:
  - Real-time threat events
  - Risk score distribution
  - Attacker geography
  - Threat type breakdown
  - Top attacker profiles
  - Attack timeline

Run:
  cd dashboard
  python3 dashboard.py

Then open: http://localhost:5000
"""

import json
import os
import glob
from collections import Counter, defaultdict
from datetime import datetime, timezone
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

LOG_DIR        = "../logs"
ENRICHED_LOG   = "../logs/enriched_events.jsonl"
SUMMARY_FILE   = "../logs/threat_summary.json"
RAW_LOGS       = ["ssh_honeypot.json", "http_honeypot.json", "ftp_honeypot.json"]


# ──────────────────────────────────────────────
# Data Helpers
# ──────────────────────────────────────────────
def load_enriched() -> list:
    data = []
    if not os.path.exists(ENRICHED_LOG):
        return data
    with open(ENRICHED_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return sorted(data, key=lambda x: x.get("risk_score", 0), reverse=True)


def load_raw_events() -> list:
    events = []
    for fname in RAW_LOGS:
        fpath = os.path.join(LOG_DIR, fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return events


def load_summary() -> dict:
    if not os.path.exists(SUMMARY_FILE):
        return {}
    with open(SUMMARY_FILE) as f:
        return json.load(f)


# ──────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────
@app.route("/api/summary")
def api_summary():
    enriched = load_enriched()
    raw      = load_raw_events()
    summary  = load_summary()

    risk_dist = Counter(ep["risk_label"] for ep in enriched)
    atk_types = Counter(ep["attacker_type"] for ep in enriched)
    protocols = Counter(ev.get("protocol", "unknown") for ev in raw)

    # Timeline: events per hour (last 24 h)
    hour_counter = Counter()
    for ev in raw:
        ts = ev.get("timestamp", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour_counter[dt.strftime("%Y-%m-%d %H:00")] += 1
            except Exception:
                pass
    timeline = sorted(hour_counter.items())[-24:]

    return jsonify({
        "total_events"     : len(raw),
        "unique_ips"       : len(enriched),
        "critical_count"   : risk_dist.get("CRITICAL", 0),
        "high_count"       : risk_dist.get("HIGH", 0),
        "risk_distribution": dict(risk_dist),
        "attacker_types"   : dict(atk_types),
        "protocols"        : dict(protocols),
        "timeline_labels"  : [t[0] for t in timeline],
        "timeline_counts"  : [t[1] for t in timeline],
        "top_threats"      : summary.get("top_threats", []),
    })


@app.route("/api/attackers")
def api_attackers():
    enriched = load_enriched()
    return jsonify(enriched[:50])  # Top 50 by risk


@app.route("/api/events")
def api_events():
    raw = load_raw_events()
    return jsonify(raw[:100])  # Latest 100 events


@app.route("/api/threat_feed")
def api_threat_feed():
    """Live threat feed for dashboard ticker."""
    raw  = load_raw_events()
    feed = []
    for ev in raw[:20]:
        feed.append({
            "time"      : ev.get("timestamp", "")[:19],
            "ip"        : ev.get("src_ip", "?"),
            "protocol"  : ev.get("protocol", "?"),
            "event_type": ev.get("event_type", "?"),
            "threats"   : ev.get("threats", []),
        })
    return jsonify(feed)


# ──────────────────────────────────────────────
# HTML Dashboard (single-file, Chart.js)
# ──────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Honeypot Intelligence Dashboard</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {
      --bg: #0d1117; --card: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
      --red: #f85149; --orange: #d29922; --green: #3fb950; --blue: #58a6ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, monospace; }
    header {
      background: var(--card); border-bottom: 1px solid var(--border);
      padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem;
    }
    header h1 { font-size: 1.1rem; font-weight: 600; }
    .badge {
      font-size: 0.7rem; padding: 2px 8px; border-radius: 4px;
      background: var(--red); color: #fff; animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
    .stats {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
      gap: 1rem; padding: 1.5rem 2rem;
    }
    .stat-card {
      background: var(--card); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.25rem;
    }
    .stat-card .label { font-size: 0.75rem; color: var(--muted); margin-bottom: 0.5rem; }
    .stat-card .value { font-size: 1.8rem; font-weight: 700; }
    .stat-card .value.red { color: var(--red); }
    .stat-card .value.orange { color: var(--orange); }
    .stat-card .value.blue { color: var(--blue); }
    .charts {
      display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; padding: 0 2rem;
    }
    @media (max-width: 768px) { .charts { grid-template-columns: 1fr; } }
    .chart-card {
      background: var(--card); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.25rem;
    }
    .chart-card h3 { font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem; }
    .chart-card canvas { max-height: 220px; }
    .feed-section { padding: 1.5rem 2rem; }
    .feed-section h2 { font-size: 0.9rem; color: var(--muted); margin-bottom: 1rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 0.6rem 0.75rem; text-align: left; font-size: 0.8rem; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 500; }
    td code { background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 4px; font-size: 0.75rem; }
    .badge-risk {
      display: inline-block; padding: 1px 8px; border-radius: 4px;
      font-size: 0.7rem; font-weight: 600;
    }
    .CRITICAL { background: #3d0f0f; color: #f85149; }
    .HIGH     { background: #2d2000; color: #d29922; }
    .MEDIUM   { background: #1a2a1a; color: #3fb950; }
    .LOW      { background: #1c2330; color: #58a6ff; }
    .INFO     { background: #21262d; color: #8b949e; }
    .refresh-note { font-size: 0.7rem; color: var(--muted); padding: 0.5rem 2rem 2rem; }
  </style>
</head>
<body>

<header>
  <h1>🍯 Honeypot Intelligence Dashboard</h1>
  <span class="badge">LIVE</span>
  <span style="margin-left:auto;font-size:0.75rem;color:var(--muted)" id="last-updated"></span>
</header>

<div class="stats">
  <div class="stat-card">
    <div class="label">Total Events Captured</div>
    <div class="value blue" id="total-events">—</div>
  </div>
  <div class="stat-card">
    <div class="label">Unique Attacker IPs</div>
    <div class="value" id="unique-ips">—</div>
  </div>
  <div class="stat-card">
    <div class="label">Critical Threats</div>
    <div class="value red" id="critical-count">—</div>
  </div>
  <div class="stat-card">
    <div class="label">High Risk IPs</div>
    <div class="value orange" id="high-count">—</div>
  </div>
</div>

<div class="charts">
  <div class="chart-card">
    <h3>Attack Timeline (events/hour)</h3>
    <canvas id="timeline-chart"></canvas>
  </div>
  <div class="chart-card">
    <h3>Risk Distribution</h3>
    <canvas id="risk-chart"></canvas>
  </div>
  <div class="chart-card">
    <h3>Attacker Types</h3>
    <canvas id="type-chart"></canvas>
  </div>
  <div class="chart-card">
    <h3>Protocol Distribution</h3>
    <canvas id="proto-chart"></canvas>
  </div>
</div>

<div class="feed-section">
  <h2>Top Threat Actors</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th><th>Risk</th><th>Type</th>
        <th>Events</th><th>Auth Attempts</th><th>Country</th>
      </tr>
    </thead>
    <tbody id="attacker-table"></tbody>
  </table>
</div>

<div class="feed-section">
  <h2>Live Event Feed</h2>
  <table>
    <thead>
      <tr><th>Time</th><th>IP</th><th>Protocol</th><th>Event</th><th>Threats</th></tr>
    </thead>
    <tbody id="event-table"></tbody>
  </table>
</div>

<p class="refresh-note">Auto-refreshes every 10 seconds.</p>

<script>
const CHART_OPTS = { responsive: true, maintainAspectRatio: true,
  plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 } } } },
  scales: { x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } } }
};

let timelineChart, riskChart, typeChart, protoChart;

function initCharts(summary) {
  timelineChart = new Chart(document.getElementById('timeline-chart'), {
    type: 'line',
    data: {
      labels: (summary.timeline_labels || []).map(l => l.split(' ')[1]),
      datasets: [{ label: 'Events', data: summary.timeline_counts || [],
        borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.12)',
        fill: true, tension: 0.4, pointRadius: 2 }]
    },
    options: { ...CHART_OPTS }
  });

  const riskColors = { CRITICAL:'#f85149', HIGH:'#d29922', MEDIUM:'#3fb950', LOW:'#58a6ff', INFO:'#8b949e' };
  const rd = summary.risk_distribution || {};
  riskChart = new Chart(document.getElementById('risk-chart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(rd),
      datasets: [{ data: Object.values(rd), backgroundColor: Object.keys(rd).map(k => riskColors[k] || '#666'), borderWidth: 0 }]
    },
    options: { responsive: true, plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 } } } } }
  });

  const at = summary.attacker_types || {};
  typeChart = new Chart(document.getElementById('type-chart'), {
    type: 'bar',
    data: {
      labels: Object.keys(at),
      datasets: [{ label: 'IPs', data: Object.values(at), backgroundColor: '#d29922', borderRadius: 4 }]
    },
    options: { ...CHART_OPTS, plugins: { legend: { display: false } } }
  });

  const pr = summary.protocols || {};
  protoChart = new Chart(document.getElementById('proto-chart'), {
    type: 'bar',
    data: {
      labels: Object.keys(pr),
      datasets: [{ label: 'Events', data: Object.values(pr), backgroundColor: '#3fb950', borderRadius: 4 }]
    },
    options: { ...CHART_OPTS, plugins: { legend: { display: false } } }
  });
}

async function refresh() {
  try {
    const [summary, attackers, events] = await Promise.all([
      fetch('/api/summary').then(r => r.json()),
      fetch('/api/attackers').then(r => r.json()),
      fetch('/api/events').then(r => r.json()),
    ]);

    document.getElementById('total-events').textContent = summary.total_events || 0;
    document.getElementById('unique-ips').textContent   = summary.unique_ips || 0;
    document.getElementById('critical-count').textContent = summary.critical_count || 0;
    document.getElementById('high-count').textContent   = summary.high_count || 0;
    document.getElementById('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();

    if (!timelineChart) {
      initCharts(summary);
    } else {
      timelineChart.data.labels   = (summary.timeline_labels || []).map(l => l.split(' ')[1]);
      timelineChart.data.datasets[0].data = summary.timeline_counts || [];
      timelineChart.update();
    }

    const tbody = document.getElementById('attacker-table');
    tbody.innerHTML = attackers.slice(0,15).map(ep => `
      <tr>
        <td><code>${ep.ip}</code></td>
        <td><span class="badge-risk ${ep.risk_label}">${ep.risk_label} (${ep.risk_score})</span></td>
        <td>${ep.attacker_type || '—'}</td>
        <td>${(ep.profile || {}).total_events || 0}</td>
        <td>${(ep.profile || {}).auth_attempts || 0}</td>
        <td>${(ep.geo || {}).country || '?'}</td>
      </tr>`).join('');

    const etbody = document.getElementById('event-table');
    etbody.innerHTML = events.slice(0,20).map(ev => `
      <tr>
        <td>${(ev.timestamp||'').substring(11,19)}</td>
        <td><code>${ev.src_ip||'?'}</code></td>
        <td>${ev.protocol||'?'}</td>
        <td>${ev.event_type||'?'}</td>
        <td>${(ev.threats||[]).join(', ') || '—'}</td>
      </tr>`).join('');

  } catch(e) {
    console.warn('Refresh failed:', e);
  }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ──────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Starting Honeypot Dashboard on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
