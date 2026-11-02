# SENTINEL — Mini SOC Analyst Dashboard

SENTINEL is a defensive-security showcase built for the kind of analyst workflow that sits between raw telemetry and triage decisions. It models a compact SOC environment where suspicious authentication activity is surfaced, prioritised, and investigated in real time.

This project blends Python, Flask, SQLite, and a dark operational UI to create a dashboard that feels like a lightweight blue-team command layer: event ingestion, anomaly detection, threat correlation, alert filtering, and investigation tracking all in one locally hosted app.

## Threat posture

The dashboard is built to simulate the operational realities of a security team responding to risky login behaviour and hostile patterning from hostile or compromised sources. It is intentionally focused on defensive monitoring, not offensive tooling or attack execution.

## Core capabilities

- Repeated-failure login detection and brute-force pattern analysis
- Suspicious source-IP monitoring and authentication anomaly tracking
- Severity-based alert prioritisation across High, Medium, and Low events
- Live synthetic event simulation for a realistic SOC feel
- Combined filtering by severity, status, source IP, and date range
- Analyst note-taking and investigation history tied to each alert
- Timeline tracking for status changes and mitigation updates
- Local-only execution for portfolio-safe demos and learning use

## Operator workflow

- Overview cards for total events, successful logins, failed logins, and suspicious IPs
- Event trend chart for recent activity patterns
- Severity distribution chart for triage weighting
- Alert table with dynamic filtering and live updates
- Analyst control flow for updating alert states and documenting findings
- Dark cyber-themed interface designed to feel like a real operations console

## Project structure

- `app.py`: Flask routes, API endpoints, and live simulation logic
- `analyzer.py`: CSV validation and event normalization
- `detector.py`: detection rules for suspicious login and auth patterns
- `database.py`: SQLite persistence, schema setup, and alert lifecycle management
- `sample_logs.csv`: synthetic event data for demonstrations and testing
- `templates/`: dashboard UI templates
- `static/`: CSS and JavaScript for the front-end experience
- `test_alert_filters.py`: regression tests covering filtering and dashboard logic

## Stack

- Python 3
- Flask
- SQLite
- Chart.js
- HTML, CSS, and JavaScript

## Installation

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Run locally

```bash
python app.py
```

Open: http://127.0.0.1:5000

## Analyst flow

1. Launch the dashboard and review the current threat picture.
2. Inspect the live overview and chart-driven indicators.
3. Filter alerts by severity, status, date window, or suspicious IP.
4. Drill into the timeline and investigation notes for each alert.
5. Update the case status to reflect investigation progress.

## Portfolio positioning

SENTINEL is designed to communicate defensive engineering capability in a compact, visually strong package. It demonstrates the ability to build a security-focused user interface, model analyst workflows, apply detection logic, and turn raw event data into actionable investigation surfaces.

## Notes

This project uses synthetic, fictional telemetry for education, portfolio demonstration, and defensive-security learning. It is intentionally local-only and is not intended for production SOC deployment or live enterprise monitoring.

## Future upgrades

- Expanded detection rule sets and threat heuristics
- Incident export and reporting views
- Historical trend comparison and retention
- Role-based analyst workflows and access layers
- Deeper drilldowns into related hosts, usernames, and attack paths
