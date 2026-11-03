# SENTINEL — Mini SOC Analyst Dashboard

SENTINEL is a local defensive-security dashboard for the analyst workflow between raw telemetry and triage decisions. It surfaces suspicious authentication activity and supports a compact alert-investigation workflow.

This project blends Python, Flask, SQLite, and a dark operational UI to create a dashboard that feels like a lightweight blue-team command layer: event ingestion, anomaly detection, threat correlation, alert filtering, and investigation tracking all in one locally hosted app.

## Threat posture

The dashboard simulates a small SOC responding to risky login behaviour and suspicious authentication patterns. It focuses on defensive monitoring, not offensive tooling or attack execution.

## Core capabilities

- Repeated-failure login detection and brute-force pattern analysis
- Suspicious source-IP monitoring and authentication anomaly tracking
- Severity-based alert prioritisation across High, Medium, and Low events
- Live synthetic event simulation for a realistic SOC feel
- Read-only collection of local Windows Security events on Windows 11
- Windows event filtering by event ID, time range, and severity
- Duplicate protection using the computer name and Windows event record ID
- Combined filtering by severity, status, source IP, and date range
- Analyst note-taking and investigation history tied to each alert
- Timeline tracking for status changes and mitigation updates
- Hash-based navigation across Overview, Alerts, Threats, Intel, and Reports, including browser history support
- Local-only execution for portfolio-safe demos and learning use

## Operator workflow

- Overview cards for total events, successful logins, failed logins, and suspicious IPs
- Event metrics are aggregated from stored demo, simulation, CSV, and Windows event records
- CSV upload validates ISO timestamps, IP addresses, authentication event types, and result status before import
- CSV uploads are limited to 2 MiB and 10,000 records, processed in memory, and deduplicated
- Event trend chart covers today and the previous six UTC calendar dates
- Severity distribution chart counts alerts after the active alert filters are applied
- Alert table with dynamic filtering and live updates
- Analyst control flow for updating alert states and documenting findings
- Native Windows event collection with manual refresh and configurable polling
- Dark cyber-themed interface designed to feel like a real operations console

## V2 scope

The Threats view currently contains the Windows Security Events panel. Intel and Reports navigation works, but those views are empty states: V2 does not yet include threat-intelligence feeds, IOC management, or report generation. Network telemetry ingestion and external security API integrations are also not implemented.

## Project structure

- `app.py`: Flask routes, API endpoints, and live simulation logic
- `analyzer.py`: CSV validation and event normalization
- `detector.py`: detection rules for suspicious login and auth patterns
- `windows_collector.py`: read-only Windows Security event collection and normalization
- `database.py`: SQLite persistence, schema setup, and alert lifecycle management
- `sample_logs.csv`: synthetic event data for demonstrations and testing
- `templates/`: dashboard UI templates
- `static/`: CSS and JavaScript for the front-end experience
- `test_alert_filters.py`: alert filtering, workflow, simulation, and detector tests
- `test_api_validation.py`: malformed and invalid API request tests
- `test_csv_import.py`: CSV validation, upload limits, and duplicate import tests
- `test_dashboard_metrics.py`: empty and large-dataset dashboard aggregate tests
- `test_database_reliability.py`: foreign-key, alert deduplication, and iterator tests
- `test_frontend_security.py`: malicious-content regression tests
- `test_navigation.py`: navigation-link/view mapping tests
- `test_windows_collector.py`: mocked collector, permission, filtering, and event deduplication tests

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

## Windows Security event collection

On Windows 11, SENTINEL can read local Security log events with the built-in Windows PowerShell `Get-WinEvent` cmdlet. Collection is read-only and limited to event IDs 4624, 4625, 4634, 4648, and 4672. The dashboard starts with a 24-hour lookback and a 500-event limit; repeated records are skipped using the computer name and event record ID.

Use the **Collect now** control for a manual refresh or choose a polling interval in the Windows Security Events section. Event ID, severity, and time-range filters apply to the displayed records. Collection errors remain visible in the dashboard.

Reading the Security log may require running PowerShell or the application with administrator privileges, depending on local Windows policy. A user with the appropriate Security log read permission may not need elevation. SENTINEL does not change auditing settings, modify logs, or alter Windows security policy. It does not collect passwords, tokens, or user documents.

On Linux and other non-Windows systems, the dashboard reports that native Windows collection is unavailable; the existing CSV analysis functionality remains available.

## CSV log import

Use the **Import CSV logs** panel to submit one CSV file containing `timestamp`, `source_ip`, `event_type`, `user`, `status`, and `host` columns. Timestamps must be ISO 8601, IP addresses must be valid IPv4 or IPv6 values, event types must be `login`, `auth`, or `authentication`, and status must be `success` or `failed`. Uploads are processed in memory and limited to 2 MiB and 10,000 records. Re-importing identical rows from the same source skips duplicates.

## Tests

Install the test runner, then run the suite from the project directory with Python 3.11:

```bash
python -m pip install pytest
python -m pytest -q
```

The current verified run completed with **75 passed, 0 failed, 0 skipped** in 59.59 seconds (process exit code 0). Windows event collection tests mock PowerShell responses; this test result does not validate collection against a real Windows Security log. Controlled Windows testing is still required before describing native collection as fully validated.

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
