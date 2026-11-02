"""Main Flask application for the SENTINEL SOC dashboard.

This file exposes the alert timeline, status updates and investigation notes.
The dashboard routes render the current alert list and provide lightweight API
endpoints for status changes without leaving the page.
"""

from __future__ import annotations

import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template, request

from analyzer import load_logs_from_csv, normalise_logs
from database import ALLOWED_ALERT_STATUSES, add_note, get_alerts, init_db, insert_alert, update_alert_status
from detector import evaluate_events

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["LIVE_MODE"] = False
app.config["SIMULATION_EVENTS"] = []

SAMPLE_LOG_PATH = Path(__file__).resolve().parent / "sample_logs.csv"


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def _event_time(delta_minutes: int = 0) -> str:
    """Create an ISO timestamp relative to the current time."""
    timestamp = _utc_now() + timedelta(minutes=delta_minutes)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_synthetic_events() -> List[Dict[str, Any]]:
    """Create 3-8 fictional log events for live demo purposes only."""
    users = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
        "ivan", "julia", "kevin", "laura", "mario", "nina", "olivia", "paul",
    ]
    hosts = ["web-01", "web-02", "vpn-05", "mail-02", "dc-01", "db-04"]
    source_ips = [
        "198.51.100.12", "203.0.113.28", "10.0.0.33", "172.16.8.19",
        "192.168.90.8", "203.0.113.77", "198.51.100.44", "10.0.0.52",
    ]
    events: List[Dict[str, Any]] = []
    count = random.randint(3, 8)

    for _ in range(count):
        timestamp = _event_time(random.randint(0, 30))
        source_ip = random.choice(source_ips)
        user = random.choice(users)
        status = random.choice(["success", "failed"])
        event_type = "login"
        host = random.choice(hosts)
        events.append(
            {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "event_type": event_type,
                "user": user,
                "status": status,
                "host": host,
            }
        )

    return events


def _summarise_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the dashboard metrics from a list of events."""
    total_events = len(events)
    successful = sum(1 for event in events if str(event.get("status", "")).lower() == "success")
    failed = sum(1 for event in events if str(event.get("status", "")).lower() == "failed")

    counts_by_ip = Counter(str(event.get("source_ip", "")).strip() for event in events if str(event.get("source_ip", "")).strip())
    suspicious_ips = sum(1 for count in counts_by_ip.values() if count >= 3)

    severity_distribution = Counter()
    for alert in get_alerts():
        severity_distribution[str(alert.get("severity", "LOW")).upper()] += 1

    last_7_points = []
    for index in range(7):
        point_time = _utc_now() - timedelta(days=6 - index)
        label = point_time.strftime("%a")
        last_7_points.append({"label": label, "value": 0})

    for event in events:
        timestamp = datetime.strptime(str(event.get("timestamp", "")).replace("Z", "+00:00"), "%Y-%m-%dT%H:%M:%S%z")
        delta_days = (datetime.now(timezone.utc) - timestamp).days
        if 0 <= delta_days < 7:
            for point in last_7_points:
                if point["label"] == timestamp.strftime("%a"):
                    point["value"] += 1
                    break

    return {
        "total_events": total_events,
        "successful_logins": successful,
        "failed_logins": failed,
        "suspicious_ips": suspicious_ips,
        "severity_distribution": {
            "LOW": severity_distribution.get("LOW", 0),
            "MEDIUM": severity_distribution.get("MEDIUM", 0),
            "HIGH": severity_distribution.get("HIGH", 0),
        },
        "trend": last_7_points,
    }


def _initialise_demo_events() -> None:
    """Populate the in-memory synthetic dataset from the sample CSV."""
    if app.config["SIMULATION_EVENTS"]:
        return
    try:
        sample_events = load_logs_from_csv(SAMPLE_LOG_PATH)
    except FileNotFoundError:
        sample_events = []
    app.config["SIMULATION_EVENTS"] = normalise_logs(sample_events)


def _normalise_datetime(value: datetime) -> datetime:
    """Ensure a datetime value is timezone-aware in UTC for comparisons."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_alert_timestamp(value: Any) -> datetime | None:
    """Convert alert timestamps into datetime objects for date-range checks."""
    if value in (None, ""):
        return None

    timestamp = str(value).strip()
    if not timestamp:
        return None

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return _normalise_datetime(parsed)
    except ValueError:
        try:
            parsed = datetime.strptime(timestamp, "%Y-%m-%d")
            return _normalise_datetime(parsed)
        except ValueError:
            return None


def _build_alert_filters() -> Dict[str, Any]:
    """Normalise query-string filters from the dashboard into a consistent dict."""
    severity_values = [value.strip().upper() for value in request.args.getlist("severity") if value and value.strip()]
    status_values = [value.strip() for value in request.args.getlist("status") if value and value.strip()]
    source_ip = str(request.args.get("source_ip", "")).strip()
    date_from = str(request.args.get("date_from", "")).strip()
    date_to = str(request.args.get("date_to", "")).strip()

    return {
        "severity": severity_values,
        "status": status_values,
        "source_ip": source_ip,
        "date_from": date_from,
        "date_to": date_to,
    }


def _filter_alerts(alerts: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply all selected alert filters using AND logic."""
    severity_filters = {item.upper() for item in filters.get("severity", [])}
    status_filters = {item for item in filters.get("status", [])}
    source_ip_filter = str(filters.get("source_ip") or "").lower().strip()

    date_from_raw = str(filters.get("date_from") or "").strip()
    date_to_raw = str(filters.get("date_to") or "").strip()
    date_from = _parse_alert_timestamp(date_from_raw)
    date_to = _parse_alert_timestamp(date_to_raw)
    if date_to and date_to_raw and "T" not in date_to_raw and " " not in date_to_raw:
        date_to = date_to + timedelta(days=1) - timedelta(microseconds=1)

    filtered: List[Dict[str, Any]] = []
    for alert in alerts:
        if severity_filters and str(alert.get("severity", "")).upper() not in severity_filters:
            continue

        if status_filters and str(alert.get("status", "")).strip() not in status_filters:
            continue

        if source_ip_filter and source_ip_filter not in str(alert.get("source_ip", "")).lower():
            continue

        alert_time = _parse_alert_timestamp(alert.get("timestamp"))
        if date_from and (alert_time is None or alert_time < date_from):
            continue

        if date_to and (alert_time is None or alert_time > date_to):
            continue

        filtered.append(alert)

    return filtered


def _summarise_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarise a filtered set of alerts for cards and charts."""
    severity_distribution = Counter()
    for alert in alerts:
        severity_distribution[str(alert.get("severity", "LOW")).upper()] += 1

    last_7_points = []
    for index in range(7):
        point_time = _utc_now() - timedelta(days=6 - index)
        last_7_points.append({"label": point_time.strftime("%a"), "value": 0})

    for alert in alerts:
        timestamp = _parse_alert_timestamp(alert.get("timestamp"))
        if timestamp is None:
            continue
        for point in last_7_points:
            label = timestamp.strftime("%a")
            if point["label"] == label:
                point["value"] += 1
                break

    return {
        "total_events": len(alerts),
        "successful_logins": 0,
        "failed_logins": 0,
        "suspicious_ips": len({str(alert.get("source_ip", "")).strip() for alert in alerts if str(alert.get("source_ip", "")).strip()}),
        "severity_distribution": {
            "LOW": severity_distribution.get("LOW", 0),
            "MEDIUM": severity_distribution.get("MEDIUM", 0),
            "HIGH": severity_distribution.get("HIGH", 0),
        },
        "trend": last_7_points,
    }


@app.route("/")
def index():
    """Render the main dashboard page with all current alerts."""
    _initialise_demo_events()
    return render_template("index.html", alerts=get_alerts())


@app.route("/health")
def health_check():
    """Return a simple health response for local validation."""
    return jsonify({"status": "ok", "project": "SENTINEL"})


@app.route("/api/alerts")
def alert_api():
    """Return alerts and their notes/history as JSON for the frontend."""
    filters = _build_alert_filters()
    alerts = _filter_alerts(get_alerts(), filters)
    return jsonify({"alerts": alerts})


@app.route("/api/dashboard")
def dashboard_api():
    """Return filtered summary values for cards and charts without a page reload."""
    _initialise_demo_events()
    filters = _build_alert_filters()
    filtered_alerts = _filter_alerts(get_alerts(), filters)
    summary = _summarise_alerts(filtered_alerts)
    summary["alerts"] = filtered_alerts
    summary["live_mode"] = app.config["LIVE_MODE"]
    return jsonify(summary)


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status_route(alert_id: int):
    """Update the status of an alert and record the timeline event."""
    payload = request.get_json(silent=True) or {}
    new_status = str(payload.get("status", "")).strip()

    if new_status not in ALLOWED_ALERT_STATUSES:
        return jsonify({"error": "Unsupported status value."}), 400

    try:
        alert = update_alert_status(alert_id, new_status)
        return jsonify({"status": "updated", "alert": alert})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/alerts/<int:alert_id>/note", methods=["POST"])
def add_note_route(alert_id: int):
    """Add an investigation note to an alert and return the updated object."""
    payload = request.get_json(silent=True) or {}
    note_text = str(payload.get("note", "")).strip()

    if not note_text:
        return jsonify({"error": "Note cannot be empty."}), 400

    try:
        alert = add_note(alert_id, note_text)
        return jsonify({"status": "saved", "alert": alert})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/live/simulate", methods=["POST"])
def live_simulation_route():
    """Start or stop live demo mode and optionally inject synthetic events."""
    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action", "tick")).strip().lower()

    if action == "start":
        app.config["LIVE_MODE"] = True
        return jsonify({"status": "started", "live_mode": True})

    if action == "stop":
        app.config["LIVE_MODE"] = False
        return jsonify({"status": "stopped", "live_mode": False})

    if action == "tick":
        new_events = _generate_synthetic_events()
        app.config["SIMULATION_EVENTS"].extend(new_events)
        findings = evaluate_events(new_events)
        for item in findings:
            insert_alert(
                None,
                {
                    "timestamp": str(item.get("timestamp") or _event_time(0)),
                    "source_ip": str(item.get("source_ip") or "unknown"),
                    "source_host": str(item.get("source_host") or "unknown"),
                    "event_type": str(item.get("event_type") or "login"),
                    "severity": str(item.get("severity") or "MEDIUM").upper(),
                    "reason": str(item.get("reason") or "Synthetic detection trigger"),
                    "status": "Open",
                },
            )

        summary = _summarise_events(app.config["SIMULATION_EVENTS"])
        summary["live_mode"] = app.config["LIVE_MODE"]
        summary["generated_events"] = len(new_events)
        summary["alerts"] = get_alerts()
        return jsonify(summary)

    return jsonify({"error": "Unsupported live simulation action."}), 400


if __name__ == "__main__":
    init_db()
    _initialise_demo_events()
    app.run(debug=True, host="127.0.0.1", port=5000)
