"""Main Flask application for the SENTINEL SOC dashboard.

This file exposes the alert timeline, status updates and investigation notes.
The dashboard routes render the current alert list and provide lightweight API
endpoints for status changes without leaving the page.
"""

from __future__ import annotations

import csv
import io
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from analyzer import MAX_CSV_RECORDS, load_logs_from_csv, normalise_logs, parse_logs_from_csv
from database import (
    ALLOWED_ALERT_STATUSES,
    add_note,
    get_alerts,
    get_dashboard_metrics,
    get_windows_events,
    init_db,
    insert_alert,
    insert_detection_alert,
    insert_security_events,
    insert_windows_events,
    update_alert_status,
)
from detector import evaluate_events
from windows_collector import (
    WINDOWS_EVENT_IDS,
    WindowsCollectionPermissionError,
    WindowsCollectionUnavailable,
    WindowsEventCollectionError,
    collect_windows_events,
    is_windows_collection_available,
)

app = Flask(__name__, template_folder="templates", static_folder="static")
MAX_CSV_UPLOAD_BYTES = 2 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_CSV_UPLOAD_BYTES + 64 * 1024
app.config["LIVE_MODE"] = False
app.config["SIMULATION_EVENTS"] = []
app.config["WINDOWS_COLLECTION"] = {
    "status": "idle",
    "message": "Windows event collection has not been run yet.",
    "last_collected_at": None,
}

SAMPLE_LOG_PATH = Path(__file__).resolve().parent / "sample_logs.csv"
MAX_NOTE_LENGTH = 4000


def _json_object_payload(allowed_fields: set[str]) -> tuple[Dict[str, Any] | None, Any | None]:
    """Parse a JSON object and reject malformed, non-object, or unexpected input."""
    if not request.is_json:
        return None, (jsonify({"error": "Content-Type must be application/json."}), 415)
    try:
        payload = request.get_json()
    except BadRequest:
        return None, (jsonify({"error": "Request body must contain valid JSON."}), 400)
    if not isinstance(payload, dict):
        return None, (jsonify({"error": "Request body must be a JSON object."}), 400)
    unexpected_fields = set(payload) - allowed_fields
    if unexpected_fields:
        return None, (jsonify({"error": "Request contains unsupported fields."}), 400)
    return payload, None


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return jsonify({"error": "Request exceeds the configured upload size limit."}), 413


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


def _initialise_demo_events() -> None:
    """Populate the in-memory synthetic dataset from the sample CSV."""
    if app.config["SIMULATION_EVENTS"]:
        return
    try:
        sample_events = load_logs_from_csv(SAMPLE_LOG_PATH)
    except FileNotFoundError:
        sample_events = []
    app.config["SIMULATION_EVENTS"] = normalise_logs(sample_events)
    insert_security_events(app.config["SIMULATION_EVENTS"], "demo")


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
    """Summarise alert-specific values for the severity chart."""
    severity_distribution = Counter()
    for alert in alerts:
        severity_distribution[str(alert.get("severity", "LOW")).upper()] += 1

    return {
        "total_alerts": len(alerts),
        "severity_distribution": {
            "LOW": severity_distribution.get("LOW", 0),
            "MEDIUM": severity_distribution.get("MEDIUM", 0),
            "HIGH": severity_distribution.get("HIGH", 0),
        },
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
    summary = get_dashboard_metrics()
    summary.update(_summarise_alerts(filtered_alerts))
    summary["alerts"] = filtered_alerts
    summary["live_mode"] = app.config["LIVE_MODE"]
    return jsonify(summary)


@app.route("/api/windows-events", methods=["GET"])
def windows_events_api():
    """Return locally collected Windows events using optional event filters."""
    event_id_value = request.args.get("event_id", "").strip()
    severity = request.args.get("severity", "").strip().upper()
    if event_id_value:
        try:
            event_id = int(event_id_value)
        except ValueError:
            return jsonify({"error": "Event ID must be an integer."}), 400
        if event_id not in WINDOWS_EVENT_IDS:
            return jsonify({"error": "Unsupported Windows Security event ID."}), 400
    else:
        event_id = None

    if severity and severity not in {"LOW", "MEDIUM", "HIGH"}:
        return jsonify({"error": "Unsupported severity filter."}), 400

    start_raw = str(request.args.get("start", "")).strip()
    start_time = _parse_alert_timestamp(start_raw)
    end_time_raw = str(request.args.get("end", "")).strip()
    end_time = _parse_alert_timestamp(end_time_raw)
    if (start_raw and start_time is None) or (end_time_raw and end_time is None):
        return jsonify({"error": "Time filters must be valid ISO timestamps or dates."}), 400
    if end_time and end_time_raw and "T" not in end_time_raw and " " not in end_time_raw:
        end_time += timedelta(days=1) - timedelta(microseconds=1)
    if start_time and end_time and start_time > end_time:
        return jsonify({"error": "The start time must be earlier than the end time."}), 400

    events = get_windows_events(
        event_id=event_id,
        severity=severity or None,
        start_time=start_time.isoformat().replace("+00:00", "Z") if start_time else None,
        end_time=end_time.isoformat().replace("+00:00", "Z") if end_time else None,
    )
    state = dict(app.config["WINDOWS_COLLECTION"])
    state["available"] = is_windows_collection_available()
    if not state["available"]:
        state["status"] = "unavailable"
        state["message"] = "Native Windows Security event collection is unavailable on this operating system. CSV import remains available."
    return jsonify({"events": events, "collection": state})


@app.route("/api/csv/import", methods=["POST"])
def import_csv_api():
    """Validate and import a bounded CSV file without saving the upload to disk."""
    if set(request.files) != {"file"} or len(request.files.getlist("file")) != 1:
        return jsonify({"error": "Upload exactly one CSV file using the 'file' field."}), 400
    upload = request.files["file"]
    if not upload.filename or Path(upload.filename).suffix.lower() != ".csv":
        return jsonify({"error": "Only files with a .csv extension are accepted."}), 400

    csv_bytes = upload.stream.read(MAX_CSV_UPLOAD_BYTES + 1)
    if len(csv_bytes) > MAX_CSV_UPLOAD_BYTES:
        return jsonify({"error": "CSV files cannot exceed 2 MiB."}), 413

    try:
        text_stream = io.TextIOWrapper(io.BytesIO(csv_bytes), encoding="utf-8-sig", newline="")
        events = parse_logs_from_csv(text_stream, max_records=MAX_CSV_RECORDS)
    except (ValueError, csv.Error, UnicodeDecodeError) as exc:
        return jsonify({"error": str(exc)}), 400

    new_events = insert_security_events(events, "csv")
    findings = evaluate_events(new_events)
    alerts_created = sum(insert_detection_alert(finding)[1] for finding in findings)
    return jsonify(
        {
            "status": "imported",
            "records_received": len(events),
            "events_imported": len(new_events),
            "duplicates": len(events) - len(new_events),
            "alerts_created": alerts_created,
        }
    )


@app.route("/api/windows-events/collect", methods=["POST"])
def collect_windows_events_api():
    """Collect, deduplicate, persist, and analyse a bounded set of Windows events."""
    payload, error_response = _json_object_payload({"lookback_hours", "max_events"})
    if error_response:
        return error_response
    payload = payload or {}
    lookback_hours = payload.get("lookback_hours", 24)
    max_events = payload.get("max_events", 500)
    if isinstance(lookback_hours, bool) or not isinstance(lookback_hours, int) or not 1 <= lookback_hours <= 720:
        return jsonify({"error": "lookback_hours must be an integer from 1 to 720."}), 400
    if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= 5000:
        return jsonify({"error": "max_events must be an integer from 1 to 5000."}), 400

    try:
        collected = collect_windows_events(lookback_hours=lookback_hours, max_events=max_events)
        new_events = insert_windows_events(collected)
        findings = evaluate_events(new_events)
        alerts_created = sum(insert_detection_alert(finding)[1] for finding in findings)

        state = {
            "status": "success",
            "message": f"Collection completed: {len(new_events)} new events saved; {len(collected) - len(new_events)} duplicates skipped.",
            "last_collected_at": _utc_now().isoformat().replace("+00:00", "Z"),
        }
        app.config["WINDOWS_COLLECTION"] = state
        return jsonify(
            {
                **state,
                "available": True,
                "new_events": len(new_events),
                "duplicates": len(collected) - len(new_events),
                "alerts_created": alerts_created,
            }
        )
    except WindowsCollectionUnavailable as exc:
        status_code = 501
        status = "unavailable"
        failure_message = str(exc)
    except WindowsCollectionPermissionError as exc:
        status_code = 403
        status = "permission_denied"
        failure_message = str(exc)
    except (ValueError, WindowsEventCollectionError) as exc:
        status_code = 400 if isinstance(exc, ValueError) else 502
        status = "error"
        failure_message = str(exc)

    state = {
        "status": status,
        "message": failure_message,
        "last_collected_at": app.config["WINDOWS_COLLECTION"].get("last_collected_at"),
    }
    app.config["WINDOWS_COLLECTION"] = state
    return jsonify({**state, "available": is_windows_collection_available()}), status_code


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status_route(alert_id: int):
    """Update the status of an alert and record the timeline event."""
    payload, error_response = _json_object_payload({"status"})
    if error_response:
        return error_response
    payload = payload or {}
    new_status = payload.get("status")

    if not isinstance(new_status, str) or new_status not in ALLOWED_ALERT_STATUSES:
        return jsonify({"error": "Unsupported status value."}), 400

    try:
        alert = update_alert_status(alert_id, new_status)
        return jsonify({"status": "updated", "alert": alert})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/alerts/<int:alert_id>/note", methods=["POST"])
def add_note_route(alert_id: int):
    """Add an investigation note to an alert and return the updated object."""
    payload, error_response = _json_object_payload({"note"})
    if error_response:
        return error_response
    payload = payload or {}
    note_text = payload.get("note")

    if not isinstance(note_text, str) or not note_text.strip():
        return jsonify({"error": "Note must be a non-empty string."}), 400
    note_text = note_text.strip()
    if len(note_text) > MAX_NOTE_LENGTH:
        return jsonify({"error": f"Note cannot exceed {MAX_NOTE_LENGTH} characters."}), 400

    try:
        alert = add_note(alert_id, note_text)
        return jsonify({"status": "saved", "alert": alert})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/live/simulate", methods=["POST"])
def live_simulation_route():
    """Start or stop live demo mode and optionally inject synthetic events."""
    payload, error_response = _json_object_payload({"action"})
    if error_response:
        return error_response
    payload = payload or {}
    action = payload.get("action", "tick")
    if not isinstance(action, str):
        return jsonify({"error": "action must be a string."}), 400
    action = action.strip().lower()

    if action == "start":
        app.config["LIVE_MODE"] = True
        return jsonify({"status": "started", "live_mode": True})

    if action == "stop":
        app.config["LIVE_MODE"] = False
        return jsonify({"status": "stopped", "live_mode": False})

    if action == "tick":
        new_events = _generate_synthetic_events()
        app.config["SIMULATION_EVENTS"].extend(new_events)
        insert_security_events(new_events, "simulation")
        findings = evaluate_events(new_events)
        for item in findings:
            insert_detection_alert(
                {
                    **item,
                    "timestamp": str(item.get("timestamp") or _event_time(0)),
                    "source_ip": str(item.get("source_ip") or "unknown"),
                    "source_host": str(item.get("source_host") or "unknown"),
                    "event_type": str(item.get("event_type") or "login"),
                    "severity": str(item.get("severity") or "MEDIUM").upper(),
                    "status": "Open",
                }
            )

        summary = get_dashboard_metrics()
        summary.update(_summarise_alerts(get_alerts()))
        summary["live_mode"] = app.config["LIVE_MODE"]
        summary["generated_events"] = len(new_events)
        summary["alerts"] = get_alerts()
        return jsonify(summary)

    return jsonify({"error": "Unsupported live simulation action."}), 400


if __name__ == "__main__":
    init_db()
    _initialise_demo_events()
    app.run(debug=True, host="127.0.0.1", port=5000)
