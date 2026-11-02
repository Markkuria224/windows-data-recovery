"""SQLite persistence layer for the SENTINEL dashboard.

This module stores alert metadata, investigation notes and status-change history.
The queries are parameterised to avoid SQL injection and to keep the data model
clear for local SOC operations.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

DB_PATH = Path(__file__).resolve().parent / "security_dashboard.db"
ALLOWED_ALERT_STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection configured for row access."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Create the tables used by the dashboard if they do not already exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                source_host TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                note_text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                previous_status TEXT,
                new_status TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysed_at TEXT NOT NULL,
                total_events INTEGER NOT NULL,
                alert_count INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed'
            )
            """
        )

        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()}
        if "created_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN created_at TEXT")
        if "updated_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN updated_at TEXT")

        connection.execute(
            "UPDATE alerts SET status = 'Open' WHERE status IS NULL OR status = ''"
        )
        connection.execute(
            "UPDATE alerts SET created_at = COALESCE(created_at, timestamp, ?) WHERE created_at IS NULL",
            (utc_now_iso(),),
        )
        connection.execute(
            "UPDATE alerts SET updated_at = COALESCE(updated_at, created_at, timestamp, ?) WHERE updated_at IS NULL",
            (utc_now_iso(),),
        )

        connection.commit()

        if connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0:
            seed_alerts(connection)


def seed_alerts(connection: sqlite3.Connection) -> None:
    """Create a few demonstrator alerts for the UI and learning workflow."""
    now = utc_now_iso()
    sample_alerts = [
        {
            "timestamp": now,
            "source_ip": "203.0.113.55",
            "source_host": "web-01",
            "event_type": "login",
            "severity": "HIGH",
            "reason": "Five failed logins were followed by a successful login within 15 minutes.",
            "status": "Investigating",
        },
        {
            "timestamp": now,
            "source_ip": "198.51.100.31",
            "source_host": "vpn-05",
            "event_type": "login",
            "severity": "MEDIUM",
            "reason": "Successful login occurred during the off-hours window between 01:00 and 05:00.",
            "status": "Open",
        },
    ]
    for alert in sample_alerts:
        insert_alert(connection, alert)


def insert_alert(connection: sqlite3.Connection | None, alert_data: Dict[str, Any]) -> int:
    """Insert an alert and return its generated primary key."""
    if connection is None:
        with get_connection() as connection:
            return insert_alert(connection, alert_data)

    timestamp = str(alert_data.get("timestamp") or utc_now_iso())
    status = str(alert_data.get("status") or "Open").strip()
    if status not in ALLOWED_ALERT_STATUSES:
        status = "Open"

    created_at = utc_now_iso()
    cursor = connection.execute(
        """
        INSERT INTO alerts (timestamp, source_ip, source_host, event_type, severity, reason, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            str(alert_data.get("source_ip") or "unknown").strip() or "unknown",
            str(alert_data.get("source_host") or "unknown").strip() or "unknown",
            str(alert_data.get("event_type") or "login").strip() or "login",
            str(alert_data.get("severity") or "MEDIUM").upper(),
            str(alert_data.get("reason") or "No reason provided").strip(),
            status,
            created_at,
            created_at,
        ),
    )
    alert_id = cursor.lastrowid

    note_text = str(alert_data.get("note") or "").strip()
    if note_text:
        connection.execute(
            "INSERT INTO alert_notes (alert_id, note_text, created_at) VALUES (?, ?, ?)",
            (alert_id, note_text, created_at),
        )

    connection.execute(
        "INSERT INTO alert_status_history (alert_id, previous_status, new_status, changed_at) VALUES (?, ?, ?, ?)",
        (alert_id, None, status, created_at),
    )
    return alert_id


def get_alerts() -> List[Dict[str, Any]]:
    """Return alerts with nested notes and status-change history for the dashboard."""
    with get_connection() as connection:
        alerts = connection.execute(
            "SELECT * FROM alerts ORDER BY updated_at DESC, id DESC"
        ).fetchall()

        result: List[Dict[str, Any]] = []
        for alert in alerts:
            alert_id = alert["id"]
            notes = connection.execute(
                "SELECT id, note_text, created_at FROM alert_notes WHERE alert_id = ? ORDER BY created_at DESC",
                (alert_id,),
            ).fetchall()
            history = connection.execute(
                "SELECT id, previous_status, new_status, changed_at FROM alert_status_history WHERE alert_id = ? ORDER BY changed_at DESC",
                (alert_id,),
            ).fetchall()

            result.append(
                {
                    "id": alert["id"],
                    "timestamp": alert["timestamp"],
                    "source_ip": alert["source_ip"],
                    "source_host": alert["source_host"],
                    "event_type": alert["event_type"],
                    "severity": alert["severity"],
                    "reason": alert["reason"],
                    "status": alert["status"],
                    "created_at": alert["created_at"],
                    "updated_at": alert["updated_at"],
                    "notes": [dict(note) for note in notes],
                    "history": [dict(item) for item in history],
                }
            )

    return result


def add_note(alert_id: int, note_text: str) -> Dict[str, Any]:
    """Persist a new investigation note and refresh the alert timestamp."""
    cleaned_note = str(note_text).strip()
    if not cleaned_note:
        raise ValueError("A note cannot be empty.")

    timestamp = utc_now_iso()
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO alert_notes (alert_id, note_text, created_at) VALUES (?, ?, ?)",
            (alert_id, cleaned_note, timestamp),
        )
        connection.execute(
            "UPDATE alerts SET updated_at = ? WHERE id = ?",
            (timestamp, alert_id),
        )
        connection.commit()

    return get_alert(alert_id)


def update_alert_status(alert_id: int, new_status: str) -> Dict[str, Any]:
    """Update an alert status with a valid transition and record the timeline entry."""
    status = str(new_status).strip()
    if status not in ALLOWED_ALERT_STATUSES:
        raise ValueError(f"Unsupported alert status: {new_status}")

    with get_connection() as connection:
        alert = connection.execute(
            "SELECT status FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert is None:
            raise ValueError(f"Alert {alert_id} does not exist.")

        previous_status = alert["status"]
        if previous_status == status:
            return get_alert(alert_id)

        timestamp = utc_now_iso()
        connection.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, timestamp, alert_id),
        )
        connection.execute(
            "INSERT INTO alert_status_history (alert_id, previous_status, new_status, changed_at) VALUES (?, ?, ?, ?)",
            (alert_id, previous_status, status, timestamp),
        )
        connection.commit()

    return get_alert(alert_id)


def get_alert(alert_id: int) -> Dict[str, Any]:
    """Fetch a single alert with notes and history for API responses."""
    alerts = get_alerts()
    for alert in alerts:
        if alert["id"] == alert_id:
            return alert
    raise ValueError(f"Alert {alert_id} not found.")
