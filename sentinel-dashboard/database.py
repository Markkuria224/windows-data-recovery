"""SQLite persistence layer for the SENTINEL dashboard.

This module stores alert metadata, investigation notes and status-change history.
The queries are parameterised to avoid SQL injection and to keep the data model
clear for local SOC operations.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
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
    connection.execute("PRAGMA foreign_keys = ON")
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
                updated_at TEXT,
                rule_id TEXT,
                last_seen_at TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1
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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS windows_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_record_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                computer_name TEXT NOT NULL,
                source_ip TEXT NOT NULL DEFAULT '',
                logon_type TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                UNIQUE(computer_name, event_record_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL,
                UNIQUE(source, timestamp, source_ip, event_type, username, status, host)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip)"
        )

        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()}
        if "created_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN created_at TEXT")
        if "updated_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN updated_at TEXT")
        if "rule_id" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN rule_id TEXT")
        if "last_seen_at" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN last_seen_at TEXT")
        if "occurrence_count" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1")

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
        connection.execute(
            "UPDATE alerts SET last_seen_at = COALESCE(last_seen_at, updated_at, timestamp, ?) WHERE last_seen_at IS NULL",
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
    """Insert an alert, or update a matching active detection within 15 minutes."""
    if connection is None:
        with get_connection() as connection:
            alert_id, _ = _insert_or_update_alert(connection, alert_data)
            return alert_id

    alert_id, _ = _insert_or_update_alert(connection, alert_data)
    return alert_id


def insert_detection_alert(alert_data: Dict[str, Any]) -> tuple[int, bool]:
    """Upsert a detector finding and report whether it created a new incident."""
    with get_connection() as connection:
        return _insert_or_update_alert(connection, alert_data)


def _insert_or_update_alert(
    connection: sqlite3.Connection,
    alert_data: Dict[str, Any],
) -> tuple[int, bool]:
    timestamp = str(alert_data.get("timestamp") or utc_now_iso())
    status = str(alert_data.get("status") or "Open").strip()
    if status not in ALLOWED_ALERT_STATUSES:
        status = "Open"

    created_at = utc_now_iso()
    source_ip = str(alert_data.get("source_ip") or "unknown").strip() or "unknown"
    source_host = str(alert_data.get("source_host") or "unknown").strip() or "unknown"
    rule_id = str(alert_data.get("rule_id") or "").strip() or None
    reason = str(alert_data.get("reason") or "No reason provided").strip()

    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    if rule_id:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        existing = connection.execute(
            """
            SELECT id FROM alerts
            WHERE rule_id = ? AND source_ip = ? AND source_host = ?
              AND status IN ('Open', 'Investigating') AND created_at >= ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (rule_id, source_ip, source_host, cutoff),
        ).fetchone()
        if existing is not None:
            alert_id = existing["id"]
            connection.execute(
                "UPDATE alerts SET reason = ?, updated_at = ?, last_seen_at = ?, occurrence_count = occurrence_count + 1 WHERE id = ?",
                (reason, created_at, created_at, alert_id),
            )
            return alert_id, False

    cursor = connection.execute(
        """
        INSERT INTO alerts (
            timestamp, source_ip, source_host, event_type, severity, reason,
            status, created_at, updated_at, rule_id, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            source_ip,
            source_host,
            str(alert_data.get("event_type") or "login").strip() or "login",
            str(alert_data.get("severity") or "MEDIUM").upper(),
            reason,
            status,
            created_at,
            created_at,
            rule_id,
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
    return alert_id, True


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
                    "rule_id": alert["rule_id"],
                    "last_seen_at": alert["last_seen_at"],
                    "occurrence_count": alert["occurrence_count"],
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
        if connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise ValueError(f"Alert {alert_id} does not exist.")
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


def _insert_security_event(
    connection: sqlite3.Connection,
    event: Dict[str, Any],
    source: str,
) -> bool:
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO security_events (
            timestamp, source_ip, event_type, username, status, host, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(event["timestamp"]),
            str(event.get("source_ip") or ""),
            str(event["event_type"]),
            str(event.get("user") or event.get("username") or ""),
            str(event["status"]).lower(),
            str(event.get("host") or event.get("computer_name") or ""),
            source,
        ),
    )
    return cursor.rowcount == 1


def insert_security_events(events: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
    """Persist normalized events, skipping exact duplicates from the same source."""
    if source not in {"csv", "windows", "demo", "simulation"}:
        raise ValueError("Unsupported security event source.")

    inserted: List[Dict[str, Any]] = []
    with get_connection() as connection:
        for event in events:
            if _insert_security_event(connection, event, source):
                inserted.append(event)
    return inserted


def get_dashboard_metrics(now: datetime | None = None) -> Dict[str, Any]:
    """Aggregate stored events; trend covers today and the prior six UTC dates."""
    current_time = now or datetime.now(timezone.utc)
    today = current_time.astimezone(timezone.utc).date()
    first_day = today - timedelta(days=6)
    with get_connection() as connection:
        totals = connection.execute(
            """
            SELECT COUNT(*) AS total_events,
                   SUM(CASE WHEN lower(status) = 'success' THEN 1 ELSE 0 END) AS successful_logins,
                   SUM(CASE WHEN lower(status) = 'failed' THEN 1 ELSE 0 END) AS failed_logins
            FROM security_events
            """
        ).fetchone()
        suspicious_ips = connection.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT source_ip
                FROM security_events
                WHERE source_ip != ''
                GROUP BY source_ip
                HAVING COUNT(*) >= 3
            )
            """
        ).fetchone()[0]
        daily_counts = connection.execute(
            """
            SELECT date(timestamp) AS event_date, COUNT(*) AS event_count
            FROM security_events
            WHERE date(timestamp) BETWEEN ? AND ?
            GROUP BY date(timestamp)
            """,
            (first_day.isoformat(), today.isoformat()),
        ).fetchall()

    counts_by_date = {row["event_date"]: row["event_count"] for row in daily_counts}
    trend = [
        {
            "label": (first_day + timedelta(days=offset)).isoformat(),
            "value": counts_by_date.get((first_day + timedelta(days=offset)).isoformat(), 0),
        }
        for offset in range(7)
    ]
    return {
        "total_events": totals["total_events"],
        "successful_logins": totals["successful_logins"] or 0,
        "failed_logins": totals["failed_logins"] or 0,
        "suspicious_ips": suspicious_ips,
        "trend": trend,
    }


def insert_windows_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Store only unseen Windows records and return the newly inserted events."""
    inserted: List[Dict[str, Any]] = []
    with get_connection() as connection:
        for event in events:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO windows_events (
                    event_record_id, event_id, timestamp, username, computer_name,
                    source_ip, logon_type, description, severity, event_type,
                    status, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(event["event_record_id"]),
                    int(event["event_id"]),
                    str(event["timestamp"]),
                    str(event.get("username", "")),
                    str(event.get("computer_name") or event.get("host") or "unknown"),
                    str(event.get("source_ip", "")),
                    str(event.get("logon_type", "")),
                    str(event.get("description", "")),
                    str(event["severity"]).upper(),
                    str(event["event_type"]),
                    str(event["status"]),
                    utc_now_iso(),
                ),
            )
            if cursor.rowcount == 1:
                _insert_security_event(connection, event, "windows")
                inserted.append(event)
    return inserted


def get_windows_events(
    event_id: int | None = None,
    severity: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 250,
) -> List[Dict[str, Any]]:
    """Return locally collected Windows events with parameterized filters."""
    conditions: List[str] = []
    parameters: List[Any] = []
    if event_id is not None:
        conditions.append("event_id = ?")
        parameters.append(event_id)
    if severity:
        conditions.append("severity = ?")
        parameters.append(severity.upper())
    if start_time:
        conditions.append("timestamp >= ?")
        parameters.append(start_time)
    if end_time:
        conditions.append("timestamp <= ?")
        parameters.append(end_time)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    safe_limit = max(1, min(int(limit), 1000))
    with get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT event_record_id, event_id, timestamp, username, computer_name,
                   source_ip, logon_type, description, severity, event_type, status
            FROM windows_events {where_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (*parameters, safe_limit),
        ).fetchall()
    return [dict(row) for row in rows]
