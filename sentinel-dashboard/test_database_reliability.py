from datetime import datetime, timedelta, timezone

import pytest

import database
from detector import evaluate_events


def _finding(**overrides):
    finding = {
        "timestamp": "2026-03-10T12:00:00Z",
        "source_ip": "203.0.113.8",
        "source_host": "vpn-test",
        "event_type": "login",
        "severity": "HIGH",
        "reason": "Repeated failed authentication",
        "status": "Open",
        "rule_id": "repeated_failed_logins",
    }
    finding.update(overrides)
    return finding


def test_every_database_connection_enforces_foreign_keys():
    with database.get_connection() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(database.sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO alert_notes (alert_id, note_text, created_at) VALUES (?, ?, ?)",
                (999999, "orphan", database.utc_now_iso()),
            )


def test_matching_active_detection_updates_existing_incident():
    alert_id, created = database.insert_detection_alert(_finding())
    repeated_id, repeated_created = database.insert_detection_alert(
        _finding(reason="Repeated again")
    )

    alert = database.get_alert(alert_id)
    assert created is True
    assert repeated_created is False
    assert repeated_id == alert_id
    assert alert["occurrence_count"] == 2
    assert alert["reason"] == "Repeated again"
    assert alert["last_seen_at"] >= alert["created_at"]


def test_detection_after_window_or_resolution_creates_new_incident():
    first_id, _ = database.insert_detection_alert(_finding())
    with database.get_connection() as connection:
        old_created_at = (datetime.now(timezone.utc) - timedelta(minutes=16)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        connection.execute(
            "UPDATE alerts SET created_at = ? WHERE id = ?", (old_created_at, first_id)
        )
    aged_id, aged_created = database.insert_detection_alert(_finding())

    assert aged_created is True
    assert aged_id != first_id

    database.update_alert_status(aged_id, "Resolved")
    resolved_id, resolved_created = database.insert_detection_alert(_finding())
    assert resolved_created is True
    assert resolved_id != aged_id


def test_detection_pipeline_accepts_one_shot_iterators():
    events = [
        {
            "timestamp": f"2026-03-10T12:0{index}:00Z",
            "source_ip": "203.0.113.8",
            "event_type": "login",
            "status": "failed",
            "user": f"user-{index}",
            "host": "vpn-test",
        }
        for index in range(6)
    ]

    assert evaluate_events(iter(events)) == evaluate_events(events)