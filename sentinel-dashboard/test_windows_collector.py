import json
import subprocess

import pytest

import app as app_module
import database
import windows_collector
from windows_collector import (
    WindowsCollectionPermissionError,
    WindowsCollectionUnavailable,
    collect_windows_events,
    normalise_windows_event,
)


def _event_record(**overrides):
    record = {
        "event_id": 4625,
        "record_id": 1234,
        "timestamp": "2025-02-01T10:30:00Z",
        "username": "analyst",
        "computer_name": "WORKSTATION-01",
        "source_ip": "203.0.113.12",
        "logon_type": "3",
        "description": "An account failed to log on.",
    }
    record.update(overrides)
    return record


def test_normalise_windows_event_maps_fields_and_sanitises_values():
    event = normalise_windows_event(
        _event_record(username=" analyst\n", source_ip="not-an-ip", description="bad\x00 text")
    )

    assert event["event_id"] == 4625
    assert event["event_record_id"] == 1234
    assert event["user"] == "analyst"
    assert event["host"] == "WORKSTATION-01"
    assert event["source_ip"] == ""
    assert event["status"] == "failed"
    assert event["severity"] == "MEDIUM"
    assert event["description"] == "bad text"


def test_normalise_windows_event_rejects_unsupported_ids_and_timestamps():
    with pytest.raises(ValueError, match="Unsupported"):
        normalise_windows_event(_event_record(event_id=9999))
    with pytest.raises(ValueError, match="timestamp"):
        normalise_windows_event(_event_record(timestamp="invalid"))


@pytest.mark.parametrize(
    ("event_id", "event_type", "status", "severity"),
    [
        (4624, "windows_login", "success", "LOW"),
        (4625, "windows_login", "failed", "MEDIUM"),
        (4634, "windows_logoff", "observed", "LOW"),
        (4648, "windows_authentication", "observed", "MEDIUM"),
        (4672, "windows_privilege", "observed", "HIGH"),
    ],
)
def test_supported_event_ids_map_to_sentinel_event_types(event_id, event_type, status, severity):
    event = normalise_windows_event(_event_record(event_id=event_id))

    assert event["event_type"] == event_type
    assert event["status"] == status
    assert event["severity"] == severity


def test_collection_is_explicitly_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr(windows_collector.platform, "system", lambda: "Linux")

    with pytest.raises(WindowsCollectionUnavailable, match="CSV import remains available"):
        collect_windows_events()


def test_collector_parses_mocked_powershell_events(monkeypatch):
    monkeypatch.setattr(windows_collector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows_collector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(_event_record()), stderr=""
        ),
    )

    events = collect_windows_events(lookback_hours=12, max_events=100)

    assert len(events) == 1
    assert events[0]["event_record_id"] == 1234
    assert events[0]["event_type"] == "windows_login"


def test_collector_reports_security_log_permission_errors(monkeypatch):
    monkeypatch.setattr(windows_collector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows_collector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, stdout="", stderr="Access is denied"
        ),
    )

    with pytest.raises(WindowsCollectionPermissionError, match="elevated PowerShell"):
        collect_windows_events()


def test_empty_windows_log_query_returns_successful_empty_list(monkeypatch):
    monkeypatch.setattr(windows_collector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows_collector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout="[]", stderr=""),
    )

    assert collect_windows_events() == []


def test_windows_event_storage_deduplicates_and_filters(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "events.sqlite")
    database.init_db()
    event = normalise_windows_event(_event_record(computer_name="TEST-HOST"))

    first_insert = database.insert_windows_events([event])
    second_insert = database.insert_windows_events([event])
    filtered_events = database.get_windows_events(event_id=4625, severity="MEDIUM")

    assert len(first_insert) == 1
    assert second_insert == []
    assert [item["event_record_id"] for item in filtered_events] == [1234]


def test_collection_api_returns_success_counts(monkeypatch):
    event = normalise_windows_event(_event_record(computer_name="API-TEST-HOST", record_id=948271))
    monkeypatch.setattr(app_module, "collect_windows_events", lambda **kwargs: [event])
    monkeypatch.setattr(app_module, "insert_windows_events", lambda events: events)

    response = app_module.app.test_client().post("/api/windows-events/collect", json={})

    assert response.status_code == 200
    assert response.get_json()["new_events"] == 1
    assert response.get_json()["status"] == "success"


def test_collection_api_reports_linux_unavailable(monkeypatch):
    def unavailable(**kwargs):
        raise WindowsCollectionUnavailable("CSV import remains available.")

    monkeypatch.setattr(app_module, "collect_windows_events", unavailable)
    response = app_module.app.test_client().post("/api/windows-events/collect", json={})

    assert response.status_code == 501
    assert response.get_json()["status"] == "unavailable"
    assert "CSV import remains available" in response.get_json()["message"]


def test_collection_api_reports_permission_denied(monkeypatch):
    def permission_denied(**kwargs):
        raise WindowsCollectionPermissionError("Access to the Windows Security log was denied.")

    monkeypatch.setattr(app_module, "collect_windows_events", permission_denied)
    response = app_module.app.test_client().post("/api/windows-events/collect", json={})

    assert response.status_code == 403
    assert response.get_json()["status"] == "permission_denied"
    assert "denied" in response.get_json()["message"]


def test_windows_events_api_validates_filters():
    response = app_module.app.test_client().get("/api/windows-events?event_id=9999")

    assert response.status_code == 400
    assert "Unsupported" in response.get_json()["error"]


def test_windows_events_api_filters_by_event_id_time_and_severity(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api-events.sqlite")
    database.init_db()
    database.insert_windows_events(
        [
            normalise_windows_event(
                _event_record(record_id=55501, computer_name="FILTER-HOST", timestamp="2025-02-01T10:30:00Z")
            ),
            normalise_windows_event(
                _event_record(event_id=4624, record_id=55502, computer_name="FILTER-HOST", timestamp="2025-02-01T11:30:00Z")
            ),
        ]
    )

    response = app_module.app.test_client().get(
        "/api/windows-events",
        query_string={
            "event_id": "4625",
            "severity": "MEDIUM",
            "start": "2025-02-01T10:00:00Z",
            "end": "2025-02-01T11:00:00Z",
        },
    )

    assert response.status_code == 200
    events = response.get_json()["events"]
    assert [event["event_record_id"] for event in events] == [55501]


def test_windows_events_api_rejects_invalid_time_range():
    response = app_module.app.test_client().get(
        "/api/windows-events?start=not-a-time"
    )

    assert response.status_code == 400
    assert "valid ISO timestamps" in response.get_json()["error"]