from datetime import datetime, timedelta, timezone

import database
import app as app_module
from app import app


def _event(index, timestamp, status="success", source_ip="203.0.113.10"):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": "login",
        "user": f"user-{index}",
        "status": status,
        "host": "test-host",
    }


def test_dashboard_metrics_are_zero_for_empty_event_store():
    metrics = database.get_dashboard_metrics(datetime(2026, 3, 10, 12, tzinfo=timezone.utc))

    assert metrics["total_events"] == 0
    assert metrics["successful_logins"] == 0
    assert metrics["failed_logins"] == 0
    assert metrics["suspicious_ips"] == 0
    assert len(metrics["trend"]) == 7
    assert all(point["value"] == 0 for point in metrics["trend"])


def test_dashboard_metrics_count_large_dataset_and_seven_utc_dates():
    now = datetime(2026, 3, 10, 12, tzinfo=timezone.utc)
    events = [
        _event(
            index,
            (now - timedelta(days=index % 8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "success" if index % 2 == 0 else "failed",
            f"203.0.113.{index % 10 + 1}",
        )
        for index in range(10_000)
    ]
    database.insert_security_events(events, "csv")

    metrics = database.get_dashboard_metrics(now)

    assert metrics["total_events"] == 10_000
    assert metrics["successful_logins"] == 5_000
    assert metrics["failed_logins"] == 5_000
    assert metrics["suspicious_ips"] == 10
    assert [point["label"] for point in metrics["trend"]] == [
        "2026-03-04", "2026-03-05", "2026-03-06", "2026-03-07",
        "2026-03-08", "2026-03-09", "2026-03-10",
    ]
    assert sum(point["value"] for point in metrics["trend"]) == 8_750


def test_dashboard_api_reports_persisted_event_metrics(monkeypatch):
    monkeypatch.setattr(app_module, "_initialise_demo_events", lambda: None)
    database.insert_security_events(
        [
            _event(1, "2026-03-10T09:00:00Z", "success"),
            _event(2, "2026-03-10T09:01:00Z", "failed"),
        ],
        "csv",
    )

    response = app.test_client().get("/api/dashboard")
    body = response.get_json()

    assert response.status_code == 200
    assert body["total_events"] == 2
    assert body["successful_logins"] == 1
    assert body["failed_logins"] == 1
    assert body["total_alerts"] == len(body["alerts"])