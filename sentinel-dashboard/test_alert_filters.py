from app import app
from database import insert_alert
from detector import detect_repeated_failed_logins


def _insert_test_alert(**overrides):
    payload = {
        "timestamp": "2024-02-15T12:00:00Z",
        "source_ip": "198.51.100.77",
        "source_host": "web-03",
        "event_type": "login",
        "severity": "HIGH",
        "reason": "Test signal for filtering",
        "status": "Open",
    }
    payload.update(overrides)
    return insert_alert(None, payload)


def test_alerts_filter_combines_severity_status_ip_and_dates():
    alert_id = _insert_test_alert(
        timestamp="2024-02-20T09:30:00Z",
        source_ip="203.0.113.88",
        severity="HIGH",
        status="Investigating",
    )
    _insert_test_alert(
        timestamp="2024-02-20T09:45:00Z",
        source_ip="203.0.113.88",
        severity="LOW",
        status="Open",
    )

    client = app.test_client()
    response = client.get(
        "/api/alerts",
        query_string={
            "severity": ["HIGH", "MEDIUM"],
            "status": ["Investigating", "Open"],
            "source_ip": "203.0.113.88",
            "date_from": "2024-02-20",
            "date_to": "2024-02-21",
        },
    )

    assert response.status_code == 200
    alerts = response.get_json()["alerts"]
    assert any(alert["id"] == alert_id for alert in alerts)
    assert all(alert["severity"] in {"HIGH", "MEDIUM"} for alert in alerts)
    assert all(alert["status"] in {"Investigating", "Open"} for alert in alerts)
    assert all("203.0.113.88" in alert["source_ip"] for alert in alerts)


def test_dashboard_summary_filters_alerts_for_chart_updates():
    _insert_test_alert(
        timestamp="2024-02-18T08:00:00Z",
        source_ip="10.10.10.10",
        severity="MEDIUM",
        status="Resolved",
    )
    _insert_test_alert(
        timestamp="2024-02-18T10:00:00Z",
        source_ip="10.10.10.10",
        severity="HIGH",
        status="Resolved",
    )

    client = app.test_client()
    response = client.get(
        "/api/dashboard",
        query_string={
            "status": ["Resolved"],
            "source_ip": "10.10.10.10",
            "date_from": "2024-02-18",
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["total_events"] >= 2
    assert body["severity_distribution"]["HIGH"] >= 1
    assert body["severity_distribution"]["MEDIUM"] >= 1


def test_health_endpoint_reports_project_status():
    client = app.test_client()
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert response.get_json()["project"] == "SENTINEL"


def test_status_and_note_routes_update_alert_workflow():
    alert_id = _insert_test_alert(
        timestamp="2024-03-01T11:00:00Z",
        source_ip="198.51.100.90",
        severity="MEDIUM",
        status="Open",
    )

    client = app.test_client()
    status_response = client.post(
        f"/api/alerts/{alert_id}/status",
        json={"status": "Investigating"},
    )
    note_response = client.post(
        f"/api/alerts/{alert_id}/note",
        json={"note": "Validated against VPN logs and suspicious geolocation."},
    )

    assert status_response.status_code == 200
    assert status_response.get_json()["alert"]["status"] == "Investigating"
    assert note_response.status_code == 200
    assert any(
        "Validated against VPN logs" in note["note_text"]
        for note in note_response.get_json()["alert"]["notes"]
    )


def test_live_simulation_tick_generates_events_and_alerts():
    client = app.test_client()
    response = client.post("/api/live/simulate", json={"action": "tick"})

    assert response.status_code == 200
    body = response.get_json()
    assert body["generated_events"] >= 1
    assert isinstance(body["alerts"], list)
    assert "live_mode" in body


def test_detector_flags_repeated_failed_login_pattern():
    events = [
        {
            "timestamp": "2024-04-01T01:00:00Z",
            "source_ip": "203.0.113.14",
            "event_type": "login",
            "status": "failed",
            "user": "alice",
            "host": "vpn-02",
        },
        {
            "timestamp": "2024-04-01T01:01:00Z",
            "source_ip": "203.0.113.14",
            "event_type": "login",
            "status": "failed",
            "user": "bob",
            "host": "vpn-02",
        },
        {
            "timestamp": "2024-04-01T01:02:00Z",
            "source_ip": "203.0.113.14",
            "event_type": "login",
            "status": "failed",
            "user": "carol",
            "host": "vpn-02",
        },
        {
            "timestamp": "2024-04-01T01:03:00Z",
            "source_ip": "203.0.113.14",
            "event_type": "login",
            "status": "failed",
            "user": "dave",
            "host": "vpn-02",
        },
        {
            "timestamp": "2024-04-01T01:04:00Z",
            "source_ip": "203.0.113.14",
            "event_type": "login",
            "status": "failed",
            "user": "erin",
            "host": "vpn-02",
        },
    ]

    findings = detect_repeated_failed_logins(events)

    assert findings
    assert any(item["severity"] == "HIGH" for item in findings)
    assert "203.0.113.14" in findings[0]["source_ip"]
