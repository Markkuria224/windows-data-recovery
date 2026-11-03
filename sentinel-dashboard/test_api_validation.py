import pytest

from app import app


@pytest.mark.parametrize(
    "path",
    [
        "/api/windows-events/collect",
        "/api/alerts/1/status",
        "/api/alerts/1/note",
        "/api/live/simulate",
    ],
)
@pytest.mark.parametrize("payload", [["unexpected"], None])
def test_post_routes_reject_non_object_json(path, payload):
    client = app.test_client()
    if payload is None:
        response = client.post(path, data="null", content_type="application/json")
    else:
        response = client.post(path, json=payload)

    assert response.status_code == 400
    assert "JSON object" in response.get_json()["error"]


def test_json_routes_reject_malformed_json_and_wrong_content_type():
    client = app.test_client()
    malformed = client.post("/api/live/simulate", data="{", content_type="application/json")
    unsupported = client.post("/api/live/simulate", data="{}", content_type="text/plain")

    assert malformed.status_code == 400
    assert unsupported.status_code == 415


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/windows-events/collect", {"unexpected": True}),
        ("/api/alerts/1/status", {"status": "Open", "unexpected": True}),
        ("/api/alerts/1/note", {"note": "case note", "unexpected": True}),
        ("/api/live/simulate", {"action": "start", "unexpected": True}),
    ],
)
def test_post_routes_reject_unexpected_fields(path, payload):
    response = app.test_client().post(path, json=payload)

    assert response.status_code == 400
    assert "unsupported fields" in response.get_json()["error"]


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/windows-events/collect", {"lookback_hours": True}),
        ("/api/windows-events/collect", {"max_events": "500"}),
        ("/api/windows-events/collect", {"lookback_hours": 721}),
        ("/api/alerts/1/status", {"status": 1}),
        ("/api/alerts/1/status", {}),
        ("/api/alerts/1/note", {"note": 1}),
        ("/api/alerts/1/note", {}),
        ("/api/alerts/1/note", {"note": "x" * 4001}),
        ("/api/live/simulate", {"action": 1}),
        ("/api/live/simulate", {"action": "delete"}),
    ],
)
def test_post_routes_reject_invalid_values(path, payload):
    response = app.test_client().post(path, json=payload)

    assert response.status_code == 400