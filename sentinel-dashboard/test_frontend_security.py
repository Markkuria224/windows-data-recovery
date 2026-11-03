from pathlib import Path

import pytest

from app import app
from database import insert_alert


SCRIPT_PATH = Path(__file__).parent / "static" / "script.js"
MALICIOUS_PAYLOADS = [
    '<img src=x onerror="window.__xss = true">',
    '<svg onload="window.__xss = true"></svg>',
    '</strong><script>window.__xss = true</script>',
]


@pytest.mark.parametrize("payload", MALICIOUS_PAYLOADS)
def test_alert_api_keeps_untrusted_content_as_data(payload):
    alert_id = insert_alert(
        None,
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "source_ip": "198.51.100.40",
            "source_host": "test-host",
            "event_type": "login",
            "severity": "HIGH",
            "reason": payload,
            "status": "Open",
            "note": payload,
        },
    )

    response = app.test_client().get("/api/alerts")
    alert = next(item for item in response.get_json()["alerts"] if item["id"] == alert_id)
    script = SCRIPT_PATH.read_text(encoding="utf-8")

    assert response.status_code == 200
    assert alert["reason"] == payload
    assert alert["notes"][0]["note_text"] == payload
    assert ".innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "textContent" in script