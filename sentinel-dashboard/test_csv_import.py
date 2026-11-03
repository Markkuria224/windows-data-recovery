from io import BytesIO, StringIO

import pytest

import analyzer
import database
from app import MAX_CSV_UPLOAD_BYTES, app


HEADER = "timestamp,source_ip,event_type,user,status,host\n"
VALID_ROW = "2026-03-10T12:00:00Z,203.0.113.8,login,analyst,failed,vpn-test\n"


@pytest.mark.parametrize(
    "row",
    [
        "not-a-time,203.0.113.8,login,analyst,failed,vpn-test\n",
        "2026-03-10T12:00:00Z,not-an-ip,login,analyst,failed,vpn-test\n",
        "2026-03-10T12:00:00Z,203.0.113.8,process,analyst,failed,vpn-test\n",
        "2026-03-10T12:00:00Z,203.0.113.8,login,analyst,unknown,vpn-test\n",
        "2026-03-10T12:00:00Z,203.0.113.8,login,analyst,failed,vpn-test,extra\n",
    ],
)
def test_csv_parser_rejects_malformed_event_semantics(row):
    with pytest.raises(ValueError):
        analyzer.parse_logs_from_csv(StringIO(HEADER + row))


def test_csv_parser_normalizes_headers_and_timestamps():
    contents = "\ufeff Timestamp , SOURCE_IP ,EVENT_TYPE,USER,STATUS,HOST\n2026-03-10T12:00:00+02:00,2001:db8::1,LOGIN,analyst,SUCCESS,host-1\n"

    records = analyzer.parse_logs_from_csv(StringIO(contents))

    assert records == [
        {
            "timestamp": "2026-03-10T10:00:00Z",
            "source_ip": "2001:db8::1",
            "event_type": "login",
            "user": "analyst",
            "status": "success",
            "host": "host-1",
        }
    ]


def test_csv_parser_enforces_row_limit():
    contents = HEADER + VALID_ROW * 3

    with pytest.raises(ValueError, match="more than 2 records"):
        analyzer.parse_logs_from_csv(StringIO(contents), max_records=2)


def test_csv_import_persists_records_and_skips_reimport_duplicates():
    client = app.test_client()
    first = client.post(
        "/api/csv/import",
        data={"file": (BytesIO((HEADER + VALID_ROW).encode()), "events.csv")},
        content_type="multipart/form-data",
    )
    second = client.post(
        "/api/csv/import",
        data={"file": (BytesIO((HEADER + VALID_ROW).encode()), "events.csv")},
        content_type="multipart/form-data",
    )

    assert first.status_code == 200
    assert first.get_json()["events_imported"] == 1
    assert second.status_code == 200
    assert second.get_json()["events_imported"] == 0
    assert second.get_json()["duplicates"] == 1
    assert database.get_dashboard_metrics()["total_events"] == 1


@pytest.mark.parametrize(
    ("filename", "contents", "expected_status"),
    [
        ("events.txt", HEADER + VALID_ROW, 400),
        ("events.csv", HEADER, 400),
        ("events.csv", "wrong,headers\nvalue,value\n", 400),
    ],
)
def test_csv_import_rejects_invalid_files(filename, contents, expected_status):
    response = app.test_client().post(
        "/api/csv/import",
        data={"file": (BytesIO(contents.encode()), filename)},
        content_type="multipart/form-data",
    )

    assert response.status_code == expected_status
    assert "error" in response.get_json()


def test_csv_import_rejects_uploads_over_size_limit():
    response = app.test_client().post(
        "/api/csv/import",
        data={"file": (BytesIO(b"x" * (MAX_CSV_UPLOAD_BYTES + 1)), "large.csv")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 413