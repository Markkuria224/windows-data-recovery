"""Log ingestion and preparation for the SENTINEL dashboard.

This module will validate uploaded CSV files, normalise records and return
structured event dictionaries for the detection engine.
"""

from __future__ import annotations

import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, TextIO

REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "event_type",
    "user",
    "status",
    "host",
}
MAX_CSV_RECORDS = 10_000
MAX_FIELD_LENGTHS = {
    "timestamp": 64,
    "source_ip": 45,
    "event_type": 64,
    "user": 128,
    "status": 16,
    "host": 255,
}
ALLOWED_EVENT_TYPES = {"login", "auth", "authentication"}
ALLOWED_STATUSES = {"success", "failed"}


def validate_csv_file(file_path: str | Path) -> None:
    """Ensure a file is present and readable before processing."""
    csv_path = Path(file_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Log file not found: {csv_path}")
    if csv_path.suffix.lower() != ".csv":
        raise ValueError("Only CSV files are accepted for log ingestion.")


def load_logs_from_csv(file_path: str | Path) -> List[Dict[str, Any]]:
    """Read a CSV file and return a list of normalised log records."""
    validate_csv_file(file_path)
    with open(file_path, "r", newline="", encoding="utf-8-sig") as handle:
        return parse_logs_from_csv(handle)


def parse_logs_from_csv(handle: TextIO, max_records: int = MAX_CSV_RECORDS) -> List[Dict[str, Any]]:
    """Parse and validate a bounded CSV stream without writing it to disk."""
    reader = csv.DictReader(handle, restkey=None)
    if reader.fieldnames is None:
        raise ValueError("The CSV file is missing a header row.")

    normalized_headers = [header.lstrip("\ufeff").strip().lower() for header in reader.fieldnames]
    if len(normalized_headers) != len(set(normalized_headers)):
        raise ValueError("The CSV file contains duplicate column names.")
    missing_columns = REQUIRED_COLUMNS - set(normalized_headers)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"The CSV file is missing required columns: {missing}")
    source_headers = dict(zip(normalized_headers, reader.fieldnames))

    records: List[Dict[str, Any]] = []
    for index, row in enumerate(reader, start=2):
        if None in row:
            raise ValueError(f"Malformed record on row {index}; too many fields were provided.")
        cleaned = {
            column: str(row.get(source_headers[column]) or "").strip()
            for column in REQUIRED_COLUMNS
        }
        if not all(cleaned.values()):
            raise ValueError(f"Malformed record on row {index}; some required fields are blank.")
        for column, value in cleaned.items():
            if len(value) > MAX_FIELD_LENGTHS[column]:
                raise ValueError(f"Malformed record on row {index}; {column} exceeds its maximum length.")

        try:
            event_time = datetime.fromisoformat(cleaned["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Malformed record on row {index}; timestamp must be ISO 8601.") from exc
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        cleaned["timestamp"] = event_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

        try:
            cleaned["source_ip"] = str(ipaddress.ip_address(cleaned["source_ip"]))
        except ValueError as exc:
            raise ValueError(f"Malformed record on row {index}; source_ip must be a valid IP address.") from exc

        cleaned["event_type"] = cleaned["event_type"].lower()
        cleaned["status"] = cleaned["status"].lower()
        if cleaned["event_type"] not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"Malformed record on row {index}; unsupported event_type.")
        if cleaned["status"] not in ALLOWED_STATUSES:
            raise ValueError(f"Malformed record on row {index}; status must be success or failed.")

        records.append(cleaned)
        if len(records) > max_records:
            raise ValueError(f"CSV files cannot contain more than {max_records} records.")

    if not records:
        raise ValueError("The CSV file does not contain any event records.")
    return records


def normalise_logs(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert event dictionaries to a consistent format before detection."""
    normalised: List[Dict[str, Any]] = []
    for event in events:
        normalised.append(
            {
                "timestamp": str(event.get("timestamp", "")).strip(),
                "source_ip": str(event.get("source_ip", "")).strip(),
                "event_type": str(event.get("event_type", "")).strip(),
                "user": str(event.get("user", "")).strip(),
                "status": str(event.get("status", "")).strip(),
                "host": str(event.get("host", "")).strip(),
            }
        )
    return normalised
