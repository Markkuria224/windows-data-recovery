"""Log ingestion and preparation for the SENTINEL dashboard.

This module will validate uploaded CSV files, normalise records and return
structured event dictionaries for the detection engine.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List

REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "event_type",
    "user",
    "status",
    "host",
}


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
    records: List[Dict[str, Any]] = []

    with open(file_path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("The CSV file is missing a header row.")

        missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"The CSV file is missing required columns: {missing}")

        for index, row in enumerate(reader, start=2):
            cleaned = {
                "timestamp": (row.get("timestamp") or "").strip(),
                "source_ip": (row.get("source_ip") or "").strip(),
                "event_type": (row.get("event_type") or "").strip(),
                "user": (row.get("user") or "").strip(),
                "status": (row.get("status") or "").strip(),
                "host": (row.get("host") or "").strip(),
            }
            if not all(cleaned.values()):
                raise ValueError(f"Malformed record on row {index}; some required fields are blank.")
            records.append(cleaned)

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
