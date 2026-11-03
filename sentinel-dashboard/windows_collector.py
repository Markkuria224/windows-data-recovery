"""Read-only collection and normalisation of local Windows Security events."""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

WINDOWS_EVENT_IDS = {4624, 4625, 4634, 4648, 4672}
EVENT_DETAILS = {
	4624: ("windows_login", "success", "LOW"),
	4625: ("windows_login", "failed", "MEDIUM"),
	4634: ("windows_logoff", "observed", "LOW"),
	4648: ("windows_authentication", "observed", "MEDIUM"),
	4672: ("windows_privilege", "observed", "HIGH"),
}
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class WindowsEventCollectionError(RuntimeError):
	"""Base error for a failed Windows Security event collection."""


class WindowsCollectionUnavailable(WindowsEventCollectionError):
	"""Raised when native Windows collection is requested on another OS."""


class WindowsCollectionPermissionError(WindowsEventCollectionError):
	"""Raised when the current user cannot read the Security event log."""


def is_windows_collection_available() -> bool:
	"""Return whether this host supports the native Windows collector."""
	return platform.system() == "Windows"


def _clean_text(value: Any, limit: int = 512) -> str:
	text = _CONTROL_CHARACTERS.sub(" ", str(value or ""))
	return " ".join(text.split())[:limit]


def _clean_ip(value: Any) -> str:
	candidate = _clean_text(value, 64)
	if not candidate or candidate in {"-", "::1", "127.0.0.1"}:
		return ""
	try:
		return str(ipaddress.ip_address(candidate))
	except ValueError:
		return ""


def normalise_windows_event(record: Dict[str, Any]) -> Dict[str, Any]:
	"""Validate a PowerShell event record and adapt it to SENTINEL's event shape."""
	try:
		event_id = int(record.get("event_id"))
		record_id = int(record.get("record_id"))
	except (TypeError, ValueError) as exc:
		raise ValueError("Windows event IDs must be integers.") from exc

	if event_id not in WINDOWS_EVENT_IDS or record_id < 0:
		raise ValueError("Unsupported or invalid Windows event record.")

	timestamp = _clean_text(record.get("timestamp"), 64)
	try:
		parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
	except ValueError as exc:
		raise ValueError("Windows event timestamp is invalid.") from exc
	if parsed_timestamp.tzinfo is None:
		parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
	timestamp = parsed_timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

	event_type, status, severity = EVENT_DETAILS[event_id]
	username = _clean_text(record.get("username"), 128)
	computer_name = _clean_text(record.get("computer_name"), 255) or "unknown"
	logon_type = _clean_text(record.get("logon_type"), 32)

	return {
		"event_id": event_id,
		"event_record_id": record_id,
		"timestamp": timestamp,
		"source_ip": _clean_ip(record.get("source_ip")),
		"event_type": event_type,
		"user": username,
		"status": status,
		"host": computer_name,
		"computer_name": computer_name,
		"username": username,
		"logon_type": logon_type,
		"description": _clean_text(record.get("description"), 2048),
		"severity": severity,
	}


def _powershell_script(lookback_hours: int, max_events: int) -> str:
	"""Build a fixed query; only already-validated numeric limits are inserted."""
	return f"""
$ErrorActionPreference = 'Stop'
$startTime = (Get-Date).ToUniversalTime().AddHours(-{lookback_hours})
$records = @(Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625,4634,4648,4672; StartTime=$startTime}} -MaxEvents {max_events} -ErrorAction SilentlyContinue | ForEach-Object {{
  $eventXml = [xml]$_.ToXml()
  $fields = @{{}}
  foreach ($data in $eventXml.Event.EventData.Data) {{
	$name = $data.GetAttribute('Name')
	if ($name) {{ $fields[$name] = $data.InnerText }}
  }}
  $username = $fields['TargetUserName']
  if (-not $username -or $username -eq '-') {{ $username = $fields['SubjectUserName'] }}
  [pscustomobject]@{{
	event_id = [int]$_.Id
	record_id = [int64]$_.RecordId
	timestamp = $_.TimeCreated.ToUniversalTime().ToString('o')
	username = $username
	computer_name = $_.MachineName
	source_ip = $fields['IpAddress']
	logon_type = $fields['LogonType']
	description = $_.Message
  }}
}})
if ($records.Count -eq 0) {{ '[]' }} else {{ ConvertTo-Json -InputObject $records -Depth 4 -Compress }}
"""


def collect_windows_events(lookback_hours: int = 24, max_events: int = 500) -> List[Dict[str, Any]]:
	"""Read supported Security events through PowerShell without changing system state."""
	if not is_windows_collection_available():
		raise WindowsCollectionUnavailable("Native Windows Security event collection is unavailable on this operating system. CSV import remains available.")
	if isinstance(lookback_hours, bool) or not isinstance(lookback_hours, int) or not 1 <= lookback_hours <= 720:
		raise ValueError("Lookback must be between 1 and 720 hours.")
	if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= 5000:
		raise ValueError("Maximum event count must be between 1 and 5000.")

	try:
		result = subprocess.run(
			[
				"powershell.exe",
				"-NoLogo",
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				_powershell_script(lookback_hours, max_events),
			],
			capture_output=True,
			text=True,
			encoding="utf-8",
			errors="replace",
			timeout=45,
			check=False,
		)
	except FileNotFoundError as exc:
		raise WindowsEventCollectionError("PowerShell was not found; native event collection could not run.") from exc
	except subprocess.TimeoutExpired as exc:
		raise WindowsEventCollectionError("Windows event collection timed out; no collection success is reported.") from exc

	if result.returncode != 0:
		error_text = f"{result.stdout}\n{result.stderr}".casefold()
		if any(marker in error_text for marker in ("access is denied", "unauthorized", "not authorized", "accessdenied")):
			raise WindowsCollectionPermissionError(
				"Access to the Windows Security log was denied. Run SENTINEL in an elevated PowerShell session or grant read access to the Security log."
			)
		raise WindowsEventCollectionError(f"Windows event collection failed (PowerShell exit code {result.returncode}).")

	try:
		payload = json.loads(result.stdout or "[]")
	except json.JSONDecodeError as exc:
		raise WindowsEventCollectionError("PowerShell returned invalid event data; collection was not accepted.") from exc

	if isinstance(payload, dict):
		payload = [payload]
	if not isinstance(payload, list):
		raise WindowsEventCollectionError("PowerShell returned an unexpected event format; collection was not accepted.")

	normalised: List[Dict[str, Any]] = []
	try:
		for record in payload:
			if not isinstance(record, dict):
				raise ValueError("PowerShell returned a non-object event record.")
			normalised.append(normalise_windows_event(record))
	except ValueError as exc:
		raise WindowsEventCollectionError(f"A Windows event record failed validation: {exc}") from exc
	return normalised
