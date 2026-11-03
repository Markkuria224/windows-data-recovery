"""Threat detection rules for the SENTINEL dashboard.

The current skeleton defines the rule interface and explains the expected
alert model. The detection logic will be implemented in the next module pass.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List


def _parse_event_time(value: Any) -> datetime | None:
    """Safely convert ISO timestamps into Python datetime objects."""
    if value is None:
        return None

    try:
        timestamp = str(value).strip()
        if not timestamp:
            return None
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def _is_authentication_event(event: Dict[str, Any]) -> bool:
    """Return True when an event is a login or authentication attempt."""
    event_type = str(event.get("event_type", "")).lower()
    return "login" in event_type or "auth" in event_type


def _build_alert(
    event: Dict[str, Any],
    severity: str,
    reason: str,
    event_type: str = "login",
    rule_id: str | None = None,
) -> Dict[str, Any]:
    """Create a consistent alert dictionary with the required metadata."""
    timestamp = event.get("timestamp", "")
    return {
        "timestamp": timestamp,
        "source_ip": str(event.get("source_ip", "unknown")).strip() or "unknown",
        "source_host": str(event.get("host", "unknown")).strip() or "unknown",
        "event_type": event_type,
        "severity": severity,
        "reason": reason,
        "status": "new",
        "rule_id": rule_id,
    }


def detect_repeated_failed_logins(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect repeated failed login attempts from a single source IP."""
    findings: List[Dict[str, Any]] = []
    grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            continue
        if not _is_authentication_event(event):
            continue
        if str(event.get("status", "")).lower() != "failed":
            continue

        source_ip = str(event.get("source_ip", "")).strip()
        if source_ip:
            grouped_events[source_ip].append(event)

    for source_ip, ip_events in grouped_events.items():
        ip_events.sort(key=lambda item: _parse_event_time(item.get("timestamp")) or datetime.min)

        window_start = 0
        for index, event in enumerate(ip_events):
            event_time = _parse_event_time(event.get("timestamp"))
            if event_time is None:
                continue

            while window_start < index:
                previous_time = _parse_event_time(ip_events[window_start].get("timestamp"))
                if previous_time is None:
                    window_start += 1
                    continue
                if event_time - previous_time <= timedelta(minutes=10):
                    break
                window_start += 1

            window_events = ip_events[window_start:index + 1]
            if len(window_events) >= 5:
                findings.append(
                    _build_alert(
                        event,
                        "HIGH",
                        (
                            f"Source IP {source_ip} generated {len(window_events)} failed logins "
                            "within 10 minutes, indicating a sustained password-guessing pattern."
                        ),
                        rule_id="repeated_failed_logins",
                    )
                )
                break

    return findings


def detect_unusual_authentication_activity(events: Iterable[Dict[str, Any]], threshold: int = 5) -> List[Dict[str, Any]]:
    """Detect authentication bursts that exceed the configured threshold."""
    findings: List[Dict[str, Any]] = []
    grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict) or not _is_authentication_event(event):
            continue

        source_ip = str(event.get("source_ip", "")).strip()
        if source_ip:
            grouped_events[source_ip].append(event)

    for source_ip, ip_events in grouped_events.items():
        ip_events.sort(key=lambda item: _parse_event_time(item.get("timestamp")) or datetime.min)

        for index, event in enumerate(ip_events):
            event_time = _parse_event_time(event.get("timestamp"))
            if event_time is None:
                continue

            window_start = 0
            while window_start <= index:
                current_time = _parse_event_time(ip_events[window_start].get("timestamp"))
                if current_time is None:
                    window_start += 1
                    continue
                if event_time - current_time > timedelta(minutes=10):
                    window_start += 1
                    continue
                break

            window_events = ip_events[window_start:index + 1]
            if len(window_events) > threshold:
                findings.append(
                    _build_alert(
                        event,
                        "MEDIUM",
                        (
                            f"Source IP {source_ip} produced {len(window_events)} authentication events "
                            f"within 10 minutes, exceeding the configured threshold of {threshold}."
                        ),
                        rule_id="unusual_authentication_burst",
                    )
                )
                break

    return findings


def detect_login_pattern_anomalies(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify suspicious login patterns such as credential stuffing and off-hours access."""
    events = list(events)
    findings: List[Dict[str, Any]] = []
    findings.extend(detect_credential_stuffing_pattern(events))
    findings.extend(detect_brute_force_success(events))
    findings.extend(detect_off_hours_login(events))
    findings.extend(detect_rapid_fire_attempts(events))
    return findings


def detect_credential_stuffing_pattern(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag a source IP that tries logins against 4+ distinct usernames in 10 minutes."""
    findings: List[Dict[str, Any]] = []
    grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict) or not _is_authentication_event(event):
            continue

        source_ip = str(event.get("source_ip", "")).strip()
        if source_ip:
            grouped_events[source_ip].append(event)

    for source_ip, ip_events in grouped_events.items():
        ip_events.sort(key=lambda item: _parse_event_time(item.get("timestamp")) or datetime.min)

        for index, event in enumerate(ip_events):
            event_time = _parse_event_time(event.get("timestamp"))
            if event_time is None:
                continue

            window_events = []
            unique_users = set()
            for candidate in ip_events:
                candidate_time = _parse_event_time(candidate.get("timestamp"))
                if candidate_time is None:
                    continue
                if event_time - candidate_time <= timedelta(minutes=10) and candidate_time <= event_time:
                    window_events.append(candidate)
                    username = str(candidate.get("user", "")).strip()
                    if username:
                        unique_users.add(username)

            if len(unique_users) >= 4:
                usernames = ", ".join(sorted(unique_users))
                findings.append(
                    _build_alert(
                        event,
                        "HIGH",
                        (
                            f"Source IP {source_ip} attempted logins for {len(unique_users)} distinct "
                            f"usernames within 10 minutes ({usernames}), which matches a credential-stuffing pattern."
                        ),
                        rule_id="credential_stuffing",
                    )
                )
                break

    return findings


def detect_brute_force_success(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Alert when an IP has 5+ failed attempts followed by a success within 15 minutes."""
    findings: List[Dict[str, Any]] = []
    grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict) or not _is_authentication_event(event):
            continue
        source_ip = str(event.get("source_ip", "")).strip()
        if source_ip:
            grouped_events[source_ip].append(event)

    for source_ip, ip_events in grouped_events.items():
        ip_events.sort(key=lambda item: _parse_event_time(item.get("timestamp")) or datetime.min)

        for index, event in enumerate(ip_events):
            if str(event.get("status", "")).lower() != "success":
                continue

            success_time = _parse_event_time(event.get("timestamp"))
            if success_time is None:
                continue

            failed_attempts = 0
            for candidate in ip_events:
                candidate_time = _parse_event_time(candidate.get("timestamp"))
                if candidate_time is None:
                    continue
                if candidate_time <= success_time and success_time - candidate_time <= timedelta(minutes=15):
                    if str(candidate.get("status", "")).lower() == "failed":
                        failed_attempts += 1

            if failed_attempts >= 5:
                findings.append(
                    _build_alert(
                        event,
                        "HIGH",
                        (
                            f"Source IP {source_ip} had {failed_attempts} failed login attempts in the previous 15 minutes "
                            "before a successful login, which is consistent with a brute-force compromise attempt."
                        ),
                        rule_id="brute_force_success",
                    )
                )
                break

    return findings


def detect_off_hours_login(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag successful logins that occurred during late-night hours."""
    findings: List[Dict[str, Any]] = []

    for event in events:
        if not isinstance(event, dict):
            continue
        if not _is_authentication_event(event):
            continue
        if str(event.get("status", "")).lower() != "success":
            continue

        event_time = _parse_event_time(event.get("timestamp"))
        if event_time is None:
            continue

        if 1 <= event_time.hour <= 5:
            findings.append(
                _build_alert(
                    event,
                    "MEDIUM",
                    (
                        f"Successful login from {event.get('source_ip', 'unknown')} occurred at {event.get('timestamp')} "
                        "during off-hours (01:00-05:00), which can indicate unusual access timing."
                    ),
                    rule_id="off_hours_login",
                )
            )

    return findings


def detect_rapid_fire_attempts(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flag a flood of authentication events from a single IP within a short timeframe."""
    findings: List[Dict[str, Any]] = []
    grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not isinstance(event, dict) or not _is_authentication_event(event):
            continue

        source_ip = str(event.get("source_ip", "")).strip()
        if source_ip:
            grouped_events[source_ip].append(event)

    for source_ip, ip_events in grouped_events.items():
        ip_events.sort(key=lambda item: _parse_event_time(item.get("timestamp")) or datetime.min)

        window_start = 0
        for index, event in enumerate(ip_events):
            event_time = _parse_event_time(event.get("timestamp"))
            if event_time is None:
                continue

            while window_start <= index:
                candidate_time = _parse_event_time(ip_events[window_start].get("timestamp"))
                if candidate_time is None:
                    window_start += 1
                    continue
                if event_time - candidate_time > timedelta(minutes=5):
                    window_start += 1
                    continue
                break

            window_events = ip_events[window_start:index + 1]
            if len(window_events) > 15:
                findings.append(
                    _build_alert(
                        event,
                        "HIGH",
                        (
                            f"Source IP {source_ip} generated {len(window_events)} authentication events in 5 minutes, "
                            "which exceeds the rapid-fire threshold and may indicate automated attack activity."
                        ),
                        rule_id="rapid_fire_authentication",
                    )
                )
                break

    return findings


def evaluate_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the complete detection pipeline and return a list of alert dictionaries."""
    events = list(events)
    findings: List[Dict[str, Any]] = []
    findings.extend(detect_repeated_failed_logins(events))
    findings.extend(detect_unusual_authentication_activity(events))
    findings.extend(detect_login_pattern_anomalies(events))
    return findings
