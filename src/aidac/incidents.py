"""Deterministic incident correlation for current AI-DAC alert snapshots."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from aidac.learning import assess_incident
from aidac.models import Severity


class IncidentError(RuntimeError):
    """Raised when incident correlation or lookup fails."""


class IncidentStatus(StrEnum):
    """Derived incident lifecycle states."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def correlate_alerts(
    alerts: list[dict[str, Any]],
    *,
    window_minutes: int = 30,
) -> list[dict[str, Any]]:
    """Correlate alert snapshots by source, database, actor and time window."""

    if not 1 <= window_minutes <= 10_080:
        raise IncidentError("Correlation window must be between 1 and 10080 minutes.")

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for raw_alert in alerts:
        alert = dict(raw_alert)
        key = _correlation_identity(alert)
        grouped.setdefault(key, []).append(alert)

    incidents: list[dict[str, Any]] = []
    window = timedelta(minutes=window_minutes)
    for key, candidates in grouped.items():
        ordered = sorted(candidates, key=_first_seen)
        cluster: list[dict[str, Any]] = []
        cluster_last: datetime | None = None
        for alert in ordered:
            first_seen = _first_seen(alert)
            if cluster and cluster_last is not None and first_seen > cluster_last + window:
                incidents.append(_build_incident(key, cluster, window_minutes=window_minutes))
                cluster = []
                cluster_last = None
            cluster.append(alert)
            alert_last = _last_seen(alert)
            cluster_last = alert_last if cluster_last is None else max(cluster_last, alert_last)
        if cluster:
            incidents.append(_build_incident(key, cluster, window_minutes=window_minutes))

    return sorted(
        incidents,
        key=lambda incident: _parse_timestamp(incident.get("last_seen")),
        reverse=True,
    )


def query_incidents(
    incidents: list[dict[str, Any]],
    *,
    status: IncidentStatus | None = None,
    severity: str | None = None,
    minimum_risk: float = 0.0,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Filter and paginate correlated incidents."""

    if not 0.0 <= minimum_risk <= 1.0:
        raise IncidentError("Minimum incident risk must be between 0.0 and 1.0.")
    if not 1 <= limit <= 1_000:
        raise IncidentError("Incident list limit must be between 1 and 1000.")
    if offset < 0:
        raise IncidentError("Incident list offset cannot be negative.")

    normalized_severity = None if severity is None else severity.strip().casefold()
    if normalized_severity and normalized_severity not in _SEVERITY_RANK:
        allowed = ", ".join(_SEVERITY_RANK)
        raise IncidentError(f"Incident severity must be one of: {allowed}.")
    normalized_search = None if search is None else search.strip().casefold()

    filtered: list[dict[str, Any]] = []
    for incident in incidents:
        if status is not None and incident.get("status") != status.value:
            continue
        if (
            normalized_severity
            and str(incident.get("severity", "")).casefold() != normalized_severity
        ):
            continue
        if float(incident.get("risk_score", 0.0)) < minimum_risk:
            continue
        if normalized_search and normalized_search not in _search_text(incident):
            continue
        filtered.append(incident)

    return filtered[offset : offset + limit], len(filtered)


def get_incident(incidents: list[dict[str, Any]], incident_id: str) -> dict[str, Any]:
    """Return one incident by identifier."""

    normalized_id = incident_id.strip()
    for incident in incidents:
        if incident.get("incident_id") == normalized_id:
            return incident
    raise IncidentError(f"Incident not found: {normalized_id}")


def incident_summary(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    """Return bounded aggregate incident counts."""

    status_counts: Counter[str] = Counter(str(item.get("status", "unknown")) for item in incidents)
    severity_counts: Counter[str] = Counter(
        str(item.get("severity", "unknown")) for item in incidents
    )
    active = [item for item in incidents if item.get("status") != IncidentStatus.RESOLVED.value]
    return {
        "incident_count": len(incidents),
        "active_count": len(active),
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "maximum_active_risk": max(
            (float(item.get("risk_score", 0.0)) for item in active),
            default=0.0,
        ),
    }


def incident_notification_payload(incident: dict[str, Any]) -> dict[str, Any]:
    """Build a notification payload without SQL text, credentials or DSNs."""

    assessment = incident.get("triple_loop", {})
    return {
        "type": "aidac_incident_notification",
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "status": incident.get("status"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "alert_count": incident.get("alert_count"),
        "occurrence_count": incident.get("occurrence_count"),
        "first_seen": incident.get("first_seen"),
        "last_seen": incident.get("last_seen"),
        "database": incident.get("database"),
        "source_system": incident.get("source_system"),
        "classifications": incident.get("classifications", []),
        "escalation_required": assessment.get("escalation_required", False),
        "human_approval_required": assessment.get("human_approval_required", False),
    }


def _build_incident(
    key: tuple[str, str, str],
    alerts: list[dict[str, Any]],
    *,
    window_minutes: int,
) -> dict[str, Any]:
    source_system, database, actor = key
    first_seen = min(_first_seen(alert) for alert in alerts)
    last_seen = max(_last_seen(alert) for alert in alerts)
    severity = max(
        (str(alert.get("severity", Severity.INFO.value)).casefold() for alert in alerts),
        key=lambda value: _SEVERITY_RANK.get(value, 0),
    )
    risk_score = max(float(alert.get("risk_score", 0.0)) for alert in alerts)
    occurrence_count = sum(_positive_integer(alert.get("occurrence_count"), 1) for alert in alerts)
    statuses = {str(alert.get("status", "new")).casefold() for alert in alerts}
    if "new" in statuses:
        status = IncidentStatus.OPEN
    elif "acknowledged" in statuses:
        status = IncidentStatus.INVESTIGATING
    else:
        status = IncidentStatus.RESOLVED

    classifications = sorted(
        {
            str(alert.get("classification", "unclassified")).strip() or "unclassified"
            for alert in alerts
        }
    )
    usernames = sorted(
        {str(alert.get("username", "")).strip() for alert in alerts if alert.get("username")}
    )
    client_ips = sorted(
        {str(alert.get("client_ip", "")).strip() for alert in alerts if alert.get("client_ip")}
    )
    identity = {
        "source_system": source_system,
        "database": database,
        "actor": actor,
        "cluster_start": first_seen.isoformat(),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    incident: dict[str, Any] = {
        "type": "aidac_incident",
        "incident_id": f"inc_{digest[:24]}",
        "title": f"{severity.title()} database-security activity on {database}",
        "status": status.value,
        "severity": severity,
        "risk_score": round(min(1.0, max(0.0, risk_score)), 4),
        "alert_count": len(alerts),
        "occurrence_count": occurrence_count,
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "correlation_window_minutes": window_minutes,
        "source_system": source_system,
        "database": database,
        "actor": actor,
        "usernames": usernames,
        "client_ips": client_ips,
        "classifications": classifications,
        "alert_ids": sorted(str(alert.get("alert_id", "")) for alert in alerts),
        "recommended_action": _recommended_action(severity, occurrence_count),
    }
    incident["triple_loop"] = assess_incident(incident).to_dict()
    return incident


def _correlation_identity(alert: dict[str, Any]) -> tuple[str, str, str]:
    source = str(alert.get("source_system", "unknown")).strip().casefold() or "unknown"
    database = str(alert.get("database", "unknown")).strip().casefold() or "unknown"
    client_ip = str(alert.get("client_ip", "")).strip().casefold()
    username = str(alert.get("username", "unknown")).strip().casefold() or "unknown"
    actor = client_ip or username
    return source, database, actor


def _recommended_action(severity: str, occurrence_count: int) -> str:
    if severity == Severity.CRITICAL.value:
        return "Preserve evidence and initiate the human-controlled incident-response procedure."
    if severity == Severity.HIGH.value:
        return "Escalate for immediate analyst review and validate containment options."
    if occurrence_count >= 3:
        return "Review recurrence, tune controls and maintain enhanced monitoring."
    return "Continue analyst review and monitor for correlated activity."


def _first_seen(alert: dict[str, Any]) -> datetime:
    return _parse_timestamp(alert.get("first_seen") or alert.get("timestamp"))


def _last_seen(alert: dict[str, Any]) -> datetime:
    return _parse_timestamp(alert.get("last_seen") or alert.get("timestamp"))


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = datetime.fromtimestamp(0, tz=UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _positive_integer(value: object, default: int) -> int:
    if not isinstance(value, (str, int, float)):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _search_text(incident: dict[str, Any]) -> str:
    values = [
        incident.get("incident_id"),
        incident.get("title"),
        incident.get("database"),
        incident.get("actor"),
        incident.get("source_system"),
        *incident.get("usernames", []),
        *incident.get("client_ips", []),
        *incident.get("classifications", []),
    ]
    return " ".join(str(value) for value in values if value is not None).casefold()
