from __future__ import annotations

from aidac.incidents import (
    IncidentStatus,
    correlate_alerts,
    get_incident,
    incident_notification_payload,
    incident_summary,
    query_incidents,
)


def _alert(
    alert_id: str,
    *,
    timestamp: str = "2026-07-22T10:00:00+00:00",
    classification: str = "sql_injection",
    severity: str = "high",
    risk: float = 0.85,
    status: str = "new",
    client_ip: str = "192.0.2.10",
    count: int = 1,
) -> dict[str, object]:
    return {
        "alert_id": alert_id,
        "first_seen": timestamp,
        "last_seen": timestamp,
        "source_system": "postgresql",
        "database": "sales",
        "username": "app_user",
        "client_ip": client_ip,
        "classification": classification,
        "query": "SELECT * FROM customers WHERE id = 1 OR 1=1",
        "severity": severity,
        "risk_score": risk,
        "status": status,
        "occurrence_count": count,
    }


def test_correlates_multistage_alerts_for_same_actor() -> None:
    incidents = correlate_alerts(
        [
            _alert("alrt_1", classification="sql_injection"),
            _alert(
                "alrt_2",
                timestamp="2026-07-22T10:15:00+00:00",
                classification="privilege_escalation",
                severity="critical",
                risk=0.97,
                count=2,
            ),
        ],
        window_minutes=30,
    )

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["alert_count"] == 2
    assert incident["occurrence_count"] == 3
    assert incident["severity"] == "critical"
    assert incident["status"] == IncidentStatus.OPEN.value
    assert incident["classifications"] == ["privilege_escalation", "sql_injection"]
    assert incident["triple_loop"]["escalation_required"] is True


def test_separates_clusters_outside_time_window() -> None:
    incidents = correlate_alerts(
        [
            _alert("alrt_1"),
            _alert("alrt_2", timestamp="2026-07-22T12:00:00+00:00"),
        ],
        window_minutes=30,
    )

    assert len(incidents) == 2
    assert incidents[0]["incident_id"] != incidents[1]["incident_id"]


def test_incident_status_and_query_filters() -> None:
    incidents = correlate_alerts(
        [
            _alert("alrt_1", status="acknowledged", severity="medium", risk=0.6),
            _alert(
                "alrt_2",
                client_ip="192.0.2.20",
                status="resolved",
                severity="low",
                risk=0.2,
            ),
        ]
    )
    investigating, total = query_incidents(
        incidents,
        status=IncidentStatus.INVESTIGATING,
        minimum_risk=0.5,
    )

    assert total == 1
    assert investigating[0]["status"] == "investigating"
    assert get_incident(incidents, str(investigating[0]["incident_id"])) == investigating[0]
    summary = incident_summary(incidents)
    assert summary["incident_count"] == 2
    assert summary["active_count"] == 1


def test_notification_payload_excludes_sql_and_alert_identifiers() -> None:
    incident = correlate_alerts([_alert("alrt_secret")])[0]
    payload = incident_notification_payload(incident)

    assert "query" not in payload
    assert "alert_ids" not in payload
    assert payload["incident_id"] == incident["incident_id"]
