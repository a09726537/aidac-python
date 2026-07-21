"""Tests for the authenticated AI-DAC alert REST API."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.api import create_app

_TOKEN = "test-token-0123456789-abcdefghijklmnopqrstuvwxyz"


def _create_alert(alert_log: Path) -> str:
    records = [
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "username": "security_test",
            "database": "sales",
            "source_system": "postgresql",
            "client_ip": "192.0.2.10",
            "query": "DROP TABLE customers;",
            "risk_score": 0.95,
            "severity": "critical",
            "classification": "destructive_sql",
        }
    ]
    return str(persist_alert_batch(alert_log, build_alert_batch(records))[0]["alert_id"])


def _client(tmp_path: Path, monkeypatch: object) -> tuple[TestClient, Path, Path]:
    alert_log = tmp_path / "alerts.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AIDAC_API_TOKEN", _TOKEN)  # type: ignore[attr-defined]
    return (
        TestClient(create_app(alert_log=alert_log, audit_log=audit_log)),
        alert_log,
        audit_log,
    )


def _authorization(token: str = _TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_and_security_headers(tmp_path: Path, monkeypatch: object) -> None:
    """Liveness should be public and responses should prevent caching."""

    client, _, _ = _client(tmp_path, monkeypatch)

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json()["status"] == "live"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_protected_endpoint_requires_valid_bearer_token(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    """Alert data must not be returned without valid authentication."""

    client, _, _ = _client(tmp_path, monkeypatch)

    missing = client.get("/api/v1/alerts")
    invalid = client.get("/api/v1/alerts", headers=_authorization("wrong-token"))

    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_list_show_and_summary_alerts(tmp_path: Path, monkeypatch: object) -> None:
    """Authenticated clients should inspect current alerts."""

    client, alert_log, _ = _client(tmp_path, monkeypatch)
    alert_id = _create_alert(alert_log)

    listed = client.get("/api/v1/alerts", headers=_authorization())
    shown = client.get(f"/api/v1/alerts/{alert_id}", headers=_authorization())
    summary = client.get("/api/v1/alerts/summary", headers=_authorization())

    assert listed.status_code == 200
    assert listed.json()["alert_count"] == 1
    assert shown.status_code == 200
    assert shown.json()["alert_id"] == alert_id
    assert summary.status_code == 200
    assert summary.json()["status_counts"] == {"new": 1}
    assert summary.json()["severity_counts"] == {"critical": 1}


def test_acknowledge_and_resolve_are_audited(tmp_path: Path, monkeypatch: object) -> None:
    """Lifecycle mutations should update the store and append audit records."""

    client, alert_log, audit_log = _client(tmp_path, monkeypatch)
    alert_id = _create_alert(alert_log)
    body = {"actor": "api-analyst", "note": "Reviewed remotely"}

    acknowledged = client.post(
        f"/api/v1/alerts/{alert_id}/ack",
        headers=_authorization(),
        json=body,
    )
    resolved = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=_authorization(),
        json={"actor": "api-analyst"},
    )

    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    actions = {
        json.loads(line)["action"] for line in audit_log.read_text(encoding="utf-8").splitlines()
    }
    assert actions == {"api_alert_acknowledged", "api_alert_resolved"}


def test_openapi_defines_bearer_authentication(tmp_path: Path, monkeypatch: object) -> None:
    """OpenAPI should advertise the bearer-token security scheme."""

    client, _, _ = _client(tmp_path, monkeypatch)

    schema = client.get("/openapi.json").json()

    schemes = schema["components"]["securitySchemes"]
    assert any(item.get("scheme") == "bearer" for item in schemes.values())


def test_readiness_reports_missing_token(tmp_path: Path, monkeypatch: object) -> None:
    """Readiness should fail closed when authentication is not configured."""

    monkeypatch.delenv("AIDAC_API_TOKEN", raising=False)  # type: ignore[attr-defined]
    client = TestClient(
        create_app(
            alert_log=tmp_path / "alerts.jsonl",
            audit_log=tmp_path / "audit.jsonl",
        )
    )

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["token_configured"] is False
