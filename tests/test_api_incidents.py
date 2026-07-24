from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.api import create_app

_VIEWER_TOKEN = "v" * 32


def _record() -> dict[str, object]:
    return {
        "timestamp": "2026-07-22T10:00:00+00:00",
        "username": "security_test",
        "database": "sales",
        "source_system": "postgresql",
        "client_ip": "192.0.2.10",
        "query": "DROP DATABASE sales;",
        "risk_score": 0.99,
        "severity": "critical",
        "classification": "destructive_sql",
    }


def test_incident_api_list_detail_assessment_and_summary(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER_TOKEN)  # type: ignore[attr-defined]
    store = tmp_path / "alerts.db"
    persist_alert_batch(store, build_alert_batch([_record()]))
    client = TestClient(create_app(alert_log=store, audit_log=tmp_path / "audit.jsonl"))
    headers = {"Authorization": f"Bearer {_VIEWER_TOKEN}"}

    listed = client.get("/api/v1/incidents", headers=headers)
    assert listed.status_code == 200
    incident_id = listed.json()["incidents"][0]["incident_id"]

    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    assessment = client.get(
        f"/api/v1/incidents/{incident_id}/assessment",
        headers=headers,
    )
    summary = client.get("/api/v1/incidents/summary", headers=headers)

    assert detail.status_code == 200
    assert detail.json()["severity"] == "critical"
    assert assessment.status_code == 200
    assert assessment.json()["escalation_required"] is True
    assert summary.json()["active_count"] == 1


def test_incident_api_requires_viewer_token(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER_TOKEN)  # type: ignore[attr-defined]
    client = TestClient(
        create_app(alert_log=tmp_path / "alerts.db", audit_log=tmp_path / "audit.jsonl")
    )

    assert client.get("/api/v1/incidents").status_code == 401
