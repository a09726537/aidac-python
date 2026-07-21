"""Tests for AI-DAC 1.0 API roles, pagination and rate limiting."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.api import create_app

_VIEWER = "viewer-token-0123456789-abcdefghijklmnopqrstuvwxyz"
_ANALYST = "analyst-token-0123456789-abcdefghijklmnopqrstuvwxyz"
_ADMIN = "admin-token-0123456789-abcdefghijklmnopqrstuvwxyz"


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _prepare(tmp_path: Path, monkeypatch: object) -> tuple[TestClient, Path]:
    monkeypatch.delenv("AIDAC_API_TOKEN", raising=False)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_API_ANALYST_TOKEN", _ANALYST)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_API_ADMIN_TOKEN", _ADMIN)  # type: ignore[attr-defined]
    store = tmp_path / "alerts.db"
    records = [
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "username": "alice",
            "database": "sales",
            "source_system": "postgresql",
            "client_ip": "192.0.2.10",
            "query": "DROP TABLE customers;",
            "risk_score": 0.95,
            "severity": "critical",
            "classification": "destructive_sql",
        },
        {
            "timestamp": "2026-01-02T00:00:00+00:00",
            "username": "bob",
            "database": "warehouse",
            "source_system": "postgresql",
            "client_ip": "192.0.2.20",
            "query": "SELECT * FROM orders;",
            "risk_score": 0.4,
            "severity": "medium",
            "classification": "query",
        },
    ]
    alerts = persist_alert_batch(store, build_alert_batch(records))
    alert_id = str(alerts[0]["alert_id"])
    app = create_app(
        alert_log=store,
        audit_log=tmp_path / "audit.jsonl",
        rate_limit_per_minute=100,
    )
    return TestClient(app), Path(alert_id)


def test_role_permissions_and_admin_diagnostics(tmp_path: Path, monkeypatch: object) -> None:
    """Viewer, analyst and admin tokens should enforce least privilege."""

    client, alert_id_path = _prepare(tmp_path, monkeypatch)
    alert_id = str(alert_id_path)

    assert client.get("/api/v1/alerts", headers=_headers(_VIEWER)).status_code == 200
    denied = client.post(
        f"/api/v1/alerts/{alert_id}/ack",
        headers=_headers(_VIEWER),
        json={"actor": "viewer"},
    )
    acknowledged = client.post(
        f"/api/v1/alerts/{alert_id}/ack",
        headers=_headers(_ANALYST),
        json={"actor": "analyst"},
    )
    analyst_system = client.get("/api/v1/system/storage", headers=_headers(_ANALYST))
    admin_system = client.get("/api/v1/system/storage", headers=_headers(_ADMIN))

    assert denied.status_code == 403
    assert acknowledged.status_code == 200
    assert analyst_system.status_code == 403
    assert admin_system.status_code == 200
    assert admin_system.json()["backend"] == "sqlite"


def test_api_pagination_and_search(tmp_path: Path, monkeypatch: object) -> None:
    """List responses should include stable pagination metadata."""

    client, _ = _prepare(tmp_path, monkeypatch)
    response = client.get(
        "/api/v1/alerts?limit=1&offset=0&q=orders",
        headers=_headers(_VIEWER),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["alert_count"] == 1
    assert payload["total"] == 1
    assert payload["offset"] == 0
    assert payload["alerts"][0]["username"] == "bob"


def test_rate_limit_returns_429(tmp_path: Path, monkeypatch: object) -> None:
    """The per-token limiter should reject requests beyond the configured window."""

    monkeypatch.delenv("AIDAC_API_TOKEN", raising=False)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER)  # type: ignore[attr-defined]
    app = create_app(
        alert_log=tmp_path / "alerts.db",
        audit_log=tmp_path / "audit.jsonl",
        rate_limit_per_minute=2,
    )
    client = TestClient(app)

    first = client.get("/api/v1/alerts", headers=_headers(_VIEWER))
    second = client.get("/api/v1/alerts", headers=_headers(_VIEWER))
    third = client.get("/api/v1/alerts", headers=_headers(_VIEWER))

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert "retry-after" in third.headers
