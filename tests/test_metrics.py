from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aidac.api import create_app
from aidac.metrics import MetricsRegistry, normalize_metric_path


def test_normalize_metric_path_hides_alert_identifiers() -> None:
    assert normalize_metric_path("/api/v1/alerts/alrt_secret") == "/api/v1/alerts/{alert_id}"
    assert (
        normalize_metric_path("/api/v1/alerts/alrt_secret/ack") == "/api/v1/alerts/{alert_id}/ack"
    )


def test_registry_renders_http_and_store_metrics(tmp_path: Path) -> None:
    registry = MetricsRegistry()
    registry.observe_http_request(
        method="GET",
        path="/health/live",
        status_code=200,
        duration_seconds=0.25,
    )
    body = registry.render(tmp_path / "alerts.db")
    assert "aidac_info" in body
    assert 'aidac_http_requests_total{method="GET",path="/health/live",status="200"} 1' in body
    assert "aidac_alert_store_up" in body


def test_metrics_endpoint_requires_viewer_token(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", "v" * 32)  # type: ignore[attr-defined]
    app = create_app(
        alert_log=tmp_path / "alerts.db",
        audit_log=tmp_path / "audit.jsonl",
    )
    client = TestClient(app)

    assert client.get("/metrics").status_code == 401
    response = client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {'v' * 32}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "aidac_http_requests_total" in response.text
