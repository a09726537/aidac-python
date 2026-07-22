from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aidac.api import create_app
from aidac.component_health import ComponentResult

_ADMIN_TOKEN = "a" * 32
_VIEWER_TOKEN = "v" * 32


def _config(path: Path) -> Path:
    path.write_text(
        """[[components]]
name = "database-vm"
url = "http://192.0.2.10/health"
required = true
""",
        encoding="utf-8",
    )
    return path


def test_admin_component_endpoint_and_metrics(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    monkeypatch.setenv("AIDAC_API_ADMIN_TOKEN", _ADMIN_TOKEN)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER_TOKEN)  # type: ignore[attr-defined]
    result = ComponentResult(
        name="database-vm",
        url="http://192.0.2.10/health",
        required=True,
        healthy=True,
        status_code=200,
        duration_seconds=0.1,
        detail="ok",
        checked_at_epoch=1.0,
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "aidac.api.check_components",
        lambda targets: [result],
    )
    app = create_app(
        alert_log=tmp_path / "alerts.db",
        audit_log=tmp_path / "audit.jsonl",
        component_config=_config(tmp_path / "components.toml"),
    )
    client = TestClient(app)

    components = client.get(
        "/api/v1/system/components",
        headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
    )
    assert components.status_code == 200
    assert components.json()["status"] == "healthy"

    metrics = client.get(
        "/metrics",
        headers={"Authorization": f"Bearer {_VIEWER_TOKEN}"},
    )
    assert metrics.status_code == 200
    assert 'aidac_component_up{component="database-vm"} 1' in metrics.text


def test_required_component_failure_affects_readiness(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    monkeypatch.setenv("AIDAC_API_VIEWER_TOKEN", _VIEWER_TOKEN)  # type: ignore[attr-defined]
    failed = ComponentResult(
        name="database-vm",
        url="http://192.0.2.10/health",
        required=True,
        healthy=False,
        status_code=None,
        duration_seconds=0.2,
        detail="timeout",
        checked_at_epoch=1.0,
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "aidac.api.check_components",
        lambda targets: [failed],
    )
    client = TestClient(
        create_app(
            alert_log=tmp_path / "alerts.db",
            audit_log=tmp_path / "audit.jsonl",
            component_config=_config(tmp_path / "components.toml"),
        )
    )
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["detail"]["required_components_healthy"] is False
