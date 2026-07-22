from __future__ import annotations

import json
from pathlib import Path

import pytest

from aidac.component_health import (
    ComponentHealthError,
    ComponentHealthRegistry,
    ComponentResult,
    ComponentTarget,
    health_summary,
    load_component_targets,
    probe_component,
    write_health_report,
)


class _Response:
    status = 200

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, amount: int) -> bytes:
        assert amount == 4096
        return b'{"status":"ok"}'


def test_load_component_targets_and_reject_credentials(tmp_path: Path) -> None:
    config = tmp_path / "components.toml"
    config.write_text(
        """[[components]]
name = "aidac-api"
url = "http://127.0.0.1:8000/health/live"
required = true
timeout_seconds = 2.5
""",
        encoding="utf-8",
    )
    targets = load_component_targets(config)
    assert targets == [
        ComponentTarget(
            name="aidac-api",
            url="http://127.0.0.1:8000/health/live",
            required=True,
            timeout_seconds=2.5,
        )
    ]
    with pytest.raises(ComponentHealthError):
        ComponentTarget(name="db", url="http://user:secret@example.test/health")


def test_probe_component_and_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aidac.component_health.urlopen", lambda *args, **kwargs: _Response())
    healthy = probe_component(ComponentTarget(name="api", url="http://example.test/health"))
    assert healthy.healthy is True
    assert healthy.status_code == 200

    missing = probe_component(
        ComponentTarget(
            name="protected",
            url="https://example.test/health",
            token_env="MISSING_COMPONENT_TOKEN",
        )
    )
    assert missing.healthy is False
    assert missing.detail == "missing_token:MISSING_COMPONENT_TOKEN"


def test_health_summary_registry_and_private_report(tmp_path: Path) -> None:
    results = [
        ComponentResult(
            name="api",
            url="http://example.test/health",
            required=True,
            healthy=True,
            status_code=200,
            duration_seconds=0.1,
            detail="ok",
            checked_at_epoch=1.0,
        ),
        ComponentResult(
            name="grafana",
            url="http://example.test/grafana",
            required=False,
            healthy=False,
            status_code=503,
            duration_seconds=0.2,
            detail="http_503",
            checked_at_epoch=2.0,
        ),
    ]
    summary = health_summary(results)
    assert summary["status"] == "healthy"
    assert summary["optional_failures"] == ["grafana"]

    registry = ComponentHealthRegistry()
    registry.replace(results)
    metrics = "\n".join(registry.render_prometheus())
    assert 'aidac_component_up{component="api"} 1' in metrics
    assert 'aidac_component_up{component="grafana"} 0' in metrics

    report = write_health_report(tmp_path / "state" / "health.json", summary)
    assert report.stat().st_mode & 0o777 == 0o600
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "healthy"
