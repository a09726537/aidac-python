from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aidac.cli import app
from aidac.ops_cli import generate_operations_bundle, validate_operations_bundle

runner = CliRunner()


def test_generate_and_validate_operations_bundle(tmp_path: Path) -> None:
    destination = tmp_path / "ops"
    generated = generate_operations_bundle(
        destination,
        aidac_url="http://host.docker.internal:8000",
        viewer_token_file=tmp_path / "viewer.token",
        overwrite=False,
    )
    assert len(generated) == 10
    result = validate_operations_bundle(destination)
    assert result["valid"] is True
    assert result["file_count"] == 10
    dashboard = json.loads(
        (destination / "grafana/dashboards/aidac-overview.json").read_text(encoding="utf-8")
    )
    assert dashboard["uid"] == "aidac-operations"
    assert "authorization:" in (destination / "prometheus/prometheus.yml").read_text(
        encoding="utf-8"
    )
    assert 'url = "http://127.0.0.1:8000/health/live"' in (
        destination / "components.toml"
    ).read_text(encoding="utf-8")


def test_ops_init_and_validate_cli(tmp_path: Path) -> None:
    destination = tmp_path / "generated"
    initialized = runner.invoke(
        app,
        [
            "ops",
            "init",
            "--output-dir",
            str(destination),
            "--viewer-token-file",
            str(tmp_path / "viewer.token"),
        ],
    )
    assert initialized.exit_code == 0
    validated = runner.invoke(app, ["ops", "validate", "--directory", str(destination), "--json"])
    assert validated.exit_code == 0
    assert json.loads(validated.stdout)["valid"] is True


def test_ops_health_notifies_on_required_failure(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from aidac.component_health import ComponentResult, ComponentTarget

    config = tmp_path / "components.toml"
    config.write_text(
        '[[components]]\nname="api"\nurl="http://example.test/health"\n',
        encoding="utf-8",
    )
    failed = ComponentResult(
        name="api",
        url="http://example.test/health",
        required=True,
        healthy=False,
        status_code=503,
        duration_seconds=0.1,
        detail="http_503",
        checked_at_epoch=1.0,
    )
    delivered: list[dict[str, object]] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "aidac.ops_cli.load_component_targets",
        lambda path: [ComponentTarget(name="api", url="http://example.test/health")],
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "aidac.ops_cli.check_components",
        lambda targets: [failed],
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "aidac.ops_cli.send_signed_webhook",
        lambda settings, payload: delivered.append(payload) or 200,
    )

    result = runner.invoke(
        app,
        [
            "ops",
            "health",
            "--config",
            str(config),
            "--report",
            str(tmp_path / "health.json"),
            "--notify-webhook",
            "https://operations.example.test/aidac",
        ],
    )
    assert result.exit_code == 2
    assert delivered[0]["status"] == "degraded"
