"""Tests for PostgreSQL watch alert persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import aidac.cli as cli_module
import pytest
from aidac.cli import app
from aidac.connectors.postgresql import (
    PostgreSQLAuditConfig,
)
from aidac.models import DatabaseEvent
from typer.testing import CliRunner

runner = CliRunner()


def test_watch_help_exposes_alert_options() -> None:
    """The watch command should expose delivery controls."""

    result = runner.invoke(
        app,
        ["postgres", "watch", "--help"],
    )

    assert result.exit_code == 0
    assert "--alert-log" in result.output
    assert "--audit-log" in result.output
    assert "--export-dir" in result.output
    assert "--webhook-url" in result.output
    assert "--webhook-strict" in result.output


def test_watch_once_persists_and_exports_alerts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One polling cycle should persist and export alerts."""

    event = DatabaseEvent(
        query="DROP TABLE customers;",
        username="security_test",
        database="sales",
        source_system="postgresql",
        client_ip="192.168.10.20",
        timestamp=datetime.now(UTC),
    )

    class FakeConnector:
        """PostgreSQL connector test double."""

        def __init__(
            self,
            config: PostgreSQLAuditConfig,
        ) -> None:
            self.config = config

        def health_check(self) -> bool:
            return True

        def fetch_events(
            self,
            *,
            since: object = None,
            limit: int | None = None,
        ) -> list[DatabaseEvent]:
            return [event]

    monkeypatch.setattr(
        cli_module,
        "PostgreSQLAuditConnector",
        FakeConnector,
    )
    monkeypatch.setenv(
        "AIDAC_POSTGRES_PASSWORD",
        "test-password",
    )

    alert_log = tmp_path / "alerts.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    state_file = tmp_path / "state.json"
    export_directory = tmp_path / "exports"
    config_file = tmp_path / "missing.toml"

    result = runner.invoke(
        app,
        [
            "postgres",
            "watch",
            "--once",
            "--min-risk",
            "0",
            "--config",
            str(config_file),
            "--state-file",
            str(state_file),
            "--alert-log",
            str(alert_log),
            "--audit-log",
            str(audit_log),
            "--export-dir",
            str(export_directory),
        ],
    )

    assert result.exit_code == 0
    assert alert_log.exists()
    assert audit_log.exists()
    assert state_file.exists()
    assert list(export_directory.glob("*.json"))

    alert_payload = json.loads(alert_log.read_text(encoding="utf-8").splitlines()[0])

    assert alert_payload["query"] == ("DROP TABLE customers;")
    assert alert_payload["type"] == "aidac_alert"

    audit_actions = {
        json.loads(line)["action"] for line in audit_log.read_text(encoding="utf-8").splitlines()
    }

    assert "postgres_watch_start" in audit_actions
    assert "alert_batch" in audit_actions
    assert "postgres_watch_stop" in audit_actions


def test_watch_rejects_insecure_webhook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The watch command must reject HTTP webhooks."""

    monkeypatch.setenv(
        "AIDAC_POSTGRES_PASSWORD",
        "test-password",
    )

    result = runner.invoke(
        app,
        [
            "postgres",
            "watch",
            "--once",
            "--config",
            str(tmp_path / "missing.toml"),
            "--state-file",
            str(tmp_path / "state.json"),
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
            "--webhook-url",
            "http://example.test/alerts",
        ],
    )

    assert result.exit_code == 1
    assert "HTTPS" in result.output
