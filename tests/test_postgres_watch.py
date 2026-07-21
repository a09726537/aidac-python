"""Tests for continuous PostgreSQL monitoring."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import aidac.cli as cli_module
from aidac.cli import app
from aidac.models import DatabaseEvent

runner = CliRunner()


def _write_config(path: Path) -> None:
    path.write_text(
        """\
[postgresql]
host = "127.0.0.1"
port = 5432
database = "aidac_pgsql"
username = "aidac_reader"
schema = "public"
relation = "aidac_events_v"
default_limit = 100
""",
        encoding="utf-8",
    )


def _events() -> list[DatabaseEvent]:
    return [
        DatabaseEvent(
            query="SELECT 1;",
            username="reader",
            database="aidac_pgsql",
            source_system="postgresql",
            timestamp=datetime(
                2026,
                7,
                21,
                10,
                0,
                tzinfo=UTC,
            ),
        ),
        DatabaseEvent(
            query="DROP DATABASE production;",
            username="attacker",
            database="aidac_pgsql",
            source_system="postgresql",
            timestamp=datetime(
                2026,
                7,
                21,
                10,
                1,
                tzinfo=UTC,
            ),
        ),
    ]


def _install_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeEngine:
        def analyze(self, event: DatabaseEvent) -> Any:
            if event.query.startswith("DROP"):
                return SimpleNamespace(
                    risk_score=0.95,
                    severity=SimpleNamespace(value="critical"),
                    classification="destructive_sql",
                )
            return SimpleNamespace(
                risk_score=0.10,
                severity=SimpleNamespace(value="info"),
                classification="normal",
            )

    monkeypatch.setattr(cli_module, "AIDAC", FakeEngine)
    monkeypatch.setenv(
        "AIDAC_POSTGRES_DSN",
        "postgresql://test:test@localhost/test",
    )


def test_watch_once_emits_only_high_risk_alerts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeConnector:
        def __init__(self, config: object) -> None:
            self.config = config

        def health_check(self) -> bool:
            return True

        def fetch_events(
            self,
            *,
            since: object = None,
            limit: int | None = None,
        ) -> list[DatabaseEvent]:
            return _events()

    monkeypatch.setattr(
        cli_module,
        "PostgreSQLAuditConnector",
        FakeConnector,
    )
    _install_engine(monkeypatch)

    config_file = tmp_path / "config.toml"
    state_file = tmp_path / "state" / "postgresql.json"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "watch",
            "--config",
            str(config_file),
            "--state-file",
            str(state_file),
            "--once",
            "--json",
            "--min-risk",
            "0.7",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "aidac_alert_batch"
    assert payload["summary"]["events_analyzed"] == 1
    assert payload["events"][0]["severity"] == "critical"

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["last_event_time"].endswith("10:01:00+00:00")
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600


def test_watch_rejects_invalid_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_engine(monkeypatch)
    config_file = tmp_path / "config.toml"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "watch",
            "--config",
            str(config_file),
            "--interval",
            "0",
            "--once",
        ],
    )

    assert result.exit_code == 1
    assert "--interval must be between" in result.output


def test_watch_stops_cleanly_with_keyboard_interrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeConnector:
        def __init__(self, config: object) -> None:
            self.config = config

        def health_check(self) -> bool:
            return True

        def fetch_events(
            self,
            *,
            since: object = None,
            limit: int | None = None,
        ) -> list[DatabaseEvent]:
            return []

    def interrupt_sleep(seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        cli_module,
        "PostgreSQLAuditConnector",
        FakeConnector,
    )
    monkeypatch.setattr(cli_module.time, "sleep", interrupt_sleep)
    _install_engine(monkeypatch)

    config_file = tmp_path / "config.toml"
    state_file = tmp_path / "postgresql.json"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "watch",
            "--config",
            str(config_file),
            "--state-file",
            str(state_file),
            "--interval",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "Monitoring stopped safely" in result.output
