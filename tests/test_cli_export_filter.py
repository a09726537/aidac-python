"""Tests for AI-DAC PostgreSQL filtering and exports."""

from __future__ import annotations

import csv
import json
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
""",
        encoding="utf-8",
    )


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        DatabaseEvent(
            query="SELECT 1;",
            username="reader",
            database="aidac_pgsql",
            source_system="postgresql",
            timestamp=datetime(2026, 7, 20, 12, 0, tzinfo=UTC),
        ),
        DatabaseEvent(
            query="DROP DATABASE production;",
            username="attacker",
            database="aidac_pgsql",
            source_system="postgresql",
            timestamp=datetime(2026, 7, 20, 12, 1, tzinfo=UTC),
        ),
    ]

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
            return events

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

    monkeypatch.setattr(
        cli_module,
        "PostgreSQLAuditConnector",
        FakeConnector,
    )
    monkeypatch.setattr(cli_module, "AIDAC", FakeEngine)
    monkeypatch.setenv(
        "AIDAC_POSTGRES_DSN",
        "postgresql://test:test@localhost/test",
    )


def test_csv_export_applies_minimum_risk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fakes(monkeypatch)
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "results.csv"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--no-state",
            "--json",
            "--min-risk",
            "0.5",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["events_analyzed"] == 1

    with output_file.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))

    assert len(rows) == 1
    assert rows[0]["query"] == "DROP DATABASE production;"
    assert rows[0]["severity"] == "critical"


def test_json_export_applies_minimum_severity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fakes(monkeypatch)
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "results.json"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--no-state",
            "--json",
            "--min-severity",
            "high",
            "--output",
            str(output_file),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["summary"]["events_analyzed"] == 1
    assert payload["events"][0]["severity"] == "critical"


def test_invalid_export_extension_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fakes(monkeypatch)
    config_file = tmp_path / "config.toml"
    _write_config(config_file)

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--no-state",
            "--output",
            str(tmp_path / "results.txt"),
        ],
    )

    assert result.exit_code == 1
    assert ".csv or .json" in result.output
