"""Tests for PostgreSQL CLI configuration integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import aidac.cli as cli_module
from aidac.cli import app
from aidac.connectors.postgresql import PostgreSQLAuditConfig

runner = CliRunner()

POSTGRES_ENVIRONMENT_VARIABLES = (
    "AIDAC_POSTGRES_HOST",
    "AIDAC_POSTGRES_PORT",
    "AIDAC_POSTGRES_DB",
    "AIDAC_POSTGRES_USER",
    "AIDAC_POSTGRES_SCHEMA",
    "AIDAC_POSTGRES_RELATION",
    "AIDAC_POSTGRES_DEFAULT_LIMIT",
    "AIDAC_POSTGRES_CONNECT_TIMEOUT",
    "AIDAC_POSTGRES_STATEMENT_TIMEOUT",
    "AIDAC_POSTGRES_DSN",
    "AIDAC_POSTGRES_PASSWORD",
)


@pytest.fixture(autouse=True)
def clear_postgres_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clear PostgreSQL environment overrides."""

    for variable in POSTGRES_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def install_fake_connector(
    monkeypatch: pytest.MonkeyPatch,
    captured: dict[str, Any],
) -> None:
    """Install a PostgreSQL connector test double."""

    class FakeConnector:
        """Minimal connector used by CLI tests."""

        def __init__(
            self,
            config: PostgreSQLAuditConfig,
        ) -> None:
            captured["config"] = config

        def health_check(self) -> bool:
            """Return a successful health status."""

            return True

        def fetch_events(
            self,
            *,
            since: object = None,
            limit: int | None = None,
        ) -> list[object]:
            """Capture collection arguments."""

            captured["since"] = since
            captured["limit"] = limit
            return []

    monkeypatch.setattr(
        cli_module,
        "PostgreSQLAuditConnector",
        FakeConnector,
    )


def write_config(path: Path) -> None:
    """Write a test PostgreSQL configuration."""

    path.write_text(
        """\
[postgresql]
host = "192.168.136.138"
port = 5544
database = "database_from_file"
username = "reader_from_file"
schema = "audit"
relation = "events_v"
default_limit = 25
connect_timeout_seconds = 9
statement_timeout_ms = 7000
""",
        encoding="utf-8",
    )


def test_postgres_scan_uses_configuration_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PostgreSQL scan should use values from TOML."""

    config_file = tmp_path / "config.toml"
    write_config(config_file)

    captured: dict[str, Any] = {}
    install_fake_connector(monkeypatch, captured)

    monkeypatch.setenv(
        "AIDAC_POSTGRES_PASSWORD",
        "test-password",
    )

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--no-state",
        ],
    )

    assert result.exit_code == 0

    config = captured["config"]

    assert config.schema == "audit"
    assert config.relation == "events_v"
    assert config.default_limit == 25
    assert config.connect_timeout_seconds == 9
    assert config.statement_timeout_ms == 7000
    assert captured["limit"] == 25

    assert config.dsn == (
        "postgresql://reader_from_file:test-password@192.168.136.138:5544/database_from_file"
    )


def test_command_line_values_override_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit CLI values should override TOML values."""

    config_file = tmp_path / "config.toml"
    write_config(config_file)

    captured: dict[str, Any] = {}
    install_fake_connector(monkeypatch, captured)

    monkeypatch.setenv(
        "AIDAC_POSTGRES_PASSWORD",
        "test-password",
    )

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--limit",
            "7",
            "--schema",
            "custom_schema",
            "--relation",
            "custom_events_v",
            "--no-state",
        ],
    )

    assert result.exit_code == 0

    config = captured["config"]

    assert config.schema == "custom_schema"
    assert config.relation == "custom_events_v"
    assert config.default_limit == 7
    assert captured["limit"] == 7


def test_environment_overrides_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment variables should override TOML values."""

    config_file = tmp_path / "config.toml"
    write_config(config_file)

    captured: dict[str, Any] = {}
    install_fake_connector(monkeypatch, captured)

    monkeypatch.setenv(
        "AIDAC_POSTGRES_HOST",
        "10.10.10.25",
    )
    monkeypatch.setenv(
        "AIDAC_POSTGRES_PORT",
        "6432",
    )
    monkeypatch.setenv(
        "AIDAC_POSTGRES_PASSWORD",
        "environment-password",
    )

    result = runner.invoke(
        app,
        [
            "postgres",
            "scan",
            "--config",
            str(config_file),
            "--no-state",
        ],
    )

    assert result.exit_code == 0

    config = captured["config"]

    assert "@10.10.10.25:6432/" in config.dsn
