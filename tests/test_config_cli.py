"""Tests for AI-DAC configuration CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aidac.cli import app

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
)


@pytest.fixture(autouse=True)
def clear_postgres_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remove PostgreSQL environment overrides."""

    for variable in POSTGRES_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def test_config_group_is_available() -> None:
    """The main CLI should expose configuration commands."""

    result = runner.invoke(app, ["config", "--help"])

    assert result.exit_code == 0
    assert "init" in result.output
    assert "show" in result.output


def test_config_init_creates_file(tmp_path: Path) -> None:
    """The init command should create a configuration file."""

    config_file = tmp_path / "aidac" / "config.toml"

    result = runner.invoke(
        app,
        [
            "config",
            "init",
            "--path",
            str(config_file),
        ],
    )

    assert result.exit_code == 0
    assert config_file.exists()
    assert "[postgresql]" in config_file.read_text(encoding="utf-8")


def test_config_init_rejects_existing_file(
    tmp_path: Path,
) -> None:
    """An existing configuration should require --force."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[postgresql]\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "config",
            "init",
            "--path",
            str(config_file),
        ],
    )

    assert result.exit_code == 1
    assert "already exists" in result.output


def test_config_init_force_overwrites_file(
    tmp_path: Path,
) -> None:
    """The --force option should overwrite an existing file."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "old content",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "config",
            "init",
            "--path",
            str(config_file),
            "--force",
        ],
    )

    assert result.exit_code == 0
    assert "[postgresql]" in config_file.read_text(encoding="utf-8")


def test_config_show_json(tmp_path: Path) -> None:
    """The show command should support JSON output."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
host = "192.168.136.138"
port = 5432
database = "aidac_pgsql"
username = "aidac_reader"
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "config",
            "show",
            "--path",
            str(config_file),
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(result.output)

    assert payload["config_file_exists"] is True
    assert payload["postgresql"]["host"] == "192.168.136.138"
    assert payload["postgresql"]["port"] == 5432


def test_config_show_environment_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment values should override the TOML file."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
host = "127.0.0.1"
""",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "AIDAC_POSTGRES_HOST",
        "192.168.136.138",
    )

    result = runner.invoke(
        app,
        [
            "config",
            "show",
            "--path",
            str(config_file),
            "--json",
        ],
    )

    assert result.exit_code == 0

    payload = json.loads(result.output)

    assert payload["postgresql"]["host"] == "192.168.136.138"


def test_config_show_rejects_secret(
    tmp_path: Path,
) -> None:
    """Passwords stored in config.toml must be rejected."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
password = "unsafe"
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "config",
            "show",
            "--path",
            str(config_file),
        ],
    )

    assert result.exit_code == 1
    assert "Secrets must not be stored" in result.output
