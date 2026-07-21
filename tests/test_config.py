"""Tests for AI-DAC configuration management."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from aidac.config import (
    ConfigError,
    create_default_config,
    load_settings,
)

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
    """Remove PostgreSQL variables before every test."""

    for variable in POSTGRES_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def test_missing_file_uses_defaults(
    tmp_path: Path,
) -> None:
    """A missing configuration should use defaults."""

    settings = load_settings(tmp_path / "missing.toml")

    assert settings.postgresql.host == "127.0.0.1"
    assert settings.postgresql.port == 5432
    assert settings.postgresql.database == "aidac_pgsql"
    assert settings.postgresql.username == "aidac_reader"
    assert settings.postgresql.default_limit == 100


def test_configuration_file_is_loaded(
    tmp_path: Path,
) -> None:
    """PostgreSQL settings should load from TOML."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
host = "192.168.136.138"
port = 5433
database = "security_db"
username = "security_reader"
schema = "audit"
relation = "events_v"
default_limit = 250
connect_timeout_seconds = 8
statement_timeout_ms = 9000
""",
        encoding="utf-8",
    )

    settings = load_settings(config_file)

    assert settings.postgresql.host == "192.168.136.138"
    assert settings.postgresql.port == 5433
    assert settings.postgresql.database == "security_db"
    assert settings.postgresql.username == "security_reader"
    assert settings.postgresql.schema == "audit"
    assert settings.postgresql.relation == "events_v"
    assert settings.postgresql.default_limit == 250


def test_environment_overrides_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment variables should override TOML."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
host = "127.0.0.1"
port = 5432
""",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "AIDAC_POSTGRES_HOST",
        "192.168.136.138",
    )
    monkeypatch.setenv(
        "AIDAC_POSTGRES_PORT",
        "5544",
    )

    settings = load_settings(config_file)

    assert settings.postgresql.host == "192.168.136.138"
    assert settings.postgresql.port == 5544


def test_invalid_integer_is_rejected(
    tmp_path: Path,
) -> None:
    """Invalid integer values should be rejected."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
port = "not-a-number"
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="port",
    ):
        load_settings(config_file)


def test_password_in_configuration_is_rejected(
    tmp_path: Path,
) -> None:
    """Passwords must not be stored in config.toml."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """\
[postgresql]
password = "unsafe-secret"
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="Secrets must not be stored",
    ):
        load_settings(config_file)


def test_invalid_toml_is_rejected(
    tmp_path: Path,
) -> None:
    """Malformed TOML should raise ConfigError."""

    config_file = tmp_path / "config.toml"

    config_file.write_text(
        "[postgresql\nhost = 'localhost'",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="Invalid TOML",
    ):
        load_settings(config_file)


def test_default_configuration_is_created_securely(
    tmp_path: Path,
) -> None:
    """The generated configuration should be private."""

    config_file = tmp_path / "aidac" / "config.toml"

    result = create_default_config(config_file)

    assert result == config_file
    assert config_file.exists()
    assert "[postgresql]" in config_file.read_text(encoding="utf-8")

    permissions = stat.S_IMODE(config_file.stat().st_mode)

    assert permissions == 0o600


def test_existing_configuration_is_not_overwritten(
    tmp_path: Path,
) -> None:
    """Existing configuration requires explicit overwrite."""

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "original",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="already exists",
    ):
        create_default_config(config_file)

    assert config_file.read_text(encoding="utf-8") == "original"
