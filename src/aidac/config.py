"""Configuration management for AI-DAC."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

DEFAULT_CONFIG_FILE: Final = Path("~/.config/aidac/config.toml")

MAX_CONFIG_SIZE_BYTES: Final = 1_000_000

DEFAULT_CONFIG_TEXT: Final = """\
[postgresql]
host = "127.0.0.1"
port = 5432
database = "aidac_pgsql"
username = "aidac_reader"
schema = "public"
relation = "aidac_events_v"
default_limit = 100
connect_timeout_seconds = 5
statement_timeout_ms = 5000

# Do not store passwords or complete DSNs in this file.
# Use AIDAC_POSTGRES_PASSWORD or AIDAC_POSTGRES_DSN.
"""


class ConfigError(RuntimeError):
    """Raised when AI-DAC configuration is invalid."""


@dataclass(frozen=True, slots=True)
class PostgreSQLSettings:
    """PostgreSQL settings used by AI-DAC."""

    host: str = "127.0.0.1"
    port: int = 5432
    database: str = "aidac_pgsql"
    username: str = "aidac_reader"
    schema: str = "public"
    relation: str = "aidac_events_v"
    default_limit: int = 100
    connect_timeout_seconds: int = 5
    statement_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        """Normalize and validate PostgreSQL settings."""

        for attribute in (
            "host",
            "database",
            "username",
            "schema",
            "relation",
        ):
            value = str(getattr(self, attribute)).strip()
            object.__setattr__(self, attribute, value)

            if not value:
                raise ConfigError(f"PostgreSQL setting cannot be empty: {attribute}")

        if not 1 <= self.port <= 65_535:
            raise ConfigError("PostgreSQL port must be between 1 and 65535.")

        if not 1 <= self.default_limit <= 100_000:
            raise ConfigError("PostgreSQL default_limit must be between 1 and 100000.")

        if self.connect_timeout_seconds <= 0:
            raise ConfigError("PostgreSQL connect_timeout_seconds must be greater than zero.")

        if self.statement_timeout_ms <= 0:
            raise ConfigError("PostgreSQL statement_timeout_ms must be greater than zero.")


@dataclass(frozen=True, slots=True)
class AIDACSettings:
    """Complete AI-DAC configuration."""

    postgresql: PostgreSQLSettings = field(default_factory=PostgreSQLSettings)


def load_settings(
    path: Path | None = None,
) -> AIDACSettings:
    """
    Load AI-DAC configuration.

    Environment variables override values from the TOML file.
    """

    config_file = (path if path is not None else DEFAULT_CONFIG_FILE).expanduser()

    payload: Mapping[str, Any] = {}

    if config_file.exists():
        try:
            if config_file.stat().st_size > MAX_CONFIG_SIZE_BYTES:
                raise ConfigError("AI-DAC configuration file is too large.")

            with config_file.open("rb") as stream:
                payload = tomllib.load(stream)
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f"Invalid TOML configuration: {config_file}") from error
        except OSError as error:
            raise ConfigError(f"Unable to read configuration: {config_file}") from error

    postgresql_section = payload.get("postgresql", {})

    if not isinstance(postgresql_section, Mapping):
        raise ConfigError("The [postgresql] configuration must be a table.")

    forbidden_keys = {
        "password",
        "dsn",
    }

    detected_forbidden_keys = forbidden_keys & set(postgresql_section)

    if detected_forbidden_keys:
        names = ", ".join(sorted(detected_forbidden_keys))
        raise ConfigError(f"Secrets must not be stored in config.toml: {names}")

    defaults = PostgreSQLSettings()

    settings = PostgreSQLSettings(
        host=_read_text(
            postgresql_section,
            key="host",
            environment="AIDAC_POSTGRES_HOST",
            default=defaults.host,
        ),
        port=_read_integer(
            postgresql_section,
            key="port",
            environment="AIDAC_POSTGRES_PORT",
            default=defaults.port,
        ),
        database=_read_text(
            postgresql_section,
            key="database",
            environment="AIDAC_POSTGRES_DB",
            default=defaults.database,
        ),
        username=_read_text(
            postgresql_section,
            key="username",
            environment="AIDAC_POSTGRES_USER",
            default=defaults.username,
        ),
        schema=_read_text(
            postgresql_section,
            key="schema",
            environment="AIDAC_POSTGRES_SCHEMA",
            default=defaults.schema,
        ),
        relation=_read_text(
            postgresql_section,
            key="relation",
            environment="AIDAC_POSTGRES_RELATION",
            default=defaults.relation,
        ),
        default_limit=_read_integer(
            postgresql_section,
            key="default_limit",
            environment="AIDAC_POSTGRES_DEFAULT_LIMIT",
            default=defaults.default_limit,
        ),
        connect_timeout_seconds=_read_integer(
            postgresql_section,
            key="connect_timeout_seconds",
            environment=("AIDAC_POSTGRES_CONNECT_TIMEOUT"),
            default=defaults.connect_timeout_seconds,
        ),
        statement_timeout_ms=_read_integer(
            postgresql_section,
            key="statement_timeout_ms",
            environment=("AIDAC_POSTGRES_STATEMENT_TIMEOUT"),
            default=defaults.statement_timeout_ms,
        ),
    )

    return AIDACSettings(postgresql=settings)


def create_default_config(
    path: Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    """Create a default AI-DAC configuration file."""

    config_file = (path if path is not None else DEFAULT_CONFIG_FILE).expanduser()

    if config_file.exists() and not overwrite:
        raise ConfigError(f"Configuration already exists: {config_file}")

    try:
        config_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        config_file.parent.chmod(0o700)

        config_file.write_text(
            DEFAULT_CONFIG_TEXT,
            encoding="utf-8",
        )
        config_file.chmod(0o600)
    except OSError as error:
        raise ConfigError(f"Unable to create configuration: {config_file}") from error

    return config_file


def _source_value(
    section: Mapping[str, Any],
    *,
    key: str,
    environment: str,
    default: object,
) -> object:
    """Return an environment, TOML or default value."""

    if environment in os.environ:
        return os.environ[environment]

    if key in section:
        return section[key]

    return default


def _read_text(
    section: Mapping[str, Any],
    *,
    key: str,
    environment: str,
    default: str,
) -> str:
    """Read a text configuration value."""

    value = _source_value(
        section,
        key=key,
        environment=environment,
        default=default,
    )

    if not isinstance(value, str):
        raise ConfigError(f"Configuration value must be text: {key}")

    return value.strip()


def _read_integer(
    section: Mapping[str, Any],
    *,
    key: str,
    environment: str,
    default: int,
) -> int:
    """Read an integer configuration value."""

    value = _source_value(
        section,
        key=key,
        environment=environment,
        default=default,
    )

    if isinstance(value, bool):
        raise ConfigError(f"Configuration value must be an integer: {key}")

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError as error:
            raise ConfigError(f"Configuration value must be an integer: {key}") from error

    raise ConfigError(f"Configuration value must be an integer: {key}")
