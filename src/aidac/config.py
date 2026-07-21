"""Configuration management for AI-DAC."""

from __future__ import annotations

import ipaddress
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

[storage]
alert_store = "~/.local/state/aidac/alerts.db"
audit_log = "~/.local/state/aidac/audit.jsonl"
backup_directory = "~/.local/share/aidac/backups"

[api]
host = "127.0.0.1"
port = 8000
rate_limit_per_minute = 120
dashboard_enabled = false
dashboard_session_minutes = 480

# Do not store passwords, complete DSNs, API tokens, dashboard tokens, or webhook secrets.
# Supply secrets through AIDAC_* environment variables.
"""

PRODUCTION_CONFIG_TEXT: Final = """\
# AI-DAC 1.0 production-oriented configuration.
# Secrets intentionally remain outside this file.

[postgresql]
host = "127.0.0.1"
port = 5432
database = "aidac_pgsql"
username = "aidac_reader"
schema = "public"
relation = "aidac_events_v"
default_limit = 500
connect_timeout_seconds = 5
statement_timeout_ms = 5000

[storage]
alert_store = "/var/lib/aidac/alerts.db"
audit_log = "/var/log/aidac/audit.jsonl"
backup_directory = "/var/backups/aidac"

[api]
host = "127.0.0.1"
port = 8000
rate_limit_per_minute = 120
dashboard_enabled = false
dashboard_session_minutes = 120

# Recommended secret environment variables:
# AIDAC_POSTGRES_PASSWORD or AIDAC_POSTGRES_DSN
# AIDAC_API_VIEWER_TOKEN
# AIDAC_API_ANALYST_TOKEN
# AIDAC_API_ADMIN_TOKEN
# AIDAC_DASHBOARD_TOKEN
# AIDAC_WEBHOOK_SECRET
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
        for attribute in ("host", "database", "username", "schema", "relation"):
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
class StorageSettings:
    """Persistent alert and audit storage paths."""

    alert_store: Path = Path("~/.local/state/aidac/alerts.db")
    audit_log: Path = Path("~/.local/state/aidac/audit.jsonl")
    backup_directory: Path = Path("~/.local/share/aidac/backups")

    def __post_init__(self) -> None:
        for attribute in ("alert_store", "audit_log", "backup_directory"):
            value = Path(getattr(self, attribute)).expanduser()
            if not str(value).strip():
                raise ConfigError(f"Storage path cannot be empty: {attribute}")
            object.__setattr__(self, attribute, value)


@dataclass(frozen=True, slots=True)
class APISettings:
    """Non-secret REST API runtime settings."""

    host: str = "127.0.0.1"
    port: int = 8000
    rate_limit_per_minute: int = 120
    dashboard_enabled: bool = False
    dashboard_session_minutes: int = 480

    def __post_init__(self) -> None:
        normalized_host = self.host.strip()
        if normalized_host.casefold() == "localhost":
            normalized_host = "127.0.0.1"
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError as error:
            raise ConfigError("API host must be an IPv4 or IPv6 address, or localhost.") from error
        object.__setattr__(self, "host", normalized_host)
        if not 1 <= self.port <= 65_535:
            raise ConfigError("API port must be between 1 and 65535.")
        if not 1 <= self.rate_limit_per_minute <= 100_000:
            raise ConfigError("API rate_limit_per_minute must be between 1 and 100000.")
        if not 5 <= self.dashboard_session_minutes <= 1_440:
            raise ConfigError("API dashboard_session_minutes must be between 5 and 1440.")


@dataclass(frozen=True, slots=True)
class AIDACSettings:
    """Complete AI-DAC configuration."""

    postgresql: PostgreSQLSettings = field(default_factory=PostgreSQLSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    api: APISettings = field(default_factory=APISettings)


def load_settings(path: Path | None = None) -> AIDACSettings:
    """Load AI-DAC configuration with environment-variable overrides."""

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

    postgresql_section = _section(payload, "postgresql")
    storage_section = _section(payload, "storage")
    api_section = _section(payload, "api")
    _reject_secrets(postgresql_section, {"password", "dsn"})
    _reject_secrets(
        api_section,
        {
            "token",
            "api_token",
            "viewer_token",
            "analyst_token",
            "admin_token",
            "dashboard_token",
        },
    )

    pg_defaults = PostgreSQLSettings()
    storage_defaults = StorageSettings()
    api_defaults = APISettings()

    postgresql = PostgreSQLSettings(
        host=_read_text(postgresql_section, "host", "AIDAC_POSTGRES_HOST", pg_defaults.host),
        port=_read_integer(postgresql_section, "port", "AIDAC_POSTGRES_PORT", pg_defaults.port),
        database=_read_text(
            postgresql_section, "database", "AIDAC_POSTGRES_DB", pg_defaults.database
        ),
        username=_read_text(
            postgresql_section, "username", "AIDAC_POSTGRES_USER", pg_defaults.username
        ),
        schema=_read_text(
            postgresql_section, "schema", "AIDAC_POSTGRES_SCHEMA", pg_defaults.schema
        ),
        relation=_read_text(
            postgresql_section, "relation", "AIDAC_POSTGRES_RELATION", pg_defaults.relation
        ),
        default_limit=_read_integer(
            postgresql_section,
            "default_limit",
            "AIDAC_POSTGRES_DEFAULT_LIMIT",
            pg_defaults.default_limit,
        ),
        connect_timeout_seconds=_read_integer(
            postgresql_section,
            "connect_timeout_seconds",
            "AIDAC_POSTGRES_CONNECT_TIMEOUT",
            pg_defaults.connect_timeout_seconds,
        ),
        statement_timeout_ms=_read_integer(
            postgresql_section,
            "statement_timeout_ms",
            "AIDAC_POSTGRES_STATEMENT_TIMEOUT",
            pg_defaults.statement_timeout_ms,
        ),
    )

    storage = StorageSettings(
        alert_store=Path(
            _read_text(
                storage_section,
                "alert_store",
                "AIDAC_ALERT_STORE",
                str(storage_defaults.alert_store),
            )
        ),
        audit_log=Path(
            _read_text(
                storage_section,
                "audit_log",
                "AIDAC_AUDIT_LOG",
                str(storage_defaults.audit_log),
            )
        ),
        backup_directory=Path(
            _read_text(
                storage_section,
                "backup_directory",
                "AIDAC_BACKUP_DIRECTORY",
                str(storage_defaults.backup_directory),
            )
        ),
    )

    api = APISettings(
        host=_read_text(api_section, "host", "AIDAC_API_HOST", api_defaults.host),
        port=_read_integer(api_section, "port", "AIDAC_API_PORT", api_defaults.port),
        rate_limit_per_minute=_read_integer(
            api_section,
            "rate_limit_per_minute",
            "AIDAC_API_RATE_LIMIT",
            api_defaults.rate_limit_per_minute,
        ),
        dashboard_enabled=_read_boolean(
            api_section,
            "dashboard_enabled",
            "AIDAC_DASHBOARD_ENABLED",
            api_defaults.dashboard_enabled,
        ),
        dashboard_session_minutes=_read_integer(
            api_section,
            "dashboard_session_minutes",
            "AIDAC_DASHBOARD_SESSION_MINUTES",
            api_defaults.dashboard_session_minutes,
        ),
    )

    return AIDACSettings(postgresql=postgresql, storage=storage, api=api)


def create_default_config(
    path: Path | None = None,
    *,
    overwrite: bool = False,
    production: bool = False,
) -> Path:
    """Create a private default or production-oriented configuration file."""

    config_file = (path if path is not None else DEFAULT_CONFIG_FILE).expanduser()
    if config_file.exists() and not overwrite:
        raise ConfigError(f"Configuration already exists: {config_file}")

    try:
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.parent.chmod(0o700)
        config_file.write_text(
            PRODUCTION_CONFIG_TEXT if production else DEFAULT_CONFIG_TEXT,
            encoding="utf-8",
        )
        config_file.chmod(0o600)
    except OSError as error:
        raise ConfigError(f"Unable to create configuration: {config_file}") from error

    return config_file


def _section(payload: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = payload.get(name, {})
    if not isinstance(section, Mapping):
        raise ConfigError(f"The [{name}] configuration must be a table.")
    return section


def _reject_secrets(section: Mapping[str, Any], forbidden: set[str]) -> None:
    detected = forbidden & {str(key).casefold() for key in section}
    if detected:
        names = ", ".join(sorted(detected))
        raise ConfigError(f"Secrets must not be stored in config.toml: {names}")


def _source_value(
    section: Mapping[str, Any],
    key: str,
    environment: str,
    default: object,
) -> object:
    if environment in os.environ:
        return os.environ[environment]
    if key in section:
        return section[key]
    return default


def _read_text(
    section: Mapping[str, Any],
    key: str,
    environment: str,
    default: str,
) -> str:
    value = _source_value(section, key, environment, default)
    if not isinstance(value, str):
        raise ConfigError(f"Configuration value must be text: {key}")
    normalized = value.strip()
    if not normalized:
        raise ConfigError(f"Configuration value cannot be empty: {key}")
    return normalized


def _read_integer(
    section: Mapping[str, Any],
    key: str,
    environment: str,
    default: int,
) -> int:
    value = _source_value(section, key, environment, default)
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


def _read_boolean(
    section: Mapping[str, Any],
    key: str,
    environment: str,
    default: bool,
) -> bool:
    value = _source_value(section, key, environment, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ConfigError(f"Configuration value must be a boolean: {key}")
