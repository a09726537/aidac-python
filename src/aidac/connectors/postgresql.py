"""Read-only PostgreSQL audit-event connector for AI-DAC."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg import Connection, sql
from psycopg.rows import DictRow, dict_row

from aidac.models import DatabaseEvent


class PostgreSQLConnectorError(RuntimeError):
    """Raised when PostgreSQL audit events cannot be collected."""


@dataclass(frozen=True, slots=True)
class PostgreSQLAuditConfig:
    """Configuration for the read-only PostgreSQL connector."""

    dsn: str
    schema: str = "public"
    relation: str = "aidac_events_v"
    default_limit: int = 1_000
    connect_timeout_seconds: int = 5
    statement_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        """Normalize and validate connector configuration."""

        object.__setattr__(self, "dsn", self.dsn.strip())
        object.__setattr__(self, "schema", self.schema.strip())
        object.__setattr__(self, "relation", self.relation.strip())

        if not self.dsn:
            raise ValueError("PostgreSQL DSN cannot be empty.")

        if not self.schema:
            raise ValueError("PostgreSQL schema cannot be empty.")

        if not self.relation:
            raise ValueError("PostgreSQL relation cannot be empty.")

        if not 1 <= self.default_limit <= 100_000:
            raise ValueError("default_limit must be between 1 and 100000.")

        if self.connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be greater than zero.")

        if self.statement_timeout_ms <= 0:
            raise ValueError("statement_timeout_ms must be greater than zero.")


class PostgreSQLAuditConnector:
    """
    Collect normalized PostgreSQL audit events in read-only mode.

    The configured table or view must expose these columns:

    - event_time
    - query_text
    - username
    - database_name
    - client_ip
    - duration_ms
    - rows_affected
    """

    def __init__(self, config: PostgreSQLAuditConfig) -> None:
        """Initialize the connector."""

        self.config = config

    def health_check(self) -> bool:
        """Verify that the configured PostgreSQL server is reachable."""

        try:
            with self._connect() as connection:
                row = connection.execute("SELECT 1 AS ok").fetchone()
        except psycopg.Error as error:
            raise PostgreSQLConnectorError("PostgreSQL health check failed.") from error

        return row is not None and row.get("ok") == 1

    def fetch_events(
        self,
        *,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[DatabaseEvent]:
        """
        Fetch normalized database events ordered by event time.

        Args:
            since:
                Return only events occurring after this timestamp.
            limit:
                Maximum number of events to return.

        Returns:
            Normalized AI-DAC database events.
        """

        effective_limit = self.config.default_limit if limit is None else limit

        if not 1 <= effective_limit <= 100_000:
            raise ValueError("limit must be between 1 and 100000.")

        statement = sql.SQL(
            """
            SELECT
                event_time,
                query_text,
                username,
                database_name,
                client_ip,
                duration_ms,
                rows_affected
            FROM {}.{}
            """
        ).format(
            sql.Identifier(self.config.schema),
            sql.Identifier(self.config.relation),
        )

        parameters: list[object] = []

        if since is not None:
            statement += sql.SQL(" WHERE event_time > %s")
            parameters.append(since)

        statement += sql.SQL(" ORDER BY event_time ASC LIMIT %s")
        parameters.append(effective_limit)

        try:
            with self._connect() as connection:
                rows = connection.execute(
                    statement,
                    parameters,
                ).fetchall()
        except psycopg.Error as error:
            raise PostgreSQLConnectorError("Unable to collect PostgreSQL audit events.") from error

        return [self._row_to_event(row) for row in rows]

    def _connect(self) -> Connection[DictRow]:
        """Create a protected read-only PostgreSQL connection."""

        options = (
            "-c default_transaction_read_only=on "
            f"-c statement_timeout={self.config.statement_timeout_ms}"
        )

        return psycopg.connect(
            self.config.dsn,
            autocommit=True,
            row_factory=dict_row,
            connect_timeout=self.config.connect_timeout_seconds,
            application_name="aidac-python",
            options=options,
        )

    @staticmethod
    def _row_to_event(
        row: Mapping[str, Any],
    ) -> DatabaseEvent:
        """Convert one normalized PostgreSQL row into an AI-DAC event."""

        event_time = row.get("event_time")

        if not isinstance(event_time, datetime):
            raise PostgreSQLConnectorError("event_time must be a PostgreSQL timestamp.")

        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)

        query_text = PostgreSQLAuditConnector._required_text(
            row,
            "query_text",
        )
        username = PostgreSQLAuditConnector._required_text(
            row,
            "username",
        )
        database_name = PostgreSQLAuditConnector._required_text(
            row,
            "database_name",
        )

        client_ip_value = row.get("client_ip")
        duration_value = row.get("duration_ms")
        rows_value = row.get("rows_affected")

        client_ip = None if client_ip_value is None else str(client_ip_value)
        duration_ms = None if duration_value is None else float(duration_value)
        rows_affected = None if rows_value is None else int(rows_value)

        return DatabaseEvent(
            query=query_text,
            username=username,
            database=database_name,
            source_system="postgresql",
            client_ip=client_ip,
            duration_ms=duration_ms,
            rows_affected=rows_affected,
            timestamp=event_time,
        )

    @staticmethod
    def _required_text(
        row: Mapping[str, Any],
        column: str,
    ) -> str:
        """Read and validate a required text column."""

        value = row.get(column)

        if value is None or not str(value).strip():
            raise PostgreSQLConnectorError(f"Required PostgreSQL column is empty: {column}")

        return str(value).strip()
