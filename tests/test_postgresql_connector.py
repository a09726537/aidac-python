"""Tests for the AI-DAC PostgreSQL connector."""

from datetime import UTC, datetime

import pytest

from aidac.connectors.postgresql import (
    PostgreSQLAuditConfig,
    PostgreSQLAuditConnector,
    PostgreSQLConnectorError,
)


def make_row(**overrides: object) -> dict[str, object]:
    """Create a valid normalized PostgreSQL audit row."""

    row: dict[str, object] = {
        "event_time": datetime(
            2026,
            7,
            20,
            12,
            30,
            tzinfo=UTC,
        ),
        "query_text": "SELECT 1;",
        "username": "test_user",
        "database_name": "postgres",
        "client_ip": "192.168.10.20",
        "duration_ms": 1.5,
        "rows_affected": 1,
    }

    row.update(overrides)
    return row


def test_empty_dsn_is_rejected() -> None:
    """The PostgreSQL DSN must not be empty."""

    with pytest.raises(
        ValueError,
        match="PostgreSQL DSN cannot be empty",
    ):
        PostgreSQLAuditConfig(dsn="   ")


def test_empty_schema_is_rejected() -> None:
    """The PostgreSQL schema must not be empty."""

    with pytest.raises(
        ValueError,
        match="PostgreSQL schema cannot be empty",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            schema="   ",
        )


def test_empty_relation_is_rejected() -> None:
    """The PostgreSQL relation must not be empty."""

    with pytest.raises(
        ValueError,
        match="PostgreSQL relation cannot be empty",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            relation="   ",
        )


def test_invalid_default_limit_is_rejected() -> None:
    """The default collection limit must be valid."""

    with pytest.raises(
        ValueError,
        match="default_limit must be between",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            default_limit=0,
        )


def test_excessive_default_limit_is_rejected() -> None:
    """The default collection limit must not exceed 100000."""

    with pytest.raises(
        ValueError,
        match="default_limit must be between",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            default_limit=100_001,
        )


def test_invalid_connect_timeout_is_rejected() -> None:
    """The connection timeout must be positive."""

    with pytest.raises(
        ValueError,
        match="connect_timeout_seconds must be greater than zero",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            connect_timeout_seconds=0,
        )


def test_invalid_statement_timeout_is_rejected() -> None:
    """The statement timeout must be positive."""

    with pytest.raises(
        ValueError,
        match="statement_timeout_ms must be greater than zero",
    ):
        PostgreSQLAuditConfig(
            dsn="postgresql://localhost/test",
            statement_timeout_ms=0,
        )


def test_configuration_values_are_normalized() -> None:
    """Whitespace should be removed from configuration strings."""

    config = PostgreSQLAuditConfig(
        dsn="  postgresql://localhost/test  ",
        schema="  audit  ",
        relation="  events_v  ",
    )

    assert config.dsn == "postgresql://localhost/test"
    assert config.schema == "audit"
    assert config.relation == "events_v"


def test_row_is_converted_to_database_event() -> None:
    """A normalized PostgreSQL row should become DatabaseEvent."""

    event_time = datetime(
        2026,
        7,
        20,
        12,
        30,
        tzinfo=UTC,
    )

    event = PostgreSQLAuditConnector._row_to_event(
        make_row(
            event_time=event_time,
            query_text="DROP TABLE customers;",
            username="security_test",
            database_name="sales",
            client_ip="192.168.10.20",
            duration_ms=12.5,
            rows_affected=0,
        )
    )

    assert event.query == "DROP TABLE customers;"
    assert event.username == "security_test"
    assert event.database == "sales"
    assert event.source_system == "postgresql"
    assert event.client_ip == "192.168.10.20"
    assert event.duration_ms == pytest.approx(12.5)
    assert event.rows_affected == 0
    assert event.timestamp == event_time


def test_optional_values_can_be_none() -> None:
    """Optional PostgreSQL values should accept null values."""

    event = PostgreSQLAuditConnector._row_to_event(
        make_row(
            client_ip=None,
            duration_ms=None,
            rows_affected=None,
        )
    )

    assert event.client_ip is None
    assert event.duration_ms is None
    assert event.rows_affected is None


def test_numeric_values_are_converted() -> None:
    """Numeric PostgreSQL values should be normalized."""

    event = PostgreSQLAuditConnector._row_to_event(
        make_row(
            duration_ms="25.75",
            rows_affected="42",
        )
    )

    assert event.duration_ms == pytest.approx(25.75)
    assert event.rows_affected == 42


def test_client_ip_is_converted_to_text() -> None:
    """The PostgreSQL client address should become text."""

    event = PostgreSQLAuditConnector._row_to_event(make_row(client_ip=12345))

    assert event.client_ip == "12345"


def test_naive_timestamp_is_converted_to_utc() -> None:
    """A timestamp without timezone should be interpreted as UTC."""

    event = PostgreSQLAuditConnector._row_to_event(
        make_row(
            event_time=datetime(
                2026,
                7,
                20,
                12,
                30,
            )
        )
    )

    assert event.timestamp.tzinfo == UTC
    assert event.timestamp.utcoffset() is not None


def test_timezone_aware_timestamp_is_preserved() -> None:
    """A timezone-aware timestamp should remain unchanged."""

    event_time = datetime.now(UTC)

    event = PostgreSQLAuditConnector._row_to_event(make_row(event_time=event_time))

    assert event.timestamp == event_time


def test_missing_query_text_is_rejected() -> None:
    """An empty query_text value must be rejected."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="query_text",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(query_text=""))


def test_whitespace_query_text_is_rejected() -> None:
    """Whitespace-only query text must be rejected."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="query_text",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(query_text="   "))


def test_missing_username_is_rejected() -> None:
    """An empty username value must be rejected."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="username",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(username=""))


def test_missing_database_name_is_rejected() -> None:
    """An empty database name must be rejected."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="database_name",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(database_name=""))


def test_invalid_event_time_is_rejected() -> None:
    """event_time must contain a datetime value."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="event_time",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(event_time="2026-07-20"))


def test_missing_event_time_is_rejected() -> None:
    """A missing event timestamp must be rejected."""

    with pytest.raises(
        PostgreSQLConnectorError,
        match="event_time",
    ):
        PostgreSQLAuditConnector._row_to_event(make_row(event_time=None))


def test_fetch_zero_limit_is_rejected() -> None:
    """A zero runtime limit must fail before connecting."""

    connector = PostgreSQLAuditConnector(PostgreSQLAuditConfig(dsn="postgresql://localhost/test"))

    with pytest.raises(
        ValueError,
        match="limit must be between",
    ):
        connector.fetch_events(limit=0)


def test_fetch_negative_limit_is_rejected() -> None:
    """A negative runtime limit must fail before connecting."""

    connector = PostgreSQLAuditConnector(PostgreSQLAuditConfig(dsn="postgresql://localhost/test"))

    with pytest.raises(
        ValueError,
        match="limit must be between",
    ):
        connector.fetch_events(limit=-1)


def test_fetch_excessive_limit_is_rejected() -> None:
    """A runtime limit above 100000 must be rejected."""

    connector = PostgreSQLAuditConnector(PostgreSQLAuditConfig(dsn="postgresql://localhost/test"))

    with pytest.raises(
        ValueError,
        match="limit must be between",
    ):
        connector.fetch_events(limit=100_001)
