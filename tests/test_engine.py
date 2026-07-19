"""Automated tests for the AI-DAC security engine."""

import pytest

from aidac import AIDAC, DatabaseEvent, Severity


@pytest.fixture
def engine() -> AIDAC:
    """Create an AI-DAC engine for each test."""

    return AIDAC()


def test_normal_select_query_has_zero_risk(engine: AIDAC) -> None:
    """A normal SELECT query should not trigger an alert."""

    event = DatabaseEvent(
        query="SELECT id, name FROM customers WHERE id = 10;",
        username="reporting_user",
        database="sales",
        source_system="postgresql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score == 0.0
    assert decision.severity == Severity.INFO
    assert decision.classification == "normal_sql_activity"
    assert decision.indicators == []
    assert decision.automatic_action is None


def test_drop_database_is_critical(engine: AIDAC) -> None:
    """DROP DATABASE should generate a critical decision."""

    event = DatabaseEvent(
        query="DROP DATABASE production;",
        username="administrator",
        database="postgres",
        source_system="postgresql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score == pytest.approx(0.95)

    assert decision.severity == Severity.CRITICAL

    assert decision.classification == "suspicious_sql_activity"

    assert "Database deletion statement detected." in decision.indicators

    assert decision.automatic_action is None


def test_drop_table_is_high_risk(engine: AIDAC) -> None:
    """DROP TABLE should generate a high-risk decision."""

    event = DatabaseEvent(
        query="DROP TABLE customers;",
        username="application_user",
        database="sales",
        source_system="postgresql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score == pytest.approx(0.80)

    assert decision.severity == Severity.HIGH

    assert decision.classification == "suspicious_sql_activity"

    assert "Table deletion statement detected." in decision.indicators

    assert decision.automatic_action is None


def test_delete_without_where_is_high_risk(engine: AIDAC) -> None:
    """DELETE without WHERE should be classified as high risk."""

    event = DatabaseEvent(
        query="DELETE FROM transactions;",
        username="batch_user",
        database="finance",
        source_system="postgresql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score == pytest.approx(0.85)

    assert decision.severity == Severity.HIGH

    assert "DELETE statement without a WHERE clause detected." in decision.indicators


def test_union_select_is_detected(engine: AIDAC) -> None:
    """UNION SELECT should trigger an SQL-injection indicator."""

    event = DatabaseEvent(
        query=("SELECT username FROM users UNION SELECT password FROM credentials;"),
        username="web_user",
        database="application",
        source_system="postgresql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score >= 0.50

    assert decision.severity == Severity.MEDIUM

    assert decision.classification == "suspicious_sql_activity"

    assert "Potential UNION-based SQL injection pattern detected." in decision.indicators


def test_xp_cmdshell_is_critical(engine: AIDAC) -> None:
    """SQL Server operating-system command execution should be critical."""

    event = DatabaseEvent(
        query="EXEC xp_cmdshell 'whoami';",
        username="sql_admin",
        database="master",
        source_system="mssql",
    )

    decision = engine.analyze(event)

    assert decision.risk_score == pytest.approx(0.95)

    assert decision.severity == Severity.CRITICAL

    assert "Operating-system command execution detected." in decision.indicators


def test_source_system_is_normalized() -> None:
    """The database system name should be normalized to lowercase."""

    event = DatabaseEvent(
        query="SELECT 1;",
        username="user1",
        database="test",
        source_system="PostgreSQL",
    )

    assert event.source_system == "postgresql"


def test_empty_query_is_rejected() -> None:
    """An empty SQL query should raise a validation error."""

    with pytest.raises(ValueError, match="SQL query cannot be empty"):
        DatabaseEvent(
            query="   ",
            username="user1",
            database="test",
            source_system="postgresql",
        )


def test_empty_username_is_rejected() -> None:
    """An empty database username should be rejected."""

    with pytest.raises(ValueError, match="username cannot be empty"):
        DatabaseEvent(
            query="SELECT 1;",
            username="   ",
            database="test",
            source_system="postgresql",
        )


def test_negative_duration_is_rejected() -> None:
    """A negative execution duration should be rejected."""

    with pytest.raises(ValueError, match="duration_ms cannot be negative"):
        DatabaseEvent(
            query="SELECT 1;",
            username="user1",
            database="test",
            source_system="postgresql",
            duration_ms=-10.0,
        )


def test_negative_rows_affected_is_rejected() -> None:
    """A negative affected-row count should be rejected."""

    with pytest.raises(ValueError, match="rows_affected cannot be negative"):
        DatabaseEvent(
            query="UPDATE customers SET active = true;",
            username="user1",
            database="test",
            source_system="postgresql",
            rows_affected=-1,
        )
