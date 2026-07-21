"""Tests for AI-DAC 1.0 SQLite alert storage."""

from __future__ import annotations

from pathlib import Path

from aidac.alert_store import (
    AlertStatus,
    backup_store,
    get_alert,
    migrate_jsonl_to_sqlite,
    persist_alert_batch,
    query_alerts,
    restore_store,
    store_info,
    update_alert_status,
    verify_store,
)
from aidac.alerting import build_alert_batch


def _record(*, query: str = "DROP TABLE customers;", risk: float = 0.95) -> dict[str, object]:
    return {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "username": "security_test",
        "database": "sales",
        "source_system": "postgresql",
        "client_ip": "192.0.2.10",
        "query": query,
        "risk_score": risk,
        "severity": "critical" if risk >= 0.9 else "medium",
        "classification": "destructive_sql",
    }


def test_sqlite_store_deduplicates_and_reopens(tmp_path: Path) -> None:
    """SQLite should preserve lifecycle state while counting occurrences."""

    store = tmp_path / "alerts.db"
    first = persist_alert_batch(store, build_alert_batch([_record()]))[0]
    alert_id = str(first["alert_id"])

    update_alert_status(
        store,
        alert_id,
        status=AlertStatus.RESOLVED,
        actor="analyst",
    )
    alerts = persist_alert_batch(store, build_alert_batch([_record()]))

    assert len(alerts) == 1
    assert alerts[0]["occurrence_count"] == 2
    assert alerts[0]["status"] == "new"
    assert alerts[0]["last_action"] == "reopened"
    assert get_alert(store, alert_id)["alert_id"] == alert_id
    assert store_info(store)["schema_version"] == 1
    assert verify_store(store)["integrity_check"] == "ok"


def test_sqlite_search_filter_and_pagination(tmp_path: Path) -> None:
    """SQLite queries should return totals independently from page size."""

    store = tmp_path / "alerts.sqlite"
    persist_alert_batch(
        store,
        build_alert_batch(
            [
                _record(query="DROP TABLE customers;", risk=0.95),
                _record(query="SELECT * FROM orders;", risk=0.5),
            ]
        ),
    )

    first_page, total = query_alerts(store, limit=1, offset=0)
    second_page, second_total = query_alerts(store, limit=1, offset=1)
    searched, search_total = query_alerts(store, search="orders", minimum_risk=0.4)

    assert len(first_page) == 1
    assert len(second_page) == 1
    assert total == second_total == 2
    assert search_total == 1
    assert searched[0]["query"] == "SELECT * FROM orders;"


def test_jsonl_migration_backup_and_restore(tmp_path: Path) -> None:
    """Legacy JSONL data should migrate and survive backup and restore."""

    legacy = tmp_path / "alerts.jsonl"
    store = tmp_path / "alerts.db"
    restored = tmp_path / "restored.db"
    backup_directory = tmp_path / "backups"
    backup_directory.mkdir()

    persist_alert_batch(legacy, build_alert_batch([_record()]))
    imported = migrate_jsonl_to_sqlite(legacy, store)
    backup = backup_store(store, backup_directory)
    restore_store(backup, restored)

    assert imported == 1
    assert store_info(restored)["alert_count"] == 1
    assert verify_store(restored)["valid"] is True
