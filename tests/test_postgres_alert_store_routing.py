from __future__ import annotations

from pathlib import Path
from typing import Any

import aidac.postgres_alert_store as postgres_store
from aidac.alert_store import (
    AlertStatus,
    is_postgres_store_configured,
    persist_alert_batch,
    query_alerts,
    store_info,
    update_alert_status,
)


def test_postgres_backend_routing(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setenv("AIDAC_ALERT_STORE_DSN", "postgresql://example.invalid/aidac")
    monkeypatch.setenv("AIDAC_ALERT_STORE_SCHEMA", "security")
    calls: list[tuple[str, str]] = []

    def fake_persist(dsn: str, *, schema: str, batch: dict[str, Any]) -> list[dict[str, Any]]:
        calls.append((dsn, schema))
        return list(batch["alerts"])

    def fake_query(
        dsn: str,
        *,
        schema: str,
        status: AlertStatus | None,
        severity: str | None,
        minimum_risk: float,
        search: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[dict[str, Any]], int]:
        assert status is AlertStatus.NEW
        assert limit == 5
        calls.append((dsn, schema))
        return ([{"alert_id": "alrt_test"}], 1)

    def fake_update(
        dsn: str,
        *,
        schema: str,
        alert_id: str,
        status: AlertStatus,
        actor: str,
        note: str | None,
    ) -> dict[str, Any]:
        assert alert_id == "alrt_test"
        assert actor == "analyst"
        calls.append((dsn, schema))
        return {"alert_id": alert_id, "status": status.value, "note": note}

    monkeypatch.setattr(postgres_store, "persist_alert_batch", fake_persist)
    monkeypatch.setattr(postgres_store, "query_alerts", fake_query)
    monkeypatch.setattr(postgres_store, "update_alert_status", fake_update)
    monkeypatch.setattr(
        postgres_store,
        "store_info",
        lambda dsn, *, schema: {"backend": "postgresql", "schema": schema},
    )

    assert is_postgres_store_configured()
    batch = {"alerts": [{"alert_id": "alrt_test"}]}
    assert persist_alert_batch(tmp_path / "alerts.db", batch) == batch["alerts"]
    alerts, total = query_alerts(
        tmp_path / "alerts.db",
        status=AlertStatus.NEW,
        limit=5,
    )
    assert total == 1
    assert alerts[0]["alert_id"] == "alrt_test"
    updated = update_alert_status(
        tmp_path / "alerts.db",
        "alrt_test",
        status=AlertStatus.ACKNOWLEDGED,
        actor="analyst",
        note="reviewed",
    )
    assert updated["status"] == "acknowledged"
    assert store_info(tmp_path / "alerts.db")["backend"] == "postgresql"
    assert calls == [
        ("postgresql://example.invalid/aidac", "security"),
        ("postgresql://example.invalid/aidac", "security"),
        ("postgresql://example.invalid/aidac", "security"),
    ]


def test_postgres_schema_validation() -> None:
    assert postgres_store.validate_schema("aidac_security") == "aidac_security"
