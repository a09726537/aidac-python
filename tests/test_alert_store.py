"""Tests for AI-DAC alert lifecycle storage."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

from aidac.alert_store import (
    AlertStatus,
    get_alert,
    load_alerts,
    persist_alert_batch,
    prune_alert_log,
    update_alert_status,
)
from aidac.alerting import build_alert_batch


def _record(timestamp: str = "2026-01-01T00:00:00+00:00") -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "username": "security_test",
        "database": "sales",
        "source_system": "postgresql",
        "client_ip": "192.0.2.10",
        "query": "DROP TABLE customers;",
        "risk_score": 0.95,
        "severity": "critical",
        "classification": "destructive_sql",
    }


def test_repeated_alerts_are_deduplicated(tmp_path: Path) -> None:
    """Equivalent occurrences should share one alert identifier."""

    alert_log = tmp_path / "alerts.jsonl"
    first = persist_alert_batch(alert_log, build_alert_batch([_record()]))
    second = persist_alert_batch(alert_log, build_alert_batch([_record()]))

    assert len(first) == 1
    assert len(second) == 1
    assert second[0]["alert_id"] == first[0]["alert_id"]
    assert second[0]["occurrence_count"] == 2
    assert second[0]["status"] == AlertStatus.NEW.value
    assert stat.S_IMODE(alert_log.stat().st_mode) == 0o600


def test_acknowledgement_survives_new_occurrence(tmp_path: Path) -> None:
    """Repeated events should preserve an acknowledged lifecycle state."""

    alert_log = tmp_path / "alerts.jsonl"
    alert = persist_alert_batch(alert_log, build_alert_batch([_record()]))[0]

    update_alert_status(
        alert_log,
        str(alert["alert_id"]),
        status=AlertStatus.ACKNOWLEDGED,
        actor="analyst",
        note="Investigating",
    )
    current = persist_alert_batch(alert_log, build_alert_batch([_record()]))[0]

    assert current["status"] == AlertStatus.ACKNOWLEDGED.value
    assert current["occurrence_count"] == 2
    assert current["updated_by"] == "analyst"


def test_resolved_alert_is_reopened_by_matching_event(tmp_path: Path) -> None:
    """A new matching event should reopen a resolved alert."""

    alert_log = tmp_path / "alerts.jsonl"
    alert = persist_alert_batch(alert_log, build_alert_batch([_record()]))[0]
    alert_id = str(alert["alert_id"])

    update_alert_status(
        alert_log,
        alert_id,
        status=AlertStatus.RESOLVED,
        actor="analyst",
    )
    current = persist_alert_batch(alert_log, build_alert_batch([_record()]))[0]

    assert current["alert_id"] == alert_id
    assert current["status"] == AlertStatus.NEW.value
    assert current["last_action"] == "reopened"
    assert current["occurrence_count"] == 2


def test_v060_alert_log_is_loaded_compatibly(tmp_path: Path) -> None:
    """Legacy records without lifecycle fields should be migrated in memory."""

    alert_log = tmp_path / "alerts.jsonl"
    legacy = {
        "type": "aidac_alert",
        "batch_id": "legacy-batch",
        "generated_at": "2026-01-01T00:00:00+00:00",
        **_record(),
    }
    alert_log.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    alerts = load_alerts(alert_log)

    assert len(alerts) == 1
    assert str(alerts[0]["alert_id"]).startswith("alrt_")
    assert alerts[0]["status"] == AlertStatus.NEW.value
    assert alerts[0]["occurrence_count"] == 1


def test_prune_removes_old_resolved_alerts(tmp_path: Path) -> None:
    """Retention pruning should retain active incidents."""

    alert_log = tmp_path / "alerts.jsonl"
    old = persist_alert_batch(
        alert_log,
        build_alert_batch([_record("2020-01-01T00:00:00+00:00")]),
    )[0]
    update_alert_status(
        alert_log,
        str(old["alert_id"]),
        status=AlertStatus.RESOLVED,
        actor="analyst",
    )

    removed, retained = prune_alert_log(
        alert_log,
        older_than_days=30,
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )

    assert removed == 1
    assert retained == 0
    assert load_alerts(alert_log) == []


def test_get_alert_returns_current_snapshot(tmp_path: Path) -> None:
    """Alert lookup should return the replayed current state."""

    alert_log = tmp_path / "alerts.jsonl"
    alert = persist_alert_batch(alert_log, build_alert_batch([_record()]))[0]

    current = get_alert(alert_log, str(alert["alert_id"]))

    assert current["query"] == "DROP TABLE customers;"
