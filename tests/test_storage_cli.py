"""Tests for storage, audit and diagnostic CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch, write_audit_event
from aidac.cli import app

runner = CliRunner()


def _record() -> dict[str, object]:
    return {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "username": "security_test",
        "database": "sales",
        "source_system": "postgresql",
        "client_ip": "192.0.2.10",
        "query": "DROP TABLE customers;",
        "risk_score": 0.95,
        "severity": "critical",
        "classification": "destructive_sql",
    }


def test_storage_migration_and_info_commands(tmp_path: Path) -> None:
    """The CLI should migrate JSONL and report SQLite metadata."""

    source = tmp_path / "alerts.jsonl"
    destination = tmp_path / "alerts.db"
    persist_alert_batch(source, build_alert_batch([_record()]))

    migrated = runner.invoke(
        app,
        [
            "storage",
            "migrate-jsonl",
            "--source",
            str(source),
            "--destination",
            str(destination),
        ],
    )
    information = runner.invoke(
        app,
        ["storage", "info", "--store", str(destination), "--json"],
    )

    assert migrated.exit_code == 0
    payload = json.loads(information.output)
    assert payload["backend"] == "sqlite"
    assert payload["alert_count"] == 1


def test_audit_verify_and_doctor_commands(tmp_path: Path) -> None:
    """Operational commands should validate a healthy local installation."""

    store = tmp_path / "alerts.db"
    audit = tmp_path / "audit.jsonl"
    config = tmp_path / "config.toml"
    config.write_text("[postgresql]\n", encoding="utf-8")
    persist_alert_batch(store, build_alert_batch([_record()]))
    write_audit_event(audit, action="test", status="success")

    verified = runner.invoke(app, ["audit", "verify", "--audit-log", str(audit), "--json"])
    diagnosed = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--store",
            str(store),
            "--audit-log",
            str(audit),
            "--json",
        ],
    )

    assert verified.exit_code == 0
    assert json.loads(verified.output)["valid"] is True
    assert diagnosed.exit_code == 0
    assert json.loads(diagnosed.output)["errors"] == 0
