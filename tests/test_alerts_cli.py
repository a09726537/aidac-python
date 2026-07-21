"""Tests for AI-DAC alert lifecycle CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.cli import app

runner = CliRunner()


def _create_alert(alert_log: Path) -> str:
    records = [
        {
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
    ]
    return str(persist_alert_batch(alert_log, build_alert_batch(records))[0]["alert_id"])


def test_alerts_group_is_available() -> None:
    """The main CLI should expose alert lifecycle commands."""

    result = runner.invoke(app, ["alerts", "--help"])

    assert result.exit_code == 0
    assert "list" in result.output
    assert "show" in result.output
    assert "ack" in result.output
    assert "resolve" in result.output
    assert "prune" in result.output


def test_alerts_list_json(tmp_path: Path) -> None:
    """Alert listing should support structured JSON output."""

    alert_log = tmp_path / "alerts.jsonl"
    alert_id = _create_alert(alert_log)

    result = runner.invoke(
        app,
        ["alerts", "list", "--alert-log", str(alert_log), "--json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["alert_count"] == 1
    assert payload["alerts"][0]["alert_id"] == alert_id


def test_ack_and_resolve_are_audited(tmp_path: Path) -> None:
    """Lifecycle changes should be persisted and locally audited."""

    alert_log = tmp_path / "alerts.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    alert_id = _create_alert(alert_log)

    acknowledged = runner.invoke(
        app,
        [
            "alerts",
            "ack",
            alert_id,
            "--alert-log",
            str(alert_log),
            "--audit-log",
            str(audit_log),
            "--actor",
            "analyst",
            "--note",
            "Review started",
        ],
    )
    resolved = runner.invoke(
        app,
        [
            "alerts",
            "resolve",
            alert_id,
            "--alert-log",
            str(alert_log),
            "--audit-log",
            str(audit_log),
            "--actor",
            "analyst",
        ],
    )
    shown = runner.invoke(
        app,
        ["alerts", "show", alert_id, "--alert-log", str(alert_log), "--json"],
    )

    assert acknowledged.exit_code == 0
    assert resolved.exit_code == 0
    assert shown.exit_code == 0
    assert json.loads(shown.output)["status"] == "resolved"
    actions = {
        json.loads(line)["action"] for line in audit_log.read_text(encoding="utf-8").splitlines()
    }
    assert "alert_acknowledged" in actions
    assert "alert_resolved" in actions


def test_prune_requires_confirmation(tmp_path: Path) -> None:
    """Destructive pruning should require --yes."""

    result = runner.invoke(
        app,
        ["alerts", "prune", "--alert-log", str(tmp_path / "alerts.jsonl")],
    )

    assert result.exit_code == 1
    assert "--yes" in result.output
