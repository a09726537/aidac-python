from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.cli import app

runner = CliRunner()


def _record() -> dict[str, object]:
    return {
        "timestamp": "2026-07-22T10:00:00+00:00",
        "username": "security_test",
        "database": "sales",
        "source_system": "postgresql",
        "client_ip": "192.0.2.10",
        "query": "DROP TABLE customers;",
        "risk_score": 0.95,
        "severity": "critical",
        "classification": "destructive_sql",
    }


def test_incidents_list_and_show_json(tmp_path: Path) -> None:
    store = tmp_path / "alerts.db"
    persist_alert_batch(store, build_alert_batch([_record()]))

    listed = runner.invoke(
        app,
        ["incidents", "list", "--alert-log", str(store), "--json"],
    )
    assert listed.exit_code == 0
    payload = json.loads(listed.stdout)
    assert payload["total"] == 1
    incident_id = payload["incidents"][0]["incident_id"]

    shown = runner.invoke(
        app,
        ["incidents", "show", incident_id, "--alert-log", str(store), "--json"],
    )
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["triple_loop"]["human_approval_required"] is True


def test_incidents_correlate_writes_private_report(tmp_path: Path) -> None:
    store = tmp_path / "alerts.db"
    report = tmp_path / "reports" / "incidents.json"
    persist_alert_batch(store, build_alert_batch([_record()]))

    result = runner.invoke(
        app,
        [
            "incidents",
            "correlate",
            "--alert-log",
            str(store),
            "--output",
            str(report),
        ],
    )

    assert result.exit_code == 0
    assert report.stat().st_mode & 0o777 == 0o600
    assert json.loads(report.read_text(encoding="utf-8"))["summary"]["incident_count"] == 1
