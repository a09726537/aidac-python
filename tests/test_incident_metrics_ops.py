from __future__ import annotations

from pathlib import Path

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.metrics import MetricsRegistry, normalize_metric_path
from aidac.ops_cli import generate_operations_bundle


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


def test_metrics_render_incident_gauges_and_normalize_paths(tmp_path: Path) -> None:
    store = tmp_path / "alerts.db"
    persist_alert_batch(store, build_alert_batch([_record()]))

    body = MetricsRegistry().render(store)

    assert 'aidac_incidents_total{status="open",severity="critical"} 1' in body
    assert "aidac_incident_recurrence_max 1" in body
    assert (
        normalize_metric_path("/api/v1/incidents/inc_secret/assessment")
        == "/api/v1/incidents/{incident_id}/assessment"
    )


def test_operations_bundle_contains_incident_rules_and_dashboard_panels(tmp_path: Path) -> None:
    destination = tmp_path / "ops"
    generate_operations_bundle(
        destination,
        aidac_url="http://host.docker.internal:8000",
        viewer_token_file=tmp_path / "viewer.token",
        overwrite=False,
    )

    rules = (destination / "prometheus/rules/aidac-alerts.yml").read_text(encoding="utf-8")
    dashboard = (destination / "grafana/dashboards/aidac-overview.json").read_text(encoding="utf-8")
    assert "AIDACCriticalIncidentOpen" in rules
    assert "AIDACRecurringIncidentActivity" in rules
    compose = (destination / "docker-compose.ops.yml").read_text(encoding="utf-8")
    assert "Active incidents" in dashboard
    assert "network_mode: host" in compose
    assert "./prometheus-data:/prometheus/data" in compose
    assert (destination / "prometheus-data").stat().st_mode & 0o777 == 0o700
