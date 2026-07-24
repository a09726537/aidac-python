"""Incident correlation, learning assessment and notification commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from aidac.alert_store import AlertStoreError, load_alerts
from aidac.alerting import (
    DEFAULT_ALERT_LOG,
    DEFAULT_AUDIT_LOG,
    AlertingError,
    WebhookSettings,
    send_signed_webhook,
    write_audit_event,
)
from aidac.incidents import (
    IncidentError,
    IncidentStatus,
    correlate_alerts,
    get_incident,
    incident_notification_payload,
    incident_summary,
    query_incidents,
)
from aidac.models import Severity

incidents_app = typer.Typer(
    help="Correlate alerts into incidents and apply Triple-Loop Learning assessments.",
    no_args_is_help=True,
)
console = Console()
_DEFAULT_WINDOW_MINUTES = 30
_DEFAULT_INCIDENT_SECRET_ENV = "AIDAC_INCIDENT_WEBHOOK_SECRET"
_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


@incidents_app.command("list")
def incidents_list(
    alert_log: Annotated[Path, typer.Option("--alert-log")] = DEFAULT_ALERT_LOG,
    window_minutes: Annotated[int, typer.Option("--window-minutes", min=1, max=10_080)] = (
        _DEFAULT_WINDOW_MINUTES
    ),
    status: Annotated[IncidentStatus | None, typer.Option("--status")] = None,
    severity: Annotated[str | None, typer.Option("--severity")] = None,
    minimum_risk: Annotated[float, typer.Option("--min-risk", min=0.0, max=1.0)] = 0.0,
    search: Annotated[str | None, typer.Option("--search")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=1_000)] = 50,
    offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List current correlated incidents."""

    incidents, total = _load_and_query(
        alert_log,
        window_minutes=window_minutes,
        status=status,
        severity=severity,
        minimum_risk=minimum_risk,
        search=search,
        limit=limit,
        offset=offset,
    )
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "incident_count": len(incidents),
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "incidents": incidents,
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
        return

    table = Table(title=f"AI-DAC correlated incidents ({len(incidents)} of {total})")
    table.add_column("Incident ID")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Risk", justify="right")
    table.add_column("Alerts", justify="right")
    table.add_column("Occurrences", justify="right")
    table.add_column("Database")
    table.add_column("Last seen")
    for incident in incidents:
        table.add_row(
            str(incident["incident_id"]),
            str(incident["status"]),
            str(incident["severity"]),
            f"{float(incident['risk_score']):.3f}",
            str(incident["alert_count"]),
            str(incident["occurrence_count"]),
            str(incident["database"]),
            str(incident["last_seen"]),
        )
    console.print(table)


@incidents_app.command("show")
def incidents_show(
    incident_id: str,
    alert_log: Annotated[Path, typer.Option("--alert-log")] = DEFAULT_ALERT_LOG,
    window_minutes: Annotated[int, typer.Option("--window-minutes", min=1, max=10_080)] = (
        _DEFAULT_WINDOW_MINUTES
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show one incident and its Triple-Loop Learning assessment."""

    try:
        incident = get_incident(
            correlate_alerts(load_alerts(alert_log.expanduser()), window_minutes=window_minutes),
            incident_id,
        )
    except (AlertStoreError, IncidentError) as error:
        _fail(str(error))
    if json_output:
        typer.echo(json.dumps(incident, indent=2, sort_keys=True, ensure_ascii=False))
        return
    table = Table(title=str(incident["title"]), show_header=False)
    table.add_column("Property")
    table.add_column("Value")
    for key in (
        "incident_id",
        "status",
        "severity",
        "risk_score",
        "alert_count",
        "occurrence_count",
        "database",
        "source_system",
        "first_seen",
        "last_seen",
        "recommended_action",
    ):
        table.add_row(key, str(incident[key]))
    assessment = incident["triple_loop"]
    table.add_row("learning_score", str(assessment["learning_score"]))
    table.add_row("loop2_response", str(assessment["loop2_adaptation"]["response_mode"]))
    table.add_row("loop3_governance", str(assessment["loop3_reflection"]["governance_action"]))
    console.print(table)


@incidents_app.command("correlate")
def incidents_correlate(
    output: Annotated[Path, typer.Option("--output", "-o")],
    alert_log: Annotated[Path, typer.Option("--alert-log")] = DEFAULT_ALERT_LOG,
    window_minutes: Annotated[int, typer.Option("--window-minutes", min=1, max=10_080)] = (
        _DEFAULT_WINDOW_MINUTES
    ),
) -> None:
    """Write a private JSON incident-correlation report."""

    try:
        incidents = correlate_alerts(
            load_alerts(alert_log.expanduser()),
            window_minutes=window_minutes,
        )
        payload = {
            "type": "aidac_incident_report",
            "summary": incident_summary(incidents),
            "incidents": incidents,
        }
        destination = output.expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.chmod(0o700)
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        destination.chmod(0o600)
    except (AlertStoreError, IncidentError, OSError) as error:
        _fail(str(error))
    console.print(f"[green]Incident report written: {destination}[/green]")


@incidents_app.command("notify")
def incidents_notify(
    webhook_url: Annotated[str, typer.Option("--webhook-url")],
    alert_log: Annotated[Path, typer.Option("--alert-log")] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[Path, typer.Option("--audit-log")] = DEFAULT_AUDIT_LOG,
    secret_env: Annotated[str, typer.Option("--secret-env")] = _DEFAULT_INCIDENT_SECRET_ENV,
    minimum_severity: Annotated[str, typer.Option("--min-severity")] = Severity.HIGH.value,
    window_minutes: Annotated[int, typer.Option("--window-minutes", min=1, max=10_080)] = (
        _DEFAULT_WINDOW_MINUTES
    ),
) -> None:
    """Send signed notifications for active incidents at or above a severity threshold."""

    normalized_severity = minimum_severity.strip().casefold()
    if normalized_severity not in _SEVERITY_RANK:
        _fail("Minimum severity must be info, low, medium, high, or critical.")
    try:
        settings = WebhookSettings(url=webhook_url, secret_env=secret_env)
        incidents = correlate_alerts(
            load_alerts(alert_log.expanduser()),
            window_minutes=window_minutes,
        )
        selected = [
            incident
            for incident in incidents
            if incident["status"] != IncidentStatus.RESOLVED.value
            and _SEVERITY_RANK[str(incident["severity"])] >= _SEVERITY_RANK[normalized_severity]
        ]
        delivered = 0
        for incident in selected:
            status_code = send_signed_webhook(settings, incident_notification_payload(incident))
            write_audit_event(
                audit_log.expanduser(),
                action="incident_notification",
                status="success",
                details={
                    "incident_id": incident["incident_id"],
                    "severity": incident["severity"],
                    "status_code": status_code,
                },
            )
            delivered += 1
    except (AlertStoreError, AlertingError, IncidentError) as error:
        _fail(str(error))
    console.print(f"[green]Incident notifications delivered: {delivered}[/green]")


def _load_and_query(
    alert_log: Path,
    *,
    window_minutes: int,
    status: IncidentStatus | None,
    severity: str | None,
    minimum_risk: float,
    search: str | None,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    try:
        incidents = correlate_alerts(
            load_alerts(alert_log.expanduser()),
            window_minutes=window_minutes,
        )
        return query_incidents(
            incidents,
            status=status,
            severity=severity,
            minimum_risk=minimum_risk,
            search=search,
            limit=limit,
            offset=offset,
        )
    except (AlertStoreError, IncidentError) as error:
        _fail(str(error))


def _fail(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=1)
