"""Alert lifecycle commands for the AI-DAC CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from aidac.alert_store import (
    AlertStatus,
    AlertStoreError,
    filter_alerts,
    get_alert,
    load_alerts,
    parse_alert_status,
    prune_alert_log,
    update_alert_status,
)
from aidac.alerting import DEFAULT_ALERT_LOG, DEFAULT_AUDIT_LOG, write_audit_event

alerts_app = typer.Typer(
    help="Inspect and manage persistent AI-DAC alerts.",
    no_args_is_help=True,
)
console = Console()


@alerts_app.command("list")
def alerts_list(
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    status: Annotated[
        str | None,
        typer.Option("--status", help="Filter by new, acknowledged, or resolved."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum alerts to display."),
    ] = 50,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """List current deduplicated alerts."""

    try:
        parsed_status = parse_alert_status(status)
        alerts = filter_alerts(
            load_alerts(alert_log),
            status=parsed_status,
            limit=limit,
        )
    except AlertStoreError as error:
        _fail("Unable to list alerts", error)

    if json_output:
        typer.echo(
            json.dumps(
                {"alert_count": len(alerts), "alerts": alerts},
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
        return

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        return

    table = Table(title="AI-DAC alert lifecycle", show_lines=True)
    table.add_column("Alert ID")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    table.add_column("Last seen")
    table.add_column("Severity")
    table.add_column("Database")
    table.add_column("Query")

    for alert in alerts:
        query = " ".join(str(alert.get("query", "")).split())
        if len(query) > 60:
            query = query[:57] + "..."
        table.add_row(
            str(alert.get("alert_id", "")),
            str(alert.get("status", "")),
            str(alert.get("occurrence_count", 1)),
            str(alert.get("last_seen", "")),
            str(alert.get("severity", "")),
            str(alert.get("database", "")),
            query,
        )

    console.print(table)


@alerts_app.command("show")
def alerts_show(
    alert_id: Annotated[str, typer.Argument(help="Alert identifier, for example alrt_....")],
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """Show one current alert."""

    try:
        alert = get_alert(alert_log, alert_id)
    except AlertStoreError as error:
        _fail("Unable to show alert", error)

    if json_output:
        typer.echo(json.dumps(alert, indent=2, sort_keys=True, ensure_ascii=False))
        return

    table = Table(title=str(alert["alert_id"]), show_header=False, show_lines=True)
    table.add_column("Property")
    table.add_column("Value")
    for key, value in alert.items():
        table.add_row(key, _display_value(value))
    console.print(table)


@alerts_app.command("ack")
def alerts_acknowledge(
    alert_id: Annotated[str, typer.Argument(help="Alert identifier to acknowledge.")],
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private JSONL audit log."),
    ] = DEFAULT_AUDIT_LOG,
    actor: Annotated[
        str | None,
        typer.Option("--actor", help="Analyst or service acknowledging the alert."),
    ] = None,
    note: Annotated[
        str | None,
        typer.Option("--note", help="Optional acknowledgement note."),
    ] = None,
) -> None:
    """Acknowledge one alert and audit the action."""

    _change_status(
        alert_id,
        status=AlertStatus.ACKNOWLEDGED,
        alert_log=alert_log,
        audit_log=audit_log,
        actor=_resolve_actor(actor),
        note=note,
    )


@alerts_app.command("resolve")
def alerts_resolve(
    alert_id: Annotated[str, typer.Argument(help="Alert identifier to resolve.")],
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private JSONL audit log."),
    ] = DEFAULT_AUDIT_LOG,
    actor: Annotated[
        str | None,
        typer.Option("--actor", help="Analyst or service resolving the alert."),
    ] = None,
    note: Annotated[
        str | None,
        typer.Option("--note", help="Optional resolution note."),
    ] = None,
) -> None:
    """Resolve one alert and audit the action."""

    _change_status(
        alert_id,
        status=AlertStatus.RESOLVED,
        alert_log=alert_log,
        audit_log=audit_log,
        actor=_resolve_actor(actor),
        note=note,
    )


@alerts_app.command("prune")
def alerts_prune(
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private JSONL audit log."),
    ] = DEFAULT_AUDIT_LOG,
    older_than_days: Annotated[
        int,
        typer.Option(
            "--older-than-days",
            help="Remove matching alerts last seen before this many days.",
        ),
    ] = 90,
    status: Annotated[
        str,
        typer.Option("--status", help="Lifecycle status eligible for removal."),
    ] = AlertStatus.RESOLVED.value,
    confirmed: Annotated[
        bool,
        typer.Option("--yes", help="Confirm destructive pruning."),
    ] = False,
) -> None:
    """Prune old alerts and compact the JSONL lifecycle log."""

    if not confirmed:
        console.print("[yellow]Pruning was not performed. Add --yes to confirm.[/yellow]")
        raise typer.Exit(code=1)

    try:
        parsed_status = parse_alert_status(status)
        if parsed_status is None:
            raise AlertStoreError("A pruning status is required.")
        removed, retained = prune_alert_log(
            alert_log,
            older_than_days=older_than_days,
            status=parsed_status,
        )
        write_audit_event(
            audit_log,
            action="alert_prune",
            status="success",
            details={
                "removed": removed,
                "retained": retained,
                "older_than_days": older_than_days,
                "alert_status": parsed_status.value,
            },
        )
    except (AlertStoreError, OSError) as error:
        _fail("Unable to prune alerts", error)

    console.print(f"[green]Alert log compacted: {removed} removed, {retained} retained.[/green]")


def _change_status(
    alert_id: str,
    *,
    status: AlertStatus,
    alert_log: Path,
    audit_log: Path,
    actor: str,
    note: str | None,
) -> None:
    try:
        alert = update_alert_status(
            alert_log,
            alert_id,
            status=status,
            actor=actor,
            note=note,
        )
        write_audit_event(
            audit_log,
            action=f"alert_{status.value}",
            status="success",
            details={
                "alert_id": alert_id,
                "actor": actor,
                "note": note,
            },
        )
    except (AlertStoreError, OSError) as error:
        _fail("Unable to update alert", error)

    console.print(f"[green]Alert {alert['alert_id']} is now {alert['status']}.[/green]")


def _resolve_actor(actor: str | None) -> str:
    if actor is not None and actor.strip():
        return actor.strip()
    return os.getenv("USER", "unknown").strip() or "unknown"


def _display_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def _fail(prefix: str, error: Exception) -> NoReturn:
    console.print(f"[red]{prefix}: {error}[/red]")
    raise typer.Exit(code=1) from error
