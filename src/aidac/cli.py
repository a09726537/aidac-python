"""Command-line interface for the AI-DAC package."""

from __future__ import annotations

import csv
import json
import os
import time
from collections import Counter
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

import typer
from rich.console import Console
from rich.table import Table

from aidac import __version__
from aidac.alert_store import AlertStoreError, persist_alert_batch
from aidac.alerting import (
    DEFAULT_ALERT_LOG,
    DEFAULT_AUDIT_LOG,
    DEFAULT_WEBHOOK_SECRET_ENV,
    AlertingError,
    WebhookSettings,
    build_alert_batch,
    send_signed_webhook,
    write_audit_event,
    write_batch_export,
)
from aidac.alerts_cli import alerts_app
from aidac.config import (
    DEFAULT_CONFIG_FILE,
    ConfigError,
    PostgreSQLSettings,
    load_settings,
)
from aidac.config_cli import config_app
from aidac.connectors.postgresql import (
    PostgreSQLAuditConfig,
    PostgreSQLAuditConnector,
    PostgreSQLConnectorError,
)
from aidac.engine import AIDAC
from aidac.models import DatabaseEvent, SecurityDecision

app = typer.Typer(
    name="aidac",
    help="AI-DAC adaptive database-security command line.",
    no_args_is_help=True,
)

postgres_app = typer.Typer(
    help="Collect and analyze PostgreSQL audit events.",
    no_args_is_help=True,
)

app.add_typer(postgres_app, name="postgres")
app.add_typer(config_app, name="config")
app.add_typer(alerts_app, name="alerts")

console = Console()

DEFAULT_STATE_FILE = Path("~/.local/state/aidac/postgresql.json")


@app.command()
def version() -> None:
    """Display the installed AI-DAC version."""

    typer.echo(f"AI-DAC version {__version__}")


@app.command()
def scan(
    query: Annotated[
        str,
        typer.Argument(help="SQL statement to analyze."),
    ],
) -> None:
    """Analyze one SQL statement."""

    event = DatabaseEvent(
        query=query,
        username="cli-user",
        database="manual",
        source_system="cli",
    )
    decision = AIDAC().analyze(event)

    table = Table(
        title="AI-DAC security decision",
        show_header=False,
    )
    table.add_column("Property")
    table.add_column("Value")
    table.add_row("Risk score", f"{decision.risk_score:.4f}")
    table.add_row("Severity", decision.severity.value)
    table.add_row("Classification", decision.classification)
    console.print(table)


@postgres_app.command("scan")
def postgres_scan(
    limit: Annotated[
        int | None,
        typer.Option(
            "--limit",
            "-n",
            help="Maximum number of events. Uses config.toml when omitted.",
        ),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Collect events after an ISO-8601 timestamp.",
        ),
    ] = None,
    schema: Annotated[
        str | None,
        typer.Option(
            "--schema",
            help="Override the configured PostgreSQL schema.",
        ),
    ] = None,
    relation: Annotated[
        str | None,
        typer.Option(
            "--relation",
            help="Override the configured audit relation.",
        ),
    ] = None,
    dsn: Annotated[
        str | None,
        typer.Option(
            "--dsn",
            help="PostgreSQL DSN. Prefer AIDAC_POSTGRES_DSN.",
        ),
    ] = None,
    config_file: Annotated[
        Path,
        typer.Option(
            "--config",
            help="AI-DAC TOML configuration file.",
        ),
    ] = DEFAULT_CONFIG_FILE,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Return machine-readable JSON.",
        ),
    ] = False,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write filtered results to a .csv or .json file.",
        ),
    ] = None,
    min_risk: Annotated[
        float,
        typer.Option(
            "--min-risk",
            help="Minimum risk score between 0.0 and 1.0.",
        ),
    ] = 0.0,
    min_severity: Annotated[
        str | None,
        typer.Option(
            "--min-severity",
            help=("Minimum severity: info, low, medium, high, or critical."),
        ),
    ] = None,
    use_state: Annotated[
        bool,
        typer.Option(
            "--state/--no-state",
            help="Remember the most recent processed event.",
        ),
    ] = True,
    state_file: Annotated[
        Path,
        typer.Option(
            "--state-file",
            help="Last processed event state file.",
        ),
    ] = DEFAULT_STATE_FILE,
) -> None:
    """Collect and analyze PostgreSQL audit events."""

    expanded_config_file = config_file.expanduser()
    expanded_state_file = state_file.expanduser()

    try:
        settings = load_settings(expanded_config_file).postgresql
        effective_min_severity = _normalize_min_severity(min_severity)

        if not 0.0 <= min_risk <= 1.0:
            raise ValueError("--min-risk must be between 0.0 and 1.0.")

        expanded_output_file = None if output_file is None else output_file.expanduser()
        if expanded_output_file is not None:
            _export_format(expanded_output_file)

        effective_limit = settings.default_limit if limit is None else limit

        if not 1 <= effective_limit <= 100_000:
            raise ValueError("--limit must be between 1 and 100000.")

        effective_schema = settings.schema if schema is None else schema.strip()
        effective_relation = settings.relation if relation is None else relation.strip()

        if not effective_schema:
            raise ValueError("--schema cannot be empty.")
        if not effective_relation:
            raise ValueError("--relation cannot be empty.")

        effective_since = _resolve_since(
            since=since,
            use_state=use_state,
            state_file=expanded_state_file,
        )

        connector = PostgreSQLAuditConnector(
            PostgreSQLAuditConfig(
                dsn=_resolve_dsn(dsn, settings),
                schema=effective_schema,
                relation=effective_relation,
                default_limit=effective_limit,
                connect_timeout_seconds=settings.connect_timeout_seconds,
                statement_timeout_ms=settings.statement_timeout_ms,
            )
        )
        connector.health_check()
        events = connector.fetch_events(
            since=effective_since,
            limit=effective_limit,
        )
    except (
        ConfigError,
        PostgreSQLConnectorError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        console.print(f"[red]PostgreSQL scan failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    engine = AIDAC()
    analyses = [(event, engine.analyze(event)) for event in events]
    analyses = _filter_analyses(
        analyses,
        min_risk=min_risk,
        min_severity=effective_min_severity,
    )

    if expanded_output_file is not None:
        _write_export(expanded_output_file, analyses)

    if json_output:
        typer.echo(
            json.dumps(
                _json_payload(analyses),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    else:
        console.print(f"[dim]Configuration: {expanded_config_file}[/dim]")
        if min_risk > 0.0 or effective_min_severity is not None:
            severity_text = effective_min_severity if effective_min_severity is not None else "none"
            console.print(
                f"[dim]Filters: minimum risk={min_risk:.4f}, minimum severity={severity_text}[/dim]"
            )
        _print_results(analyses, since=effective_since)
        if expanded_output_file is not None:
            console.print(f"[green]Export written: {expanded_output_file}[/green]")

    if use_state and events:
        last_event_time = max(event.timestamp for event in events)
        _write_state(expanded_state_file, last_event_time)

        if not json_output:
            console.print(f"[dim]State updated: {expanded_state_file}[/dim]")


@postgres_app.command("watch")
def postgres_watch(
    interval: Annotated[
        float,
        typer.Option(
            "--interval",
            help="Polling interval in seconds.",
        ),
    ] = 10.0,
    limit: Annotated[
        int | None,
        typer.Option(
            "--limit",
            "-n",
            help="Maximum events collected during each polling cycle.",
        ),
    ] = None,
    min_risk: Annotated[
        float,
        typer.Option(
            "--min-risk",
            help="Alert only when risk is at least this value.",
        ),
    ] = 0.7,
    min_severity: Annotated[
        str | None,
        typer.Option(
            "--min-severity",
            help=("Optional minimum severity: info, low, medium, high, or critical."),
        ),
    ] = None,
    schema: Annotated[
        str | None,
        typer.Option(
            "--schema",
            help="Override the configured PostgreSQL schema.",
        ),
    ] = None,
    relation: Annotated[
        str | None,
        typer.Option(
            "--relation",
            help="Override the configured audit relation.",
        ),
    ] = None,
    dsn: Annotated[
        str | None,
        typer.Option(
            "--dsn",
            help="PostgreSQL DSN. Prefer AIDAC_POSTGRES_DSN.",
        ),
    ] = None,
    config_file: Annotated[
        Path,
        typer.Option(
            "--config",
            help="AI-DAC TOML configuration file.",
        ),
    ] = DEFAULT_CONFIG_FILE,
    state_file: Annotated[
        Path,
        typer.Option(
            "--state-file",
            help="File containing the last processed event timestamp.",
        ),
    ] = DEFAULT_STATE_FILE,
    alert_log: Annotated[
        Path,
        typer.Option(
            "--alert-log",
            help="Private JSONL file for persistent alerts.",
        ),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option(
            "--audit-log",
            help="Private JSONL file for local audit events.",
        ),
    ] = DEFAULT_AUDIT_LOG,
    persist_alerts: Annotated[
        bool,
        typer.Option(
            "--persist-alerts/--no-persist-alerts",
            help="Persist matching alerts to the JSONL alert log.",
        ),
    ] = True,
    export_directory: Annotated[
        Path | None,
        typer.Option(
            "--export-dir",
            help="Automatically export every alert batch as JSON.",
        ),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option(
            "--webhook-url",
            help=(
                "HTTPS notification endpoint. The "
                "AIDAC_WEBHOOK_URL environment variable is used "
                "when omitted."
            ),
        ),
    ] = None,
    webhook_secret_env: Annotated[
        str,
        typer.Option(
            "--webhook-secret-env",
            help="Environment variable containing the HMAC secret.",
        ),
    ] = DEFAULT_WEBHOOK_SECRET_ENV,
    webhook_timeout: Annotated[
        float,
        typer.Option(
            "--webhook-timeout",
            help="Webhook timeout in seconds.",
        ),
    ] = 5.0,
    webhook_strict: Annotated[
        bool,
        typer.Option(
            "--webhook-strict",
            help="Stop monitoring when webhook delivery fails.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Stream alert batches as JSON.",
        ),
    ] = False,
    once: Annotated[
        bool,
        typer.Option(
            "--once",
            help="Run one polling cycle and stop.",
        ),
    ] = False,
) -> None:
    """Continuously monitor PostgreSQL for new high-risk events."""

    expanded_config_file = config_file.expanduser()
    expanded_state_file = state_file.expanduser()
    expanded_alert_log = alert_log.expanduser()
    expanded_audit_log = audit_log.expanduser()
    expanded_export_directory = None if export_directory is None else export_directory.expanduser()

    try:
        settings = load_settings(expanded_config_file).postgresql
        effective_min_severity = _normalize_min_severity(min_severity)

        if not 1.0 <= interval <= 3_600.0:
            raise ValueError("--interval must be between 1 and 3600 seconds.")

        if not 0.0 <= min_risk <= 1.0:
            raise ValueError("--min-risk must be between 0.0 and 1.0.")

        effective_limit = settings.default_limit if limit is None else limit
        if not 1 <= effective_limit <= 100_000:
            raise ValueError("--limit must be between 1 and 100000.")

        effective_schema = settings.schema if schema is None else schema.strip()
        effective_relation = settings.relation if relation is None else relation.strip()

        if not effective_schema:
            raise ValueError("--schema cannot be empty.")
        if not effective_relation:
            raise ValueError("--relation cannot be empty.")

        effective_webhook_url = (
            webhook_url.strip()
            if webhook_url is not None
            else os.getenv(
                "AIDAC_WEBHOOK_URL",
                "",
            ).strip()
        )

        webhook_settings = (
            None
            if not effective_webhook_url
            else WebhookSettings(
                url=effective_webhook_url,
                secret_env=webhook_secret_env,
                timeout_seconds=webhook_timeout,
            )
        )

        since = _read_state(expanded_state_file)

        connector = PostgreSQLAuditConnector(
            PostgreSQLAuditConfig(
                dsn=_resolve_dsn(dsn, settings),
                schema=effective_schema,
                relation=effective_relation,
                default_limit=effective_limit,
                connect_timeout_seconds=(settings.connect_timeout_seconds),
                statement_timeout_ms=(settings.statement_timeout_ms),
            )
        )
        connector.health_check()

        write_audit_event(
            expanded_audit_log,
            action="postgres_watch_start",
            status="success",
            details={
                "interval_seconds": interval,
                "minimum_risk": min_risk,
                "minimum_severity": effective_min_severity,
                "persistent_alerts": persist_alerts,
                "webhook_enabled": (webhook_settings is not None),
            },
        )
    except (
        AlertingError,
        AlertStoreError,
        ConfigError,
        PostgreSQLConnectorError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        console.print(f"[red]PostgreSQL watch failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    engine = AIDAC()

    if not json_output:
        console.print("[green]AI-DAC PostgreSQL monitoring started.[/green]")
        console.print(
            f"[dim]Interval: {interval:g}s | "
            f"Minimum risk: {min_risk:.4f} | "
            f"State: {expanded_state_file}[/dim]"
        )
        console.print(
            f"[dim]Alert log: {expanded_alert_log} | Audit log: {expanded_audit_log}[/dim]"
        )
        console.print("[dim]Press Ctrl+C to stop safely.[/dim]")

    try:
        while True:
            try:
                events = connector.fetch_events(
                    since=since,
                    limit=effective_limit,
                )
            except PostgreSQLConnectorError as error:
                console.print(f"[red]PostgreSQL polling failed: {error}[/red]")
                write_audit_event(
                    expanded_audit_log,
                    action="postgres_poll",
                    status="error",
                    details={"error": str(error)},
                )
                if once:
                    raise typer.Exit(code=1) from error
                time.sleep(interval)
                continue

            analyses = [(event, engine.analyze(event)) for event in events]
            alerts = _filter_analyses(
                analyses,
                min_risk=min_risk,
                min_severity=effective_min_severity,
            )

            if alerts:
                batch = build_alert_batch(_analysis_records(alerts))
                batch.update(_json_payload(alerts))

                if persist_alerts:
                    lifecycle_alerts = persist_alert_batch(
                        expanded_alert_log,
                        batch,
                    )
                    current_ids = {
                        str(alert.get("alert_id", ""))
                        for alert in batch["alerts"]
                        if isinstance(alert, dict)
                    }
                    batch["alerts"] = [
                        alert
                        for alert in lifecycle_alerts
                        if str(alert.get("alert_id", "")) in current_ids
                    ]

                export_file = None
                if expanded_export_directory is not None:
                    export_file = write_batch_export(
                        expanded_export_directory,
                        batch,
                    )

                webhook_status = None
                if webhook_settings is not None:
                    try:
                        webhook_status = send_signed_webhook(
                            webhook_settings,
                            batch,
                        )
                    except AlertingError as error:
                        write_audit_event(
                            expanded_audit_log,
                            action="webhook_delivery",
                            status="error",
                            details={"error": str(error)},
                        )
                        console.print(f"[yellow]Webhook delivery failed: {error}[/yellow]")
                        if webhook_strict:
                            raise typer.Exit(code=1) from error

                write_audit_event(
                    expanded_audit_log,
                    action="alert_batch",
                    status="success",
                    details={
                        "batch_id": batch["batch_id"],
                        "alert_count": len(alerts),
                        "export_file": (None if export_file is None else str(export_file)),
                        "webhook_status": webhook_status,
                    },
                )

                if json_output:
                    typer.echo(
                        json.dumps(
                            batch,
                            sort_keys=True,
                            ensure_ascii=False,
                        )
                    )
                else:
                    console.print("[bold red]High-risk PostgreSQL alert detected[/bold red]")
                    _print_results(alerts, since=since)
                    if export_file is not None:
                        console.print(f"[green]Automatic export: {export_file}[/green]")

            if events:
                last_event_time = max(event.timestamp for event in events)
                _write_state(
                    expanded_state_file,
                    last_event_time,
                )
                since = last_event_time

            if once:
                break

            time.sleep(interval)
    except (AlertingError, AlertStoreError) as error:
        console.print(f"[red]Alert processing failed: {error}[/red]")
        raise typer.Exit(code=1) from error
    except KeyboardInterrupt:
        write_audit_event(
            expanded_audit_log,
            action="postgres_watch_stop",
            status="success",
            details={"reason": "keyboard_interrupt"},
        )
        if not json_output:
            console.print("\n[yellow]Monitoring stopped safely.[/yellow]")
    else:
        write_audit_event(
            expanded_audit_log,
            action="postgres_watch_stop",
            status="success",
            details={"reason": "completed"},
        )


def _resolve_dsn(
    cli_dsn: str | None,
    settings: PostgreSQLSettings,
) -> str:
    """Build the PostgreSQL connection string."""

    environment_dsn = os.getenv("AIDAC_POSTGRES_DSN", "").strip()

    if cli_dsn is not None and cli_dsn.strip():
        return cli_dsn.strip()
    if environment_dsn:
        return environment_dsn

    password = os.getenv("AIDAC_POSTGRES_PASSWORD")
    if password is None:
        password = getpass(f"PostgreSQL password for {settings.username}: ")

    encoded_username = quote(settings.username, safe="")
    encoded_password = quote(password, safe="")
    encoded_database = quote(settings.database, safe="")

    return (
        f"postgresql://{encoded_username}:"
        f"{encoded_password}@{settings.host}:"
        f"{settings.port}/{encoded_database}"
    )


def _resolve_since(
    *,
    since: str | None,
    use_state: bool,
    state_file: Path,
) -> datetime | None:
    """Resolve the explicit or stored starting timestamp."""

    if since is not None:
        return _parse_datetime(since)
    if not use_state:
        return None
    return _read_state(state_file)


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 timestamp."""

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value}") from error


def _read_state(state_file: Path) -> datetime | None:
    """Read the last processed event timestamp."""

    if not state_file.exists():
        return None

    payload = json.loads(state_file.read_text(encoding="utf-8"))
    value = payload.get("last_event_time")

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Invalid last_event_time in state file.")

    return _parse_datetime(value)


def _write_state(
    state_file: Path,
    last_event_time: datetime,
) -> None:
    """Persist the last processed event timestamp."""

    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.parent.chmod(0o700)
    payload = {"last_event_time": last_event_time.isoformat()}

    temporary_file = state_file.with_suffix(state_file.suffix + ".tmp")
    temporary_file.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_file.chmod(0o600)
    temporary_file.replace(state_file)
    state_file.chmod(0o600)


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_min_severity(value: str | None) -> str | None:
    """Validate and normalize the minimum severity filter."""

    if value is None:
        return None

    normalized = value.strip().casefold()
    if normalized not in _SEVERITY_RANK:
        allowed = ", ".join(_SEVERITY_RANK)
        raise ValueError(f"--min-severity must be one of: {allowed}.")

    return normalized


def _filter_analyses(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
    *,
    min_risk: float,
    min_severity: str | None,
) -> list[tuple[DatabaseEvent, SecurityDecision]]:
    """Filter analyses by risk score and severity."""

    severity_threshold = -1 if min_severity is None else _SEVERITY_RANK[min_severity]

    return [
        (event, decision)
        for event, decision in analyses
        if decision.risk_score >= min_risk
        and _SEVERITY_RANK.get(
            decision.severity.value.casefold(),
            -1,
        )
        >= severity_threshold
    ]


def _analysis_records(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> list[dict[str, Any]]:
    """Convert analyses into flat export records."""

    return [
        {
            "timestamp": event.timestamp.isoformat(),
            "username": event.username,
            "database": event.database,
            "source_system": event.source_system,
            "client_ip": event.client_ip,
            "query": event.query,
            "risk_score": decision.risk_score,
            "severity": decision.severity.value,
            "classification": decision.classification,
        }
        for event, decision in analyses
    ]


def _export_format(output_file: Path) -> str:
    """Return the supported export format for a path."""

    suffix = output_file.suffix.casefold()
    if suffix == ".csv":
        return "csv"
    if suffix == ".json":
        return "json"

    raise ValueError("--output must end with .csv or .json.")


def _write_export(
    output_file: Path,
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> None:
    """Write filtered results atomically to CSV or JSON."""

    export_format = _export_format(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = output_file.with_suffix(output_file.suffix + ".tmp")

    if export_format == "json":
        temporary_file.write_text(
            json.dumps(
                _json_payload(analyses),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        fieldnames = [
            "timestamp",
            "username",
            "database",
            "source_system",
            "client_ip",
            "query",
            "risk_score",
            "severity",
            "classification",
        ]
        with temporary_file.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            writer.writerows(_analysis_records(analyses))

    temporary_file.chmod(0o600)
    temporary_file.replace(output_file)
    output_file.chmod(0o600)


def _build_summary(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> dict[str, Any]:
    """Build aggregate scan statistics."""

    severity_counts: Counter[str] = Counter(decision.severity.value for _, decision in analyses)
    risk_scores = [decision.risk_score for _, decision in analyses]

    return {
        "events_analyzed": len(analyses),
        "average_risk": (sum(risk_scores) / len(risk_scores) if risk_scores else 0.0),
        "maximum_risk": max(risk_scores) if risk_scores else 0.0,
        "severity_counts": dict(severity_counts),
    }


def _json_payload(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> dict[str, Any]:
    """Convert analyses into JSON-compatible data."""

    return {
        "summary": _build_summary(analyses),
        "events": _analysis_records(analyses),
    }


def _print_results(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
    *,
    since: datetime | None,
) -> None:
    """Display human-readable scan results."""

    if since is not None:
        console.print(f"[dim]Collecting events after {since.isoformat()}[/dim]")

    if not analyses:
        console.print("[yellow]No new PostgreSQL events found.[/yellow]")
        return

    table = Table(
        title="AI-DAC PostgreSQL scan",
        show_lines=True,
    )
    table.add_column("#", justify="right")
    table.add_column("Time")
    table.add_column("User")
    table.add_column("Database")
    table.add_column("Risk", justify="right")
    table.add_column("Severity")
    table.add_column("Classification")
    table.add_column("Query")

    for number, (event, decision) in enumerate(analyses, start=1):
        query = " ".join(event.query.split())
        if len(query) > 70:
            query = query[:67] + "..."

        table.add_row(
            str(number),
            event.timestamp.isoformat(),
            event.username,
            event.database,
            f"{decision.risk_score:.4f}",
            decision.severity.value,
            decision.classification,
            query,
        )

    console.print(table)
    summary = _build_summary(analyses)

    console.print(
        "[bold]Summary[/bold]"
        f" | Events: {summary['events_analyzed']}"
        f" | Average risk: {summary['average_risk']:.4f}"
        f" | Maximum risk: {summary['maximum_risk']:.4f}"
    )
    console.print("Severity counts:", summary["severity_counts"])
