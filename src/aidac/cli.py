"""Command-line interface for the AI-DAC package."""

from __future__ import annotations

import json
import os
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

app.add_typer(
    postgres_app,
    name="postgres",
)

console = Console()

DEFAULT_STATE_FILE = Path("~/.local/state/aidac/postgresql.json")


@app.command()
def version() -> None:
    """Display the installed AI-DAC version."""

    typer.echo(f"AI-DAC version {__version__}")


@app.command()
def scan(
    query: str = typer.Argument(
        ...,
        help="SQL statement to analyze.",
    ),
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

    table.add_row(
        "Risk score",
        f"{decision.risk_score:.4f}",
    )
    table.add_row(
        "Severity",
        decision.severity.value,
    )
    table.add_row(
        "Classification",
        decision.classification,
    )

    console.print(table)


@postgres_app.command("scan")
def postgres_scan(
    limit: int = typer.Option(
        100,
        "--limit",
        "-n",
        help="Maximum number of events to collect.",
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="Collect events after an ISO-8601 timestamp.",
    ),
    schema: str = typer.Option(
        "public",
        "--schema",
        help="PostgreSQL schema containing the normalized view.",
    ),
    relation: str = typer.Option(
        "aidac_events_v",
        "--relation",
        help="Normalized PostgreSQL table or view.",
    ),
    dsn: str | None = typer.Option(
        None,
        "--dsn",
        help=("PostgreSQL DSN. Prefer the AIDAC_POSTGRES_DSN environment variable."),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Return machine-readable JSON.",
    ),
    use_state: bool = typer.Option(
        True,
        "--state/--no-state",
        help="Remember the most recent processed event.",
    ),
    state_file: Annotated[
        Path,
        typer.Option(
            "--state-file",
            help="File used to remember the last event timestamp.",
        ),
    ] = DEFAULT_STATE_FILE,
) -> None:
    """Collect and analyze PostgreSQL audit events."""

    if not 1 <= limit <= 100_000:
        console.print("[red]Error: --limit must be between 1 and 100000.[/red]")
        raise typer.Exit(code=2)

    expanded_state_file = state_file.expanduser()

    try:
        effective_since = _resolve_since(
            since=since,
            use_state=use_state,
            state_file=expanded_state_file,
        )

        connector = PostgreSQLAuditConnector(
            PostgreSQLAuditConfig(
                dsn=_resolve_dsn(dsn),
                schema=schema,
                relation=relation,
                default_limit=limit,
            )
        )

        connector.health_check()

        events = connector.fetch_events(
            since=effective_since,
            limit=limit,
        )
    except (
        PostgreSQLConnectorError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        console.print(f"[red]PostgreSQL scan failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    engine = AIDAC()

    analyses = [(event, engine.analyze(event)) for event in events]

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
        _print_results(
            analyses,
            since=effective_since,
        )

    if use_state and events:
        last_event_time = max(event.timestamp for event in events)

        _write_state(
            expanded_state_file,
            last_event_time,
        )

        if not json_output:
            console.print(f"[dim]State updated: {expanded_state_file}[/dim]")


def _resolve_dsn(cli_dsn: str | None) -> str:
    """Build the PostgreSQL connection string."""

    environment_dsn = os.getenv(
        "AIDAC_POSTGRES_DSN",
        "",
    ).strip()

    if cli_dsn is not None and cli_dsn.strip():
        return cli_dsn.strip()

    if environment_dsn:
        return environment_dsn

    host = os.getenv(
        "AIDAC_POSTGRES_HOST",
        "127.0.0.1",
    )
    port = os.getenv(
        "AIDAC_POSTGRES_PORT",
        "5432",
    )
    database = os.getenv(
        "AIDAC_POSTGRES_DB",
        "aidac_pgsql",
    )
    username = os.getenv(
        "AIDAC_POSTGRES_USER",
        "aidac_reader",
    )

    password = os.getenv("AIDAC_POSTGRES_PASSWORD")

    if password is None:
        password = getpass(f"PostgreSQL password for {username}: ")

    encoded_username = quote(
        username,
        safe="",
    )
    encoded_password = quote(
        password,
        safe="",
    )
    encoded_database = quote(
        database,
        safe="",
    )

    return f"postgresql://{encoded_username}:{encoded_password}@{host}:{port}/{encoded_database}"


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


def _read_state(
    state_file: Path,
) -> datetime | None:
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

    state_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = {"last_event_time": (last_event_time.isoformat())}

    temporary_file = state_file.with_suffix(state_file.suffix + ".tmp")

    temporary_file.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    temporary_file.replace(state_file)


def _build_summary(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> dict[str, Any]:
    """Build aggregate scan statistics."""

    severity_counts: Counter[str] = Counter(decision.severity.value for _, decision in analyses)

    risk_scores = [decision.risk_score for _, decision in analyses]

    return {
        "events_analyzed": len(analyses),
        "average_risk": (sum(risk_scores) / len(risk_scores) if risk_scores else 0.0),
        "maximum_risk": (max(risk_scores) if risk_scores else 0.0),
        "severity_counts": dict(severity_counts),
    }


def _json_payload(
    analyses: list[tuple[DatabaseEvent, SecurityDecision]],
) -> dict[str, Any]:
    """Convert analyses into JSON-compatible data."""

    return {
        "summary": _build_summary(analyses),
        "events": [
            {
                "timestamp": (event.timestamp.isoformat()),
                "username": event.username,
                "database": event.database,
                "source_system": (event.source_system),
                "client_ip": event.client_ip,
                "query": event.query,
                "risk_score": (decision.risk_score),
                "severity": (decision.severity.value),
                "classification": (decision.classification),
            }
            for event, decision in analyses
        ],
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

    for number, (
        event,
        decision,
    ) in enumerate(analyses, start=1):
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
        f" | Average risk: "
        f"{summary['average_risk']:.4f}"
        f" | Maximum risk: "
        f"{summary['maximum_risk']:.4f}"
    )

    console.print(
        "Severity counts:",
        summary["severity_counts"],
    )
