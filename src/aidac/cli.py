"""Command-line interface for the AI-DAC framework."""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from aidac import __version__
from aidac.engine import AIDAC
from aidac.models import DatabaseEvent

app = typer.Typer(
    name="aidac",
    help="Adaptive and explainable database cybersecurity framework.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.command()
def version() -> None:
    """Display the installed AI-DAC version."""

    console.print(f"AI-DAC version {__version__}")


@app.command()
def scan(
    query: str = typer.Argument(
        ...,
        help="SQL query to analyse.",
    ),
    username: str = typer.Option(
        "unknown",
        "--username",
        "-u",
        help="Database username.",
    ),
    database: str = typer.Option(
        "unknown",
        "--database",
        "-d",
        help="Database name.",
    ),
    source: str = typer.Option(
        "postgresql",
        "--source",
        "-s",
        help="Source database system.",
    ),
    client_ip: str | None = typer.Option(
        None,
        "--client-ip",
        help="Client IP address.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Return the result as JSON.",
    ),
) -> None:
    """Analyse one SQL query and return an AI-DAC security decision."""

    try:
        event = DatabaseEvent(
            query=query,
            username=username,
            database=database,
            source_system=source,
            client_ip=client_ip,
        )

        engine = AIDAC()
        decision = engine.analyze(event)

    except ValueError as error:
        console.print(f"[bold red]Invalid input:[/bold red] {error}")
        raise typer.Exit(code=2) from error

    if output_json:
        payload = {
            "event_id": decision.event_id,
            "risk_score": decision.risk_score,
            "severity": decision.severity.value,
            "classification": decision.classification,
            "indicators": decision.indicators,
            "explanation": decision.explanation,
            "recommended_action": decision.recommended_action,
            "automatic_action": decision.automatic_action,
        }

        console.print_json(json.dumps(payload))
        return

    table = Table(title="AI-DAC Security Analysis")
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Event ID", decision.event_id)
    table.add_row("Risk score", f"{decision.risk_score:.2f}")
    table.add_row("Severity", decision.severity.value.upper())
    table.add_row("Classification", decision.classification)
    table.add_row(
        "Indicators",
        "\n".join(decision.indicators) if decision.indicators else "None",
    )
    table.add_row("Explanation", decision.explanation)
    table.add_row("Recommended action", decision.recommended_action)
    table.add_row(
        "Automatic action",
        decision.automatic_action or "None — observation mode",
    )

    console.print(table)


if __name__ == "__main__":
    app()
