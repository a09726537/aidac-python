"""Tamper-evident local audit-log commands."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from aidac.alerting import DEFAULT_AUDIT_LOG, AlertingError, verify_audit_log

audit_app = typer.Typer(
    help="Verify the local AI-DAC audit hash chain.",
    no_args_is_help=True,
)
console = Console()


@audit_app.command("verify")
def audit_verify(
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private chained JSONL audit log."),
    ] = DEFAULT_AUDIT_LOG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """Verify sequence numbers and cryptographic record links."""

    try:
        result = verify_audit_log(audit_log)
    except AlertingError as error:
        _fail(error)

    payload = asdict(result)
    payload["path"] = str(audit_log.expanduser())
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        table = Table(title="AI-DAC audit verification", show_header=False, show_lines=True)
        table.add_column("Property")
        table.add_column("Value")
        for key, value in payload.items():
            table.add_row(key, str(value))
        console.print(table)

    if not result.valid:
        raise typer.Exit(code=1)


def _fail(error: Exception) -> NoReturn:
    console.print(f"[red]Unable to verify audit log: {error}[/red]")
    raise typer.Exit(code=1) from error
