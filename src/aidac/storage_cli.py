"""Alert-store migration, backup, restore and inspection commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from aidac.alert_store import (
    AlertStoreError,
    backup_store,
    initialize_store,
    migrate_jsonl_to_sqlite,
    restore_store,
    store_info,
    verify_store,
)
from aidac.alerting import DEFAULT_ALERT_LOG

DEFAULT_LEGACY_ALERT_LOG = Path("~/.local/state/aidac/alerts.jsonl")
DEFAULT_BACKUP_DIRECTORY = Path("~/.local/share/aidac/backups")

storage_app = typer.Typer(
    help="Initialize, migrate, back up and restore AI-DAC alert storage.",
    no_args_is_help=True,
)
console = Console()


@storage_app.command("init")
def storage_init(
    store: Annotated[
        Path,
        typer.Option("--store", help="SQLite alert-store path."),
    ] = DEFAULT_ALERT_LOG,
) -> None:
    """Initialize or migrate the SQLite schema."""

    try:
        initialized = initialize_store(store)
        information = store_info(initialized)
    except AlertStoreError as error:
        _fail("Unable to initialize alert store", error)

    console.print(f"[green]Alert store ready:[/green] {initialized}")
    console.print(f"Schema version: {information['schema_version']}")


@storage_app.command("info")
def storage_information(
    store: Annotated[
        Path,
        typer.Option("--store", help="SQLite store or legacy JSONL log."),
    ] = DEFAULT_ALERT_LOG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """Inspect storage backend, schema, size and alert count."""

    try:
        information = verify_store(store)
    except AlertStoreError as error:
        _fail("Unable to inspect alert store", error)

    if json_output:
        typer.echo(json.dumps(information, indent=2, sort_keys=True))
        return

    table = Table(title="AI-DAC alert storage", show_header=False, show_lines=True)
    table.add_column("Property")
    table.add_column("Value")
    for key, value in information.items():
        table.add_row(key, str(value))
    console.print(table)


@storage_app.command("migrate-jsonl")
def storage_migrate_jsonl(
    source: Annotated[
        Path,
        typer.Option("--source", help="Legacy v0.6+ JSONL alert log."),
    ] = DEFAULT_LEGACY_ALERT_LOG,
    destination: Annotated[
        Path,
        typer.Option("--destination", help="Destination SQLite alert store."),
    ] = DEFAULT_ALERT_LOG,
    merge: Annotated[
        bool,
        typer.Option("--merge", help="Merge into a non-empty destination."),
    ] = False,
) -> None:
    """Import deduplicated lifecycle state from JSONL into SQLite."""

    try:
        imported = migrate_jsonl_to_sqlite(source, destination, merge=merge)
    except AlertStoreError as error:
        _fail("Unable to migrate alert data", error)

    console.print(f"[green]Migration completed:[/green] {imported} alerts imported.")
    console.print(f"Destination: {destination.expanduser()}")


@storage_app.command("backup")
def storage_backup(
    store: Annotated[
        Path,
        typer.Option("--store", help="Alert store to back up."),
    ] = DEFAULT_ALERT_LOG,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Backup directory or destination file."),
    ] = DEFAULT_BACKUP_DIRECTORY,
) -> None:
    """Create a consistent private alert-store backup."""

    expanded_output = output.expanduser()
    if not expanded_output.suffix:
        expanded_output.mkdir(parents=True, exist_ok=True)
        expanded_output.chmod(0o700)

    try:
        backup = backup_store(store, expanded_output)
    except (AlertStoreError, OSError) as error:
        _fail("Unable to back up alert store", error)

    console.print(f"[green]Backup created:[/green] {backup}")


@storage_app.command("restore")
def storage_restore(
    backup: Annotated[Path, typer.Argument(help="Backup file to restore.")],
    store: Annotated[
        Path,
        typer.Option("--store", help="Destination alert store."),
    ] = DEFAULT_ALERT_LOG,
    confirmed: Annotated[
        bool,
        typer.Option("--yes", help="Confirm replacement of an existing store."),
    ] = False,
) -> None:
    """Validate and restore a store backup."""

    destination = store.expanduser()
    if destination.exists() and not confirmed:
        console.print("[yellow]Restore was not performed. Add --yes to replace the store.[/yellow]")
        raise typer.Exit(code=1)

    try:
        restored = restore_store(backup, destination, overwrite=confirmed)
    except AlertStoreError as error:
        _fail("Unable to restore alert store", error)

    console.print(f"[green]Alert store restored:[/green] {restored}")


def _fail(prefix: str, error: Exception) -> NoReturn:
    console.print(f"[red]{prefix}: {error}[/red]")
    raise typer.Exit(code=1) from error
