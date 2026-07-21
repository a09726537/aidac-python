"""Configuration commands for the AI-DAC CLI."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from aidac.config import (
    DEFAULT_CONFIG_FILE,
    ConfigError,
    create_default_config,
    load_settings,
)

config_app = typer.Typer(
    help="Create and inspect AI-DAC configuration.",
    no_args_is_help=True,
)

console = Console()


@config_app.command("init")
def config_init(
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            help="Configuration file to create.",
        ),
    ] = DEFAULT_CONFIG_FILE,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Overwrite an existing configuration.",
        ),
    ] = False,
) -> None:
    """Create a secure default AI-DAC configuration file."""

    try:
        created_file = create_default_config(
            path,
            overwrite=force,
        )
    except ConfigError as error:
        console.print(f"[red]Configuration initialization failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print("[green]Configuration created successfully.[/green]")
    console.print(f"File: {created_file.expanduser()}")
    console.print("[yellow]No password or complete DSN was stored.[/yellow]")


@config_app.command("production")
def config_production(
    path: Annotated[
        Path,
        typer.Option("--path", help="Production configuration file to create."),
    ] = Path("./aidac.production.toml"),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing file."),
    ] = False,
) -> None:
    """Create a production-oriented template without secrets."""

    try:
        created_file = create_default_config(path, overwrite=force, production=True)
    except ConfigError as error:
        console.print(f"[red]Production configuration failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(f"[green]Production template created:[/green] {created_file}")
    console.print(
        "[yellow]Review paths and supply all secrets through environment variables.[/yellow]"
    )


@config_app.command("show")
def config_show(
    path: Annotated[
        Path,
        typer.Option(
            "--path",
            help="Configuration file to inspect.",
        ),
    ] = DEFAULT_CONFIG_FILE,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Return machine-readable JSON.",
        ),
    ] = False,
) -> None:
    """Display the effective AI-DAC configuration."""

    expanded_path = path.expanduser()

    try:
        settings = load_settings(expanded_path)
    except ConfigError as error:
        console.print(f"[red]Unable to load configuration: {error}[/red]")
        raise typer.Exit(code=1) from error

    postgresql = _mapping_json_safe(asdict(settings.postgresql))
    storage = _mapping_json_safe(asdict(settings.storage))
    api = _mapping_json_safe(asdict(settings.api))

    payload = {
        "config_file": str(expanded_path),
        "config_file_exists": expanded_path.exists(),
        "postgresql": postgresql,
        "storage": storage,
        "api": api,
    }

    if json_output:
        typer.echo(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
        )
        return

    console.print(f"[bold]Configuration file:[/bold] {expanded_path}")
    console.print(f"[bold]File exists:[/bold] {'yes' if expanded_path.exists() else 'no'}")

    for title, section in (
        ("Effective PostgreSQL configuration", postgresql),
        ("Effective storage configuration", storage),
        ("Effective API configuration", api),
    ):
        table = Table(title=title, show_lines=True)
        table.add_column("Setting")
        table.add_column("Value")
        for key, value in section.items():
            table.add_row(key, str(value))
        console.print(table)

    console.print("[dim]Environment variables override values stored in config.toml.[/dim]")


def _mapping_json_safe(value: dict[str, Any]) -> dict[str, object]:
    return {str(key): _json_safe(item) for key, item in value.items()}


def _json_safe(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value
