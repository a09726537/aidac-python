"""Generate and manage a hardened user-level systemd service for AI-DAC."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

SERVICE_NAME = "aidac-api.service"
service_app = typer.Typer(
    help="Generate and manage the AI-DAC user systemd service.",
    no_args_is_help=True,
)
console = Console()


@service_app.command("install")
def service_install(
    host: Annotated[str, typer.Option("--host", help="API listening address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="API listening port.")] = 8000,
    dashboard: Annotated[
        bool,
        typer.Option("--dashboard/--no-dashboard", help="Enable the web dashboard."),
    ] = True,
    enable: Annotated[
        bool,
        typer.Option("--enable/--no-enable", help="Enable and start the service immediately."),
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace an existing generated unit."),
    ] = False,
) -> None:
    """Install a private user-level systemd unit and environment template."""

    if not 1 <= port <= 65_535:
        _fail("--port must be between 1 and 65535.")
    if host.strip() not in {"127.0.0.1", "::1", "localhost"}:
        _fail("The generated service is loopback-only. Use the API CLI for remote TLS deployment.")
    if shutil.which("systemctl") is None:
        _fail("systemctl is not available on this system.")

    home = Path.home()
    unit_dir = home / ".config/systemd/user"
    env_file = home / ".config/aidac/aidac.env"
    unit_file = unit_dir / SERVICE_NAME
    state_dir = home / ".local/state/aidac"
    share_dir = home / ".local/share/aidac"
    executable = _aidac_executable()

    if unit_file.exists() and not overwrite:
        _fail(f"Service unit already exists: {unit_file}. Add --overwrite to replace it.")

    for directory in (unit_dir, env_file.parent, state_dir, share_dir):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)

    if not env_file.exists():
        env_file.write_text(_environment_template(), encoding="utf-8")
        env_file.chmod(0o600)

    unit_file.write_text(
        render_systemd_unit(
            executable=executable,
            env_file=env_file,
            state_dir=state_dir,
            share_dir=share_dir,
            host="127.0.0.1" if host == "localhost" else host,
            port=port,
            dashboard=dashboard,
        ),
        encoding="utf-8",
    )
    unit_file.chmod(0o600)

    _systemctl("daemon-reload")
    if enable:
        _systemctl("enable", "--now", SERVICE_NAME)

    console.print(f"[green]Systemd user service installed:[/green] {unit_file}")
    console.print(f"Environment file: {env_file}")
    if not enable:
        console.print(f"Start later with: systemctl --user enable --now {SERVICE_NAME}")


@service_app.command("status")
def service_status() -> None:
    """Display the current user service status."""

    result = subprocess.run(
        ["systemctl", "--user", "status", SERVICE_NAME, "--no-pager"],
        check=False,
        text=True,
    )
    if result.returncode not in {0, 3}:
        raise typer.Exit(code=result.returncode)


@service_app.command("logs")
def service_logs(
    lines: Annotated[
        int,
        typer.Option("--lines", "-n", help="Number of recent journal lines."),
    ] = 100,
) -> None:
    """Show recent service journal entries."""

    if not 1 <= lines <= 100_000:
        _fail("--lines must be between 1 and 100000.")
    result = subprocess.run(
        [
            "journalctl",
            "--user",
            "-u",
            SERVICE_NAME,
            "-n",
            str(lines),
            "--no-pager",
        ],
        check=False,
        text=True,
    )
    if result.returncode:
        raise typer.Exit(code=result.returncode)


@service_app.command("remove")
def service_remove(
    confirmed: Annotated[
        bool,
        typer.Option("--yes", help="Confirm service removal."),
    ] = False,
) -> None:
    """Disable and remove the generated user service unit."""

    if not confirmed:
        _fail("Add --yes to remove the generated service unit.")
    unit_file = Path.home() / ".config/systemd/user" / SERVICE_NAME
    _systemctl("disable", "--now", SERVICE_NAME, check=False)
    unit_file.unlink(missing_ok=True)
    _systemctl("daemon-reload")
    console.print(f"[green]Removed service unit:[/green] {unit_file}")


def render_systemd_unit(
    *,
    executable: Path,
    env_file: Path,
    state_dir: Path,
    share_dir: Path,
    host: str,
    port: int,
    dashboard: bool,
) -> str:
    """Render the hardened systemd user unit."""

    dashboard_flag = " --dashboard" if dashboard else ""
    log_file = state_dir / "service.jsonl"
    return f"""[Unit]
Description=AI-DAC Security Operations API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env_file}
ExecStart={executable} api serve --host {host} --port {port}{dashboard_flag} \
    --log-format json --log-file {log_file}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={state_dir} {share_dir}
UMask=0077

[Install]
WantedBy=default.target
"""


def _environment_template() -> str:
    return """# AI-DAC service environment. Keep this file private (mode 600).
# Generate separate random tokens of at least 32 characters.
AIDAC_API_VIEWER_TOKEN=
AIDAC_API_ANALYST_TOKEN=
AIDAC_API_ADMIN_TOKEN=
AIDAC_DASHBOARD_TOKEN=
# Optional PostgreSQL alert lifecycle store:
# AIDAC_ALERT_STORE_DSN=postgresql://aidac_app:REDACTED@127.0.0.1:5432/aidac_pgsql
# AIDAC_ALERT_STORE_SCHEMA=aidac
# Optional distributed component checks and OTLP traces:
# AIDAC_COMPONENTS_FILE=/home/user/.config/aidac/components.toml
AIDAC_INCIDENT_WINDOW_MINUTES=30
# AIDAC_INCIDENT_WEBHOOK_SECRET=replace-with-random-secret
# OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces
# OTEL_SERVICE_NAME=aidac-api
"""


def _aidac_executable() -> Path:
    candidate = Path(sys.executable).parent / "aidac"
    if not candidate.exists():
        _fail(f"AI-DAC executable not found beside the active Python interpreter: {candidate}")
    return candidate


def _systemctl(*arguments: str, check: bool = True) -> None:
    result = subprocess.run(
        ["systemctl", "--user", *arguments],
        check=False,
        text=True,
    )
    if check and result.returncode:
        _fail("systemctl --user command failed. Ensure a user systemd session is available.")


def _fail(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=1)
