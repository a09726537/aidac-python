"""Command-line launcher for the optional AI-DAC REST API."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from aidac.alerting import DEFAULT_ALERT_LOG, DEFAULT_AUDIT_LOG

DEFAULT_API_TOKEN_ENV = "AIDAC_API_TOKEN"
DEFAULT_DASHBOARD_TOKEN_ENV = "AIDAC_DASHBOARD_TOKEN"
DEFAULT_DASHBOARD_SESSION_MINUTES = 480
_MINIMUM_API_TOKEN_LENGTH = 32
_MINIMUM_DASHBOARD_TOKEN_LENGTH = 32
_ALLOWED_LOG_LEVELS = {"critical", "error", "warning", "info", "debug", "trace"}
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

api_app = typer.Typer(
    help="Run the authenticated AI-DAC alert REST API.",
    no_args_is_help=True,
)
console = Console()


@api_app.command("serve")
def api_serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Listening IP address."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Listening TCP port."),
    ] = 8000,
    alert_log: Annotated[
        Path,
        typer.Option("--alert-log", help="Private JSONL alert lifecycle log."),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private JSONL API audit log."),
    ] = DEFAULT_AUDIT_LOG,
    token_env: Annotated[
        str,
        typer.Option("--token-env", help="Environment variable containing the API token."),
    ] = DEFAULT_API_TOKEN_ENV,
    allow_remote: Annotated[
        bool,
        typer.Option(
            "--allow-remote",
            help="Permit a non-loopback listening address. TLS is also required.",
        ),
    ] = False,
    ssl_certfile: Annotated[
        Path | None,
        typer.Option("--ssl-certfile", help="TLS certificate file for remote access."),
    ] = None,
    ssl_keyfile: Annotated[
        Path | None,
        typer.Option("--ssl-keyfile", help="TLS private-key file for remote access."),
    ] = None,
    dashboard: Annotated[
        bool,
        typer.Option(
            "--dashboard/--no-dashboard",
            help="Serve the authenticated web dashboard.",
        ),
    ] = False,
    dashboard_token_env: Annotated[
        str,
        typer.Option(
            "--dashboard-token-env",
            help="Environment variable containing the separate dashboard token.",
        ),
    ] = DEFAULT_DASHBOARD_TOKEN_ENV,
    dashboard_session_minutes: Annotated[
        int,
        typer.Option(
            "--dashboard-session-minutes",
            help="Dashboard session duration in minutes.",
        ),
    ] = DEFAULT_DASHBOARD_SESSION_MINUTES,
    log_level: Annotated[
        str,
        typer.Option("--log-level", help="Uvicorn log level."),
    ] = "info",
    access_log: Annotated[
        bool,
        typer.Option("--access-log/--no-access-log", help="Enable HTTP access logs."),
    ] = False,
) -> None:
    """Serve the local alert lifecycle API."""

    try:
        normalized_host = _validate_host(host)
        normalized_token_env = _validate_token_environment(token_env)
        normalized_level = _validate_log_level(log_level)
        normalized_dashboard_token_env = _validate_token_environment(dashboard_token_env)
        _validate_port(port)
        _validate_token(normalized_token_env)
        _validate_dashboard(
            enabled=dashboard,
            token_env=normalized_dashboard_token_env,
            session_minutes=dashboard_session_minutes,
        )
        certificate, private_key = _validate_transport(
            host=normalized_host,
            allow_remote=allow_remote,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
        )
    except ValueError as error:
        _fail(error)

    try:
        import uvicorn

        from aidac.api import create_app
    except ImportError as error:
        console.print(
            "[red]AI-DAC API dependencies are missing. "
            "Install them with: python -m pip install 'aidac-sec[api]'[/red]"
        )
        raise typer.Exit(code=1) from error

    application = create_app(
        alert_log=alert_log,
        audit_log=audit_log,
        token_env=normalized_token_env,
        dashboard_enabled=dashboard,
        dashboard_token_env=normalized_dashboard_token_env,
        dashboard_session_minutes=dashboard_session_minutes,
    )
    scheme = "https" if certificate is not None else "http"
    display_host = "localhost" if normalized_host in {"127.0.0.1", "::1"} else normalized_host
    console.print(f"[green]AI-DAC API listening on {scheme}://{display_host}:{port}[/green]")
    console.print(f"[dim]OpenAPI documentation: {scheme}://{display_host}:{port}/docs[/dim]")
    if dashboard:
        console.print(f"[dim]Web dashboard: {scheme}://{display_host}:{port}/dashboard[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")

    uvicorn.run(
        application,
        host=normalized_host,
        port=port,
        log_level=normalized_level,
        access_log=access_log,
        ssl_certfile=(None if certificate is None else str(certificate)),
        ssl_keyfile=(None if private_key is None else str(private_key)),
        proxy_headers=False,
    )


def _validate_host(host: str) -> str:
    normalized = host.strip()
    if normalized.casefold() == "localhost":
        return "127.0.0.1"
    try:
        ipaddress.ip_address(normalized)
    except ValueError as error:
        raise ValueError("--host must be an IPv4 or IPv6 address, or localhost.") from error
    return normalized


def _validate_port(port: int) -> None:
    if not 1 <= port <= 65_535:
        raise ValueError("--port must be between 1 and 65535.")


def _validate_token_environment(token_env: str) -> str:
    normalized = token_env.strip()
    if not _ENVIRONMENT_NAME.fullmatch(normalized):
        raise ValueError("--token-env must be a valid environment-variable name.")
    return normalized


def _validate_token(token_env: str) -> None:
    if len(os.getenv(token_env, "")) < _MINIMUM_API_TOKEN_LENGTH:
        raise ValueError(
            f"{token_env} must contain a random API token of at least "
            f"{_MINIMUM_API_TOKEN_LENGTH} characters."
        )


def _validate_dashboard(
    *,
    enabled: bool,
    token_env: str,
    session_minutes: int,
) -> None:
    if not 5 <= session_minutes <= 1_440:
        raise ValueError("--dashboard-session-minutes must be between 5 and 1440.")
    if enabled and len(os.getenv(token_env, "")) < _MINIMUM_DASHBOARD_TOKEN_LENGTH:
        raise ValueError(
            f"{token_env} must contain a random dashboard token of at least "
            f"{_MINIMUM_DASHBOARD_TOKEN_LENGTH} characters."
        )


def _validate_log_level(log_level: str) -> str:
    normalized = log_level.strip().casefold()
    if normalized not in _ALLOWED_LOG_LEVELS:
        allowed = ", ".join(sorted(_ALLOWED_LOG_LEVELS))
        raise ValueError(f"--log-level must be one of: {allowed}.")
    return normalized


def _validate_transport(
    *,
    host: str,
    allow_remote: bool,
    ssl_certfile: Path | None,
    ssl_keyfile: Path | None,
) -> tuple[Path | None, Path | None]:
    is_loopback = ipaddress.ip_address(host).is_loopback
    if (ssl_certfile is None) != (ssl_keyfile is None):
        raise ValueError("--ssl-certfile and --ssl-keyfile must be supplied together.")

    certificate = None if ssl_certfile is None else ssl_certfile.expanduser()
    private_key = None if ssl_keyfile is None else ssl_keyfile.expanduser()

    if certificate is not None:
        if not certificate.is_file():
            raise ValueError(f"TLS certificate not found: {certificate}")
        if private_key is None or not private_key.is_file():
            raise ValueError(f"TLS private key not found: {private_key}")

    if not is_loopback:
        if not allow_remote:
            raise ValueError("Remote binding requires --allow-remote.")
        if certificate is None or private_key is None:
            raise ValueError("Remote binding requires TLS certificate and key files.")

    return certificate, private_key


def _fail(error: Exception) -> NoReturn:
    console.print(f"[red]Unable to start AI-DAC API: {error}[/red]")
    raise typer.Exit(code=1) from error
