"""Operational diagnostics for AI-DAC installations."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from aidac import __version__
from aidac.alert_store import AlertStoreError, verify_store
from aidac.alerting import DEFAULT_ALERT_LOG, DEFAULT_AUDIT_LOG, AlertingError, verify_audit_log
from aidac.config import DEFAULT_CONFIG_FILE, ConfigError, load_settings

console = Console()
_TOKEN_ENVIRONMENTS = (
    "AIDAC_API_TOKEN",
    "AIDAC_API_VIEWER_TOKEN",
    "AIDAC_API_ANALYST_TOKEN",
    "AIDAC_API_ADMIN_TOKEN",
)


def doctor(
    config_file: Annotated[
        Path,
        typer.Option("--config", help="AI-DAC TOML configuration file."),
    ] = DEFAULT_CONFIG_FILE,
    store: Annotated[
        Path,
        typer.Option("--store", help="SQLite store or legacy JSONL log."),
    ] = DEFAULT_ALERT_LOG,
    audit_log: Annotated[
        Path,
        typer.Option("--audit-log", help="Private chained JSONL audit log."),
    ] = DEFAULT_AUDIT_LOG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """Run local configuration, storage, audit and permission checks."""

    checks: list[dict[str, Any]] = []
    alert_backend = "unknown"
    checks.append({"check": "package_version", "status": "ok", "detail": __version__})

    try:
        load_settings(config_file)
        checks.append(
            {
                "check": "configuration",
                "status": "ok",
                "detail": str(config_file.expanduser()),
            }
        )
    except ConfigError as error:
        checks.append({"check": "configuration", "status": "error", "detail": str(error)})

    try:
        information = verify_store(store)
        alert_backend = str(information.get("backend", "unknown"))
        checks.append(
            {
                "check": "alert_store",
                "status": "ok" if information.get("valid") else "error",
                "detail": information,
            }
        )
    except AlertStoreError as error:
        checks.append({"check": "alert_store", "status": "error", "detail": str(error)})

    try:
        audit = verify_audit_log(audit_log)
        checks.append(
            {
                "check": "audit_chain",
                "status": "ok" if audit.valid else "error",
                "detail": {
                    "records": audit.records,
                    "chained_records": audit.chained_records,
                    "legacy_records": audit.legacy_records,
                    "message": audit.message,
                    "failure_line": audit.failure_line,
                },
            }
        )
    except AlertingError as error:
        checks.append({"check": "audit_chain", "status": "error", "detail": str(error)})

    if alert_backend == "postgresql":
        checks.append(
            {
                "check": "alert_store_permissions",
                "status": "ok",
                "detail": "Managed by PostgreSQL roles and privileges.",
            }
        )
    else:
        checks.append(_permission_check("alert_store_permissions", store.expanduser()))
    checks.append(_permission_check("audit_log_permissions", audit_log.expanduser()))

    configured_roles = [
        environment for environment in _TOKEN_ENVIRONMENTS if len(os.getenv(environment, "")) >= 32
    ]
    checks.append(
        {
            "check": "api_authentication",
            "status": "ok" if configured_roles else "warning",
            "detail": configured_roles or "No API token is configured in this shell.",
        }
    )

    errors = sum(item["status"] == "error" for item in checks)
    warnings = sum(item["status"] == "warning" for item in checks)
    payload = {
        "version": __version__,
        "status": "error" if errors else "ok",
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }

    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        table = Table(title="AI-DAC diagnostics", show_lines=True)
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for item in checks:
            table.add_row(
                str(item["check"]),
                str(item["status"]),
                _display_detail(item["detail"]),
            )
        console.print(table)
        console.print(f"Errors: {errors} | Warnings: {warnings}")

    if errors:
        raise typer.Exit(code=1)


def _permission_check(name: str, path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"check": name, "status": "warning", "detail": "file does not exist yet"}
    permissions = stat.S_IMODE(path.stat().st_mode)
    private = permissions & 0o077 == 0
    return {
        "check": name,
        "status": "ok" if private else "error",
        "detail": oct(permissions),
    }


def _display_detail(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)
