"""Operational observability bundle and distributed health commands."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Annotated, Any, NoReturn
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from aidac.alerting import AlertingError, WebhookSettings, send_signed_webhook, utc_timestamp
from aidac.component_health import (
    ComponentHealthError,
    check_components,
    health_summary,
    load_component_targets,
    write_health_report,
)

DEFAULT_OPERATIONS_DIRECTORY = Path("./aidac-operations")
DEFAULT_COMPONENT_CONFIG = Path("~/.config/aidac/components.toml")
DEFAULT_HEALTH_REPORT = Path("~/.local/state/aidac/component-health.json")
DEFAULT_OPERATIONS_WEBHOOK_SECRET_ENV = "AIDAC_OPERATIONS_WEBHOOK_SECRET"

ops_app = typer.Typer(
    help="Generate observability assets and check distributed components.",
    no_args_is_help=True,
)
console = Console()


@ops_app.command("init")
def ops_init(
    output_directory: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory for generated operations assets."),
    ] = DEFAULT_OPERATIONS_DIRECTORY,
    aidac_url: Annotated[
        str,
        typer.Option("--aidac-url", help="Base URL Prometheus uses to reach AI-DAC."),
    ] = "http://127.0.0.1:8000",
    viewer_token_file: Annotated[
        Path,
        typer.Option(
            "--viewer-token-file",
            help="Host path containing the AI-DAC viewer token for Prometheus.",
        ),
    ] = Path("~/.config/aidac/viewer.token"),
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Replace an existing generated bundle."),
    ] = False,
) -> None:
    """Generate Prometheus, Alertmanager, Grafana, and Collector assets."""

    try:
        normalized_url = _validate_base_url(aidac_url)
        destination = output_directory.expanduser().resolve()
        token_file = viewer_token_file.expanduser().resolve()
        generated = generate_operations_bundle(
            destination,
            aidac_url=normalized_url,
            viewer_token_file=token_file,
            overwrite=overwrite,
        )
    except (ComponentHealthError, OSError, ValueError) as error:
        _fail(str(error))

    console.print(f"[green]AI-DAC operations bundle generated:[/green] {destination}")
    for path in generated:
        console.print(f"  {path.relative_to(destination)}")
    console.print("[yellow]Review Alertmanager receivers before production deployment.[/yellow]")


@ops_app.command("validate")
def ops_validate(
    directory: Annotated[
        Path,
        typer.Option("--directory", help="Generated operations bundle directory."),
    ] = DEFAULT_OPERATIONS_DIRECTORY,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
) -> None:
    """Validate the generated bundle structure and dashboard JSON."""

    try:
        result = validate_operations_bundle(directory.expanduser().resolve())
    except (OSError, ValueError) as error:
        _fail(str(error))

    if json_output:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
    else:
        table = Table(title="AI-DAC operations bundle validation", show_header=False)
        table.add_column("Property")
        table.add_column("Value")
        table.add_row("valid", str(result["valid"]))
        table.add_row("files", str(result["file_count"]))
        table.add_row("warnings", str(len(result["warnings"])))
        console.print(table)
        for warning in result["warnings"]:
            console.print(f"[yellow]Warning:[/yellow] {warning}")
    if not result["valid"]:
        raise typer.Exit(code=1)


@ops_app.command("health")
def ops_health(
    config_file: Annotated[
        Path,
        typer.Option("--config", help="TOML file containing distributed component targets."),
    ] = DEFAULT_COMPONENT_CONFIG,
    report_file: Annotated[
        Path | None,
        typer.Option("--report", help="Optional private JSON report output."),
    ] = DEFAULT_HEALTH_REPORT,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Return machine-readable JSON."),
    ] = False,
    notify_webhook: Annotated[
        str | None,
        typer.Option("--notify-webhook", help="HTTPS webhook notified when health is degraded."),
    ] = None,
    webhook_secret_env: Annotated[
        str,
        typer.Option("--webhook-secret-env", help="Webhook signing-secret environment variable."),
    ] = DEFAULT_OPERATIONS_WEBHOOK_SECRET_ENV,
    notify_always: Annotated[
        bool,
        typer.Option(
            "--notify-always",
            help="Notify even when all required components are healthy.",
        ),
    ] = False,
) -> None:
    """Probe distributed components and optionally notify an operations webhook."""

    try:
        targets = load_component_targets(config_file)
        results = check_components(targets)
        summary = health_summary(results)
        if report_file is not None:
            write_health_report(report_file, summary)
        if notify_webhook is not None and (notify_always or summary["status"] != "healthy"):
            settings = WebhookSettings(
                url=notify_webhook,
                secret_env=webhook_secret_env,
            )
            payload = {
                "type": "aidac_component_health",
                "generated_at": utc_timestamp(),
                **summary,
            }
            send_signed_webhook(settings, payload)
    except (AlertingError, ComponentHealthError, OSError) as error:
        _fail(str(error))

    if json_output:
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        table = Table(title="AI-DAC distributed component health")
        table.add_column("Component")
        table.add_column("Required")
        table.add_column("Healthy")
        table.add_column("HTTP")
        table.add_column("Duration")
        table.add_column("Detail")
        for result in results:
            table.add_row(
                result.name,
                str(result.required),
                str(result.healthy),
                "-" if result.status_code is None else str(result.status_code),
                f"{result.duration_seconds:.3f}s",
                result.detail,
            )
        console.print(table)
        console.print(f"Status: {summary['status']}")
    if summary["status"] != "healthy":
        raise typer.Exit(code=2)


def generate_operations_bundle(
    destination: Path,
    *,
    aidac_url: str,
    viewer_token_file: Path,
    overwrite: bool,
) -> list[Path]:
    """Generate a complete, secret-free observability bundle."""

    if destination.exists():
        if not overwrite:
            raise ValueError(f"Operations directory already exists: {destination}")
        if destination.is_symlink():
            raise ValueError("Refusing to overwrite a symbolic-link operations directory.")
        shutil.rmtree(destination)

    files: dict[str, str] = {
        "docker-compose.ops.yml": _docker_compose(viewer_token_file),
        "prometheus/prometheus.yml": _prometheus_config(aidac_url),
        "prometheus/rules/aidac-alerts.yml": _prometheus_rules(),
        "alertmanager/alertmanager.yml": _alertmanager_config(),
        "grafana/provisioning/datasources/aidac.yml": _grafana_datasource(),
        "grafana/provisioning/dashboards/aidac.yml": _grafana_provider(),
        "grafana/dashboards/aidac-overview.json": json.dumps(
            _grafana_dashboard(), indent=2, sort_keys=True
        )
        + "\n",
        "otel-collector/config.yaml": _otel_collector_config(),
        "components.toml": _components_template(aidac_url),
        "README.md": _operations_readme(aidac_url, viewer_token_file),
    }

    generated: list[Path] = []
    destination.mkdir(parents=True, exist_ok=False)
    destination.chmod(0o700)
    for relative in ("prometheus-data", "alertmanager-data", "grafana-data"):
        data_directory = destination / relative
        data_directory.mkdir(parents=True, exist_ok=True)
        data_directory.chmod(0o700)
    for relative, content in files.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o700)
        target.write_text(content, encoding="utf-8")
        target.chmod(0o600)
        generated.append(target)
    return generated


def validate_operations_bundle(directory: Path) -> dict[str, Any]:
    """Validate generated files without requiring Docker, Prometheus, or Grafana."""

    required = {
        "docker-compose.ops.yml",
        "prometheus/prometheus.yml",
        "prometheus/rules/aidac-alerts.yml",
        "alertmanager/alertmanager.yml",
        "grafana/provisioning/datasources/aidac.yml",
        "grafana/provisioning/dashboards/aidac.yml",
        "grafana/dashboards/aidac-overview.json",
        "otel-collector/config.yaml",
        "components.toml",
        "README.md",
    }
    missing = sorted(relative for relative in required if not (directory / relative).is_file())
    warnings: list[str] = []
    errors: list[str] = []
    if missing:
        errors.append(f"Missing files: {', '.join(missing)}")

    dashboard_path = directory / "grafana/dashboards/aidac-overview.json"
    if dashboard_path.exists():
        try:
            dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
            if dashboard.get("uid") != "aidac-operations":
                errors.append("Grafana dashboard UID is missing or unexpected.")
            if not isinstance(dashboard.get("panels"), list) or not dashboard["panels"]:
                errors.append("Grafana dashboard contains no panels.")
        except (json.JSONDecodeError, OSError) as error:
            errors.append(f"Invalid Grafana dashboard JSON: {error}")

    components_path = directory / "components.toml"
    if components_path.exists():
        try:
            load_component_targets(components_path)
        except ComponentHealthError as error:
            errors.append(str(error))

    alertmanager_path = directory / "alertmanager/alertmanager.yml"
    if alertmanager_path.exists() and "replace.example.invalid" in alertmanager_path.read_text(
        encoding="utf-8"
    ):
        warnings.append("Alertmanager webhook receiver still contains the replacement placeholder.")

    return {
        "valid": not errors,
        "file_count": sum((directory / relative).is_file() for relative in required),
        "errors": errors,
        "warnings": warnings,
    }


def _validate_base_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--aidac-url must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("--aidac-url must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("--aidac-url must not contain a query string or fragment.")
    return normalized


def _docker_compose(viewer_token_file: Path) -> str:
    token_volume = json.dumps(f"{viewer_token_file}:/run/secrets/aidac_viewer_token:ro")
    return f"""services:
  prometheus:
    image: prom/prometheus:latest
    user: "${{AIDAC_UID:-1000}}:${{AIDAC_GID:-1000}}"
    network_mode: host
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --web.listen-address=127.0.0.1:9090
      - --storage.tsdb.path=/prometheus/data
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/rules:/etc/prometheus/rules:ro
      - ./prometheus-data:/prometheus/data
      - {token_volume}

  alertmanager:
    image: prom/alertmanager:latest
    user: "${{AIDAC_UID:-1000}}:${{AIDAC_GID:-1000}}"
    network_mode: host
    command:
      - --config.file=/etc/alertmanager/alertmanager.yml
      - --web.listen-address=127.0.0.1:9093
      - --storage.path=/alertmanager
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
      - ./alertmanager-data:/alertmanager

  grafana:
    image: grafana/grafana:latest
    user: "${{AIDAC_UID:-1000}}:${{AIDAC_GID:-1000}}"
    network_mode: host
    environment:
      GF_SERVER_HTTP_ADDR: 127.0.0.1
      GF_SERVER_HTTP_PORT: "3000"
      GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_admin_password
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
      - ./grafana-data:/var/lib/grafana
      - ./grafana-admin-password:/run/secrets/grafana_admin_password:ro
    depends_on:
      - prometheus

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    user: "${{AIDAC_UID:-1000}}:${{AIDAC_GID:-1000}}"
    network_mode: host
    command:
      - --config=/etc/otelcol-contrib/config.yaml
    volumes:
      - ./otel-collector/config.yaml:/etc/otelcol-contrib/config.yaml:ro
"""


def _prometheus_config(aidac_url: str) -> str:
    parsed = urlparse(aidac_url)
    target = parsed.netloc
    scheme = parsed.scheme
    prefix = parsed.path.rstrip("/")
    metrics_path = f"{prefix}/metrics" if prefix else "/metrics"
    return f"""global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/rules/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["127.0.0.1:9093"]

scrape_configs:
  - job_name: aidac
    scheme: {scheme}
    metrics_path: {metrics_path}
    authorization:
      type: Bearer
      credentials_file: /run/secrets/aidac_viewer_token
    static_configs:
      - targets: ["{target}"]
        labels:
          service: aidac
"""


def _prometheus_rules() -> str:
    return """groups:
  - name: aidac-operations
    rules:
      - alert: AIDACServiceDown
        expr: up{job="aidac"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: AI-DAC metrics endpoint is unavailable
          description: Prometheus has been unable to scrape AI-DAC for at least two minutes.

      - alert: AIDACAlertStoreUnavailable
        expr: aidac_alert_store_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: AI-DAC alert store is unavailable
          description: AI-DAC cannot read its configured lifecycle store.

      - alert: AIDACCriticalAlertsPresent
        expr: aidac_alerts_by_severity{severity="critical"} > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: Critical database-security alerts require review
          description: AI-DAC currently contains one or more critical alerts.

      - alert: AIDACCriticalIncidentOpen
        expr: sum(aidac_incidents_total{severity="critical",status!="resolved"}) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: Critical correlated AI-DAC incident is active
          description: >-
            One or more critical correlated database-security incidents require human review.

      - alert: AIDACRecurringIncidentActivity
        expr: aidac_incident_recurrence_max >= 3
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: Recurrent activity detected in an AI-DAC incident
          description: An active correlated incident contains at least three observed occurrences.

      - alert: AIDACRequiredComponentDown
        expr: aidac_component_up == 0 and on(component) aidac_component_required == 1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: Required AI-DAC component is unhealthy
          description: A required distributed component failed its latest health probe.

      - alert: AIDACServerErrors
        expr: sum(increase(aidac_http_requests_total{status=~"5.."}[5m])) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: AI-DAC API returned server errors
          description: At least one HTTP 5xx response occurred during the last five minutes.
"""


def _alertmanager_config() -> str:
    return """route:
  receiver: aidac-operations-webhook
  group_by: [alertname, severity]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

receivers:
  - name: aidac-operations-webhook
    webhook_configs:
      - url: https://replace.example.invalid/aidac-alerts
        send_resolved: true
"""


def _grafana_datasource() -> str:
    return """apiVersion: 1
prune: true
datasources:
  - name: Prometheus
    uid: aidac-prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
"""


def _grafana_provider() -> str:
    return """apiVersion: 1
providers:
  - name: AI-DAC
    orgId: 1
    folder: AI-DAC
    type: file
    disableDeletion: true
    editable: false
    options:
      path: /var/lib/grafana/dashboards
"""


def _grafana_dashboard() -> dict[str, Any]:
    return {
        "annotations": {"list": []},
        "editable": False,
        "graphTooltip": 1,
        "panels": [
            _stat_panel(1, "Current alerts", "sum(aidac_alerts_total)", 0, 0),
            _stat_panel(
                2,
                "Critical alerts",
                'sum(aidac_alerts_by_severity{severity="critical"})',
                8,
                0,
            ),
            _stat_panel(3, "Alert store up", "min(aidac_alert_store_up)", 16, 0),
            _stat_panel(
                4,
                "Active incidents",
                'sum(aidac_incidents_total{status!="resolved"})',
                0,
                5,
            ),
            _stat_panel(
                5,
                "Critical active incidents",
                'sum(aidac_incidents_total{severity="critical",status!="resolved"})',
                8,
                5,
            ),
            _stat_panel(6, "Maximum recurrence", "aidac_incident_recurrence_max", 16, 5),
            _timeseries_panel(
                7,
                "API request rate",
                "sum by (status) (rate(aidac_http_requests_total[5m]))",
                0,
                10,
                12,
            ),
            _timeseries_panel(
                8,
                "Request duration average",
                "sum(rate(aidac_http_request_duration_seconds_sum[5m])) / "
                "clamp_min(sum(rate(aidac_http_request_duration_seconds_count[5m])), 1e-9)",
                12,
                10,
                12,
            ),
            _timeseries_panel(
                9,
                "Distributed components",
                "aidac_component_up",
                0,
                18,
                24,
            ),
        ],
        "refresh": "30s",
        "schemaVersion": 40,
        "tags": ["aidac", "database-security", "operations"],
        "templating": {"list": []},
        "time": {"from": "now-6h", "to": "now"},
        "timezone": "browser",
        "title": "AI-DAC Security Operations",
        "uid": "aidac-operations",
        "version": 1,
    }


def _stat_panel(panel_id: int, title: str, expression: str, x: int, y: int) -> dict[str, Any]:
    return {
        "id": panel_id,
        "type": "stat",
        "title": title,
        "datasource": {"type": "prometheus", "uid": "aidac-prometheus"},
        "gridPos": {"h": 5, "w": 8, "x": x, "y": y},
        "targets": [{"expr": expression, "refId": "A"}],
        "options": {
            "colorMode": "value",
            "graphMode": "area",
            "reduceOptions": {"calcs": ["lastNotNull"]},
        },
    }


def _timeseries_panel(
    panel_id: int,
    title: str,
    expression: str,
    x: int,
    y: int,
    width: int,
) -> dict[str, Any]:
    return {
        "id": panel_id,
        "type": "timeseries",
        "title": title,
        "datasource": {"type": "prometheus", "uid": "aidac-prometheus"},
        "gridPos": {"h": 8, "w": width, "x": x, "y": y},
        "targets": [
            {
                "expr": expression,
                "legendFormat": "{{{{status}}}}{{{{component}}}}",
                "refId": "A",
            }
        ],
    }


def _otel_collector_config() -> str:
    return """receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
      http:
        endpoint: 127.0.0.1:4318

processors:
  batch:

exporters:
  debug:
    verbosity: basic

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
"""


def _components_template(aidac_url: str) -> str:
    health_base_url = _host_health_base_url(aidac_url)
    return f"""# Distributed component health checks. Do not embed credentials in URLs.

[[components]]
name = "aidac-api"
url = "{health_base_url}/health/live"
required = true
timeout_seconds = 3.0

[[components]]
name = "prometheus"
url = "http://127.0.0.1:9090/-/ready"
required = true
timeout_seconds = 3.0

[[components]]
name = "grafana"
url = "http://127.0.0.1:3000/api/health"
required = false
timeout_seconds = 3.0

[[components]]
name = "alertmanager"
url = "http://127.0.0.1:9093/-/ready"
required = false
timeout_seconds = 3.0
"""


def _host_health_base_url(aidac_url: str) -> str:
    parsed = urlparse(aidac_url)
    if parsed.hostname != "host.docker.internal":
        return aidac_url
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    authority = "127.0.0.1" if port in {None, default_port} else f"127.0.0.1:{port}"
    return f"{parsed.scheme}://{authority}{parsed.path.rstrip('/')}"


def _operations_readme(aidac_url: str, viewer_token_file: Path) -> str:
    return f"""# AI-DAC 1.2 operations bundle

This directory provisions Prometheus, Alertmanager, Grafana, and an OpenTelemetry Collector.
No bearer token, database password, webhook secret, or Grafana password is generated into
version-controlled configuration.

## Before starting

1. Ensure AI-DAC is reachable from containers at `{aidac_url}`.
2. Confirm the viewer token exists at `{viewer_token_file}` with mode 600.
3. Create `grafana-admin-password` in this directory with mode 600.
4. Replace the Alertmanager webhook placeholder in `alertmanager/alertmanager.yml`.

## Start

```bash
chmod 600 grafana-admin-password
export AIDAC_UID="$(id -u)"
export AIDAC_GID="$(id -g)"
docker compose -f docker-compose.ops.yml up -d
```

Grafana: http://127.0.0.1:3000
Prometheus: http://127.0.0.1:9090
Alertmanager: http://127.0.0.1:9093

## OpenTelemetry

Set these variables for the AI-DAC service to export HTTP request spans through OTLP/HTTP:

```bash
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces
OTEL_SERVICE_NAME=aidac-api
```

Install the optional exporter dependencies with `python -m pip install 'aidac-sec[otel]'`.
The Collector uses the debug exporter by default; replace it with the organization-approved
trace backend before production deployment.

## Distributed health

```bash
aidac ops health --config ./components.toml
```

Copy `components.toml` to `~/.config/aidac/components.toml` for service-side health checks.
"""


def _fail(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=1)
