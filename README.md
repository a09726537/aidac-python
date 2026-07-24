# AI-DAC Python Library

AI-DAC is an adaptive and explainable database-cybersecurity framework for detecting,
monitoring, storing, and managing potentially dangerous SQL activity.

Version **1.3.0** adds deterministic incident correlation, explainable Triple-Loop Learning assessments, incident-oriented API and CLI workflows, signed incident notifications, and incident observability while preserving the stable 1.x interfaces.

## Main capabilities

- SQL event normalization, anomaly detection, risk scoring, and explanations
- Read-only PostgreSQL audit collection and continuous monitoring
- SQLite alert store with schema migrations and transactional lifecycle updates
- Optional PostgreSQL lifecycle store selected securely through environment variables
- Import compatibility for legacy JSONL alert logs
- Alert deduplication with `new`, `acknowledged`, and `resolved` states
- Tamper-evident JSONL audit log with sequence numbers and SHA-256 hash chaining
- Role-aware REST API with `viewer`, `analyst`, and `admin` tokens
- Pagination, filtering, search, and per-token API rate limiting
- Authenticated server-rendered security-operations dashboard
- Consistent alert-store backup and validated restore commands
- Prometheus-compatible metrics and structured JSON application logs
- Hardened user-level systemd service generation and management
- Generated Prometheus, Alertmanager, Grafana, and OpenTelemetry Collector assets
- Distributed component health probes with bounded Prometheus labels
- Optional OTLP/HTTP request tracing through OpenTelemetry
- Signed operational webhook notifications for degraded component health
- Deterministic incident correlation across related alerts and bounded time windows
- Explainable Loop 1 detection, Loop 2 adaptation, and Loop 3 governance assessments
- Signed incident notifications that exclude SQL text, tokens, credentials, and DSNs
- Incident API, CLI, Prometheus rules, metrics, and Grafana panels
- Local diagnostic and production-configuration commands

## Installation

```bash
python -m pip install aidac-sec
```

Install the REST API and dashboard dependencies:

```bash
python -m pip install "aidac-sec[api]"
```

Install optional OpenTelemetry OTLP/HTTP trace export:

```bash
python -m pip install "aidac-sec[otel]"
```

## Basic analysis

```python
from aidac import AIDAC, DatabaseEvent

engine = AIDAC()
event = DatabaseEvent(
    query="DROP DATABASE production;",
    username="administrator",
    database="postgres",
    source_system="postgresql",
)

decision = engine.analyze(event)
print(decision.risk_score)
print(decision.severity.value)
print(decision.recommended_action)
```

```bash
aidac version
aidac scan "DROP DATABASE production;"
aidac postgres scan --min-risk 0.5
aidac postgres watch --interval 5 --min-severity high
```

## Alert storage

### SQLite default

AI-DAC uses this store by default:

```text
~/.local/state/aidac/alerts.db
```

Initialize or inspect it:

```bash
aidac storage init
aidac storage info
aidac storage info --json
```

### Upgrade from AI-DAC 0.6–0.9

Import the previous JSONL lifecycle log:

```bash
aidac storage migrate-jsonl \
  --source ~/.local/state/aidac/alerts.jsonl \
  --destination ~/.local/state/aidac/alerts.db
```

The JSONL backend remains supported when a path ending in `.jsonl` is supplied explicitly.

### Optional PostgreSQL lifecycle store

Set a dedicated writable PostgreSQL DSN outside the repository. The collector account
`aidac_reader` can remain read-only; use a separate least-privilege role for lifecycle data.

```bash
export AIDAC_ALERT_STORE_DSN="postgresql://aidac_app:REDACTED@127.0.0.1:5432/aidac_pgsql"
export AIDAC_ALERT_STORE_SCHEMA="aidac"
aidac storage init
aidac storage info
```

When `AIDAC_ALERT_STORE_DSN` is present, alert lifecycle commands, the API, dashboard,
monitoring process, backup, restore, and diagnostics use PostgreSQL. The DSN is never
returned by API or diagnostic output. `AIDAC_ALERT_STORE_SCHEMA` defaults to `aidac`.

Import a previous JSONL lifecycle log directly into PostgreSQL:

```bash
aidac storage migrate-jsonl \
  --source ~/.local/state/aidac/alerts.jsonl \
  --destination ~/.local/state/aidac/alerts.db
```

For PostgreSQL, backups are private application-level JSON snapshots that can be restored
with the same `aidac storage restore ... --yes` command.

## Alert lifecycle and search

```bash
aidac alerts list
aidac alerts list --status new --severity critical --min-risk 0.8
aidac alerts list --search production --limit 25 --offset 0 --json
aidac alerts show alrt_IDENTIFIER
aidac alerts ack alrt_IDENTIFIER --actor analyst --note "Review started"
aidac alerts resolve alrt_IDENTIFIER --actor analyst --note "Incident closed"
aidac alerts prune --older-than-days 90 --status resolved --yes
```

## Incident correlation and Triple-Loop Learning

AI-DAC correlates current alert snapshots using source system, database, actor identity, and a
bounded time window. Correlation is deterministic: it does not silently execute response actions
or modify the protected database.

```bash
aidac incidents list
aidac incidents list --status open --min-risk 0.8 --json
aidac incidents show inc_IDENTIFIER
aidac incidents correlate --output ~/.local/state/aidac/incidents.json
```

Each incident contains an explainable assessment with:

- **Loop 1 — detection and explanation:** evidence count, signal strength, recurrence, and observed classifications;
- **Loop 2 — response adaptation:** priority, response mode, evidence preservation, and recurrence handling;
- **Loop 3 — governance reflection:** control-effectiveness review, policy review, documented rationale, and feedback candidacy.

High and critical incidents require human-controlled review. AI-DAC does not automatically block,
terminate, quarantine, or modify database activity.

Send signed incident summaries without SQL statements or credentials:

```bash
export AIDAC_INCIDENT_WEBHOOK_SECRET="replace-with-random-secret"
aidac incidents notify \
  --webhook-url https://operations.example/aidac-incidents \
  --min-severity high
```

The default correlation window is 30 minutes. Set `AIDAC_INCIDENT_WINDOW_MINUTES` for the API and
service, or pass `--window-minutes` to incident CLI commands.

## Backup and restore

Create a consistent backup:

```bash
aidac storage backup
```

Select an explicit output path:

```bash
aidac storage backup --output ~/Backups/aidac-alerts.db
```

Restore after validation:

```bash
aidac storage restore ~/Backups/aidac-alerts.db --yes
```

## Tamper-evident audit log

Each new audit record contains a sequence number, the previous record hash, and its own
SHA-256 record hash. Legacy records remain readable and new records chain forward from them.

```bash
aidac audit verify
aidac audit verify --json
```

## Role-aware REST API

Create separate random tokens:

```bash
export AIDAC_API_VIEWER_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AIDAC_API_ANALYST_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AIDAC_API_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

The legacy `AIDAC_API_TOKEN` variable remains accepted as an administrator token.

Start the local service:

```bash
aidac api serve --rate-limit 120
```

Role permissions:

- `viewer`: list, search, summarize, and inspect alerts
- `analyst`: viewer permissions plus acknowledge and resolve
- `admin`: analyst permissions plus storage and audit diagnostics

Useful routes:

- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/alerts?limit=50&offset=0&q=production`
- `GET /api/v1/alerts/summary`
- `GET /api/v1/alerts/{alert_id}`
- `GET /api/v1/incidents?status=open&min_risk=0.8`
- `GET /api/v1/incidents/summary`
- `GET /api/v1/incidents/{incident_id}`
- `GET /api/v1/incidents/{incident_id}/assessment`
- `POST /api/v1/alerts/{alert_id}/ack`
- `POST /api/v1/alerts/{alert_id}/resolve`
- `GET /api/v1/system/storage`
- `GET /api/v1/system/audit/verify`
- `GET /api/v1/system/components`
- `GET /metrics` (viewer token required)

OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.


## Prometheus metrics

The authenticated `/metrics` endpoint exposes bounded HTTP counters, request-duration sums
and counts, alert gauges, correlated-incident gauges, recurrence state, and alert-store availability.
Prometheus can use the viewer token as a bearer token.

```bash
curl -H "Authorization: Bearer $AIDAC_API_VIEWER_TOKEN" \
  http://127.0.0.1:8000/metrics
```

No alert identifiers, SQL statements, database usernames, DSNs, or tokens are used as metric
labels.

## Structured logging

Write AI-DAC application events as private JSON Lines records:

```bash
aidac api serve \
  --log-format json \
  --log-file ~/.local/state/aidac/service.jsonl
```

The file is created with mode `600`. HTTP request records include method, normalized path,
status code, and duration without retaining bearer tokens or dynamic alert identifiers.

## User-level systemd deployment

Generate a hardened service and a private environment template:

```bash
aidac service install
```

Edit `~/.config/aidac/aidac.env`, add the required random tokens and optional PostgreSQL
store variables, then start the service:

```bash
systemctl --user enable --now aidac-api.service
aidac service status
aidac service logs --lines 100
```

The generated unit is loopback-only and uses `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=read-only`, private temporary storage, restart-on-failure, and `UMask=0077`.

## Operations bundle

Generate version-controlled observability assets without embedding secrets:

```bash
aidac ops init \
  --output-dir ./aidac-operations \
  --aidac-url http://127.0.0.1:8000 \
  --viewer-token-file ~/.config/aidac/viewer.token

aidac ops validate --directory ./aidac-operations
```

The bundle contains Prometheus scrape configuration, AI-DAC service and incident alerting rules, an
Alertmanager receiver template, Grafana provisioning, an incident-aware security-operations dashboard, an
OpenTelemetry Collector configuration, a Docker Compose file, and a component-health TOML
template. It references a viewer-token file but never copies the token into generated YAML.

Before starting the bundle, create a private `grafana-admin-password` file and replace the
Alertmanager webhook placeholder.

```bash
cd aidac-operations
chmod 600 grafana-admin-password
export AIDAC_UID="$(id -u)"
export AIDAC_GID="$(id -g)"
docker compose -f docker-compose.ops.yml up -d
```

## Distributed component health

Configure HTTP health targets in TOML:

```toml
[[components]]
name = "aidac-api"
url = "http://127.0.0.1:8000/health/live"
required = true
timeout_seconds = 3.0

[[components]]
name = "prometheus"
url = "http://127.0.0.1:9090/-/ready"
required = true
timeout_seconds = 3.0
```

Run an explicit health check and write a private JSON report:

```bash
aidac ops health \
  --config ~/.config/aidac/components.toml \
  --report ~/.local/state/aidac/component-health.json
```

To make the API and `/metrics` probe the same targets, set:

```bash
export AIDAC_COMPONENTS_FILE=~/.config/aidac/components.toml
```

Administrators can inspect the current result through
`GET /api/v1/system/components`. Prometheus exposes `aidac_component_up`,
`aidac_component_required`, and `aidac_component_probe_duration_seconds` without using target
URLs or credentials as labels.

A degraded health check can send a signed HTTPS notification:

```bash
export AIDAC_OPERATIONS_WEBHOOK_SECRET="replace-with-random-secret"
aidac ops health \
  --config ~/.config/aidac/components.toml \
  --notify-webhook https://operations.example/aidac-health
```

## OpenTelemetry trace export

AI-DAC can export API request spans with OTLP over HTTP. Dynamic alert identifiers are
normalized before becoming span attributes.

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces
export OTEL_SERVICE_NAME=aidac-api
aidac api serve
```

The exporter is disabled when no OTLP endpoint is configured. Production deployments should
send OTLP to an OpenTelemetry Collector and then forward traces to the organization-approved
backend.

## Web dashboard

Create a separate dashboard token and enable the dashboard:

```bash
export AIDAC_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
aidac api serve --dashboard
```

Open `http://127.0.0.1:8000/dashboard`. The API bearer tokens are never placed in browser
JavaScript, local storage, page URLs, or HTML.

## Production configuration

Create a hardened configuration template without secrets:

```bash
aidac config production --path ./aidac.production.toml
```

Inspect the effective configuration:

```bash
aidac config show --json
```

The template covers PostgreSQL collection, local storage paths, API binding, rate limiting, and dashboard session settings. PostgreSQL lifecycle storage is selected only through `AIDAC_ALERT_STORE_DSN` and `AIDAC_ALERT_STORE_SCHEMA`. Passwords and tokens must remain in environment variables or a dedicated secret
manager.

## Diagnostics

```bash
aidac doctor
aidac doctor --json
```

The diagnostic command checks configuration parsing, alert-store integrity, audit-chain
integrity, private file permissions, and API token availability in the current shell.

## Network safety

The API listens on loopback by default. Binding to a non-loopback address requires both
`--allow-remote` and TLS certificate/key files. CORS is not enabled by default. AI-DAC
operates in observation mode and does not automatically modify or block database activity.

## License

Apache License 2.0.
