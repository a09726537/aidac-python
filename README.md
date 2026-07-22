# AI-DAC Python Library

AI-DAC is an adaptive and explainable database-cybersecurity framework for detecting,
monitoring, storing, and managing potentially dangerous SQL activity.

Version **1.1.0** adds optional PostgreSQL lifecycle storage, Prometheus metrics, structured service logging, and hardened user-level systemd deployment while preserving the stable 1.0 interfaces.

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
- Local diagnostic and production-configuration commands

## Installation

```bash
python -m pip install aidac-sec
```

Install the REST API and dashboard dependencies:

```bash
python -m pip install "aidac-sec[api]"
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
- `POST /api/v1/alerts/{alert_id}/ack`
- `POST /api/v1/alerts/{alert_id}/resolve`
- `GET /api/v1/system/storage`
- `GET /api/v1/system/audit/verify`
- `GET /metrics` (viewer token required)

OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.


## Prometheus metrics

The authenticated `/metrics` endpoint exposes bounded HTTP counters, request-duration sums
and counts, alert gauges by lifecycle status and severity, and alert-store availability.
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
