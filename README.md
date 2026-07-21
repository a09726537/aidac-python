# AI-DAC Python Library

AI-DAC is an adaptive and explainable database-cybersecurity framework for detecting,
monitoring, and managing potentially dangerous SQL activity.

## Features

- SQL security-event normalization
- Rule-based anomaly detection
- Risk scoring and severity classification
- Human-readable explanations
- Read-only PostgreSQL audit collection
- Continuous PostgreSQL monitoring
- Private JSONL alert and audit logs
- Signed HTTPS webhook notifications
- Alert deduplication and lifecycle management
- Authenticated REST API and OpenAPI documentation
- Server-rendered security-operations dashboard
- Python API and command-line interface

## Installation

```bash
python -m pip install aidac-sec
```

Install the REST API and dashboard dependencies:

```bash
python -m pip install "aidac-sec[api]"
```

## Python API

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

## Command line

```bash
aidac version
aidac scan "DROP DATABASE production;"
aidac postgres scan --min-risk 0.5
aidac postgres watch --interval 5 --min-severity high
```

## Alert lifecycle

AI-DAC assigns deterministic alert identifiers, deduplicates repeated matching database
events, and maintains the states `new`, `acknowledged`, and `resolved`.

```bash
aidac alerts list
aidac alerts list --status new --json
aidac alerts show alrt_IDENTIFIER
aidac alerts ack alrt_IDENTIFIER --actor analyst --note "Review started"
aidac alerts resolve alrt_IDENTIFIER --actor analyst --note "Incident closed"
aidac alerts prune --older-than-days 90 --status resolved --yes
```

The alert log remains compatible with JSONL records created by AI-DAC 0.6.0 and later.
Files created by AI-DAC use private permissions where the operating system supports POSIX
permissions.

## Authenticated REST API

Create a random bearer token and start the API on the local machine:

```bash
export AIDAC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
aidac api serve
```

The interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.
Alert endpoints require the header `Authorization: Bearer <token>`.

```bash
curl -H "Authorization: Bearer $AIDAC_API_TOKEN" \
  http://127.0.0.1:8000/api/v1/alerts
```

Available routes include:

- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/summary`
- `GET /api/v1/alerts/{alert_id}`
- `POST /api/v1/alerts/{alert_id}/ack`
- `POST /api/v1/alerts/{alert_id}/resolve`

## Web dashboard

AI-DAC 0.9.0 adds a server-rendered dashboard with:

- current alert totals and lifecycle statistics;
- severity-distribution visualization;
- status, severity, risk, text, and result-limit filters;
- alert detail pages;
- acknowledgement and resolution forms;
- configurable automatic refresh;
- audit logging for dashboard lifecycle actions.

The dashboard uses a separate random token. The REST API bearer token is not placed in
browser JavaScript, browser storage, page URLs, or HTML. After sign-in, the browser receives
an opaque, signed, time-limited, `HttpOnly` session cookie. Mutation forms use CSRF tokens.

Create both tokens and start the local API with the dashboard enabled:

```bash
export AIDAC_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AIDAC_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
aidac api serve --dashboard
```

Open:

```text
http://127.0.0.1:8000/dashboard
```

The default dashboard session duration is eight hours. It can be changed from 5 to 1440
minutes:

```bash
aidac api serve --dashboard --dashboard-session-minutes 120
```

The dashboard is disabled unless `--dashboard` is supplied. The listener remains
loopback-only by default. Binding to a non-loopback address requires explicit
`--allow-remote` together with a TLS certificate and private key. CORS is not enabled by
default.

## Safety

AI-DAC operates in observation mode. It does not automatically modify or block database
activity. Passwords, complete DSNs, API tokens, dashboard tokens, and webhook secrets should
be supplied through environment variables rather than stored in the repository or TOML
configuration.

## License

Apache License 2.0.
