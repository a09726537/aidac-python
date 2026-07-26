# AI-DAC Python Library

> **Artificial Intelligence–Driven Anomaly Detection and Control**
>
> **Reference Software Implementation for Lifecycle-Aware Database Cybersecurity**

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)
![Status](https://img.shields.io/badge/Status-Research-orange.svg)
![Stage](https://img.shields.io/badge/Stage-Preparatory%20Software-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)

</p>

---

## Table of Contents

- [Overview](#overview)
- [Research Status](#research-status)
- [Version 1.3.0](#version-130)
- [Main Capabilities](#main-capabilities)
- [Installation](#installation)
- [Basic Analysis](#basic-analysis)
- [Alert Storage](#alert-storage)
- [Alert Lifecycle and Search](#alert-lifecycle-and-search)
- [Incident Correlation and Triple-Loop Learning](#incident-correlation-and-triple-loop-learning)
- [Backup and Restore](#backup-and-restore)
- [Tamper-Evident Audit Log](#tamper-evident-audit-log)
- [Role-Aware REST API](#role-aware-rest-api)
- [Prometheus Metrics](#prometheus-metrics)
- [Structured Logging](#structured-logging)
- [User-Level systemd Deployment](#user-level-systemd-deployment)
- [Operations Bundle](#operations-bundle)
- [Distributed Component Health](#distributed-component-health)
- [OpenTelemetry Trace Export](#opentelemetry-trace-export)
- [Web Dashboard](#web-dashboard)
- [Production Configuration](#production-configuration)
- [Diagnostics](#diagnostics)
- [Network Safety](#network-safety)
- [Research Context](#research-context)
- [Citation](#citation)
- [Contributing](#contributing)
- [Reproducibility Policy](#reproducibility-policy)
- [License](#license)
- [Acknowledgements](#acknowledgements)
- [Contact](#contact)



## Overview

AI-DAC (**Artificial Intelligence–Driven Anomaly Detection and Control**) is an adaptive and explainable database cybersecurity framework for detecting, monitoring, correlating, storing, and managing potentially dangerous SQL activity in relational database environments.

The project combines anomaly detection, deterministic incident correlation, explainable decision support, operational monitoring, and governance-aware assessment within a modular Python software framework intended for cybersecurity research and engineering.

AI-DAC is being developed as the **reference software implementation** supporting the doctoral research project:

> **Triple-Loop Learning for Lifecycle-Aware Database Cybersecurity: A Recursive Learning Framework**

The software repository and the doctoral dissertation are complementary but distinct research outputs.

- The **repository** documents the evolving software implementation, APIs, operational tooling, testing infrastructure, and engineering components.
- The **doctoral dissertation** presents the scientific framework, research methodology, theoretical contributions, experimental design, and confirmatory evaluation.

---

## Research Status

**Current status:** **Preparatory Research Software**

This repository contains the actively developed implementation of AI-DAC, including:

- SQL anomaly detection
- Database monitoring
- Incident correlation
- Triple-Loop Learning assessments
- REST API
- Operational dashboard
- Observability
- OpenTelemetry integration
- Prometheus metrics
- Alert lifecycle management
- Configuration management
- Python package
- Command-line interface

This repository **does not** constitute the protocol-frozen doctoral evaluation package.

Future confirmatory evaluation artifacts—including benchmark manifests, protocol documentation, dataset provenance, statistical analyses, reproducibility records, and archived evaluation environments—will be released separately after the protocol-freeze stage of the doctoral research.

---

## Version 1.3.0

Version **1.3.0** introduces:

- deterministic incident correlation;
- explainable Triple-Loop Learning assessments;
- incident-oriented API and CLI workflows;
- signed incident notifications;
- distributed operational observability;
- hardened monitoring infrastructure; and
- improved operational diagnostics,

## Main Capabilities

AI-DAC currently provides:

- SQL event normalization, anomaly detection, risk scoring, and explainable assessments
- Read-only PostgreSQL audit collection and continuous monitoring
- SQLite-based alert storage with schema migrations and transactional lifecycle updates
- Optional PostgreSQL lifecycle storage configured securely through environment variables
- Import compatibility for legacy JSONL alert logs
- Alert deduplication with `new`, `acknowledged`, and `resolved` lifecycle states
- Tamper-evident JSONL audit logging with sequence numbers and SHA-256 hash chaining
- Role-aware REST API access using `viewer`, `analyst`, and `admin` tokens
- Pagination, filtering, search, and per-token API rate limiting
- Authenticated server-rendered security-operations dashboard
- Consistent alert-store backup and validated restore commands
- Prometheus-compatible metrics and structured JSON application logging
- Hardened user-level `systemd` service generation and management
- Generated Prometheus, Alertmanager, Grafana, and OpenTelemetry Collector assets
- Distributed component-health probes with bounded Prometheus labels
- Optional OTLP/HTTP request tracing through OpenTelemetry
- Signed operational webhook notifications for degraded component health
- Deterministic correlation of related alerts within bounded time windows
- Explainable Loop 1, Loop 2, and Loop 3 incident assessments
- Signed incident notifications that exclude SQL text, tokens, credentials, and DSNs
- Incident-oriented API, CLI, metrics, Prometheus rules, and Grafana panels
- Local diagnostics and production-configuration commands

---

## Installation

### Install the Core Package

```bash
python -m pip install aidac-sec
```

### Install REST API and Dashboard Support

```bash
python -m pip install "aidac-sec[api]"
```

### Install OpenTelemetry Export Support

```bash
python -m pip install "aidac-sec[otel]"
```

A virtual environment is recommended:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install "aidac-sec[api,otel]"
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install "aidac-sec[api,otel]"
```

---

## Basic Analysis

AI-DAC can be used directly from Python to analyze a database event.

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

The resulting decision object provides the calculated risk score, severity classification, and recommended response.

### Basic CLI Usage

```bash
aidac version
aidac scan "DROP DATABASE production;"
aidac postgres scan --min-risk 0.5
aidac postgres watch --interval 5 --min-severity high
```

The PostgreSQL commands operate in monitoring and analysis mode. They do not automatically block, terminate, quarantine, or modify database activity.

---

## Alert Storage

AI-DAC stores alert lifecycle information in a local SQLite database by default and can optionally use PostgreSQL for lifecycle persistence.

### SQLite Default

The default alert store is:

```text
~/.local/state/aidac/alerts.db
```

Initialize or inspect the store:

```bash
aidac storage init
aidac storage info
aidac storage info --json
```

SQLite is suitable for local development, single-user analysis, laboratory workflows, and lightweight deployments.

---

### Upgrade from AI-DAC 0.6–0.9

Import a legacy JSONL lifecycle log into the current storage backend:

```bash
aidac storage migrate-jsonl \
  --source ~/.local/state/aidac/alerts.jsonl \
  --destination ~/.local/state/aidac/alerts.db
```

The legacy JSONL backend remains supported when a path ending in `.jsonl` is explicitly supplied.

---

### Optional PostgreSQL Lifecycle Store

For multi-process or service-oriented deployments, AI-DAC can use a dedicated PostgreSQL lifecycle store.

Configure the connection outside the repository:

```bash
export AIDAC_ALERT_STORE_DSN="postgresql://aidac_app:REDACTED@127.0.0.1:5432/aidac_pgsql"
export AIDAC_ALERT_STORE_SCHEMA="aidac"

aidac storage init
aidac storage info
```

Use a dedicated least-privilege PostgreSQL role for lifecycle data.

The audit collector account, such as `aidac_reader`, should remain read-only and should not be reused as the lifecycle-store writer account.

When `AIDAC_ALERT_STORE_DSN` is configured, the following components use PostgreSQL:

- alert lifecycle commands;
- REST API;
- dashboard;
- monitoring process;
- backup and restore;
- diagnostic commands.

The DSN is not returned through API or diagnostic output.

`AIDAC_ALERT_STORE_SCHEMA` defaults to:

```text
aidac
```

Import a previous JSONL lifecycle log into the selected PostgreSQL store:

```bash
aidac storage migrate-jsonl \
  --source ~/.local/state/aidac/alerts.jsonl \
  --destination ~/.local/state/aidac/alerts.db
```

For PostgreSQL lifecycle storage, AI-DAC creates private application-level JSON backup snapshots that can be restored using the standard restore command.

---

## Alert Lifecycle and Search

AI-DAC supports alert inspection, filtering, acknowledgement, resolution, and controlled retention.

```bash
aidac alerts list
aidac alerts list --status new --severity critical --min-risk 0.8
aidac alerts list --search production --limit 25 --offset 0 --json
aidac alerts show alrt_IDENTIFIER
aidac alerts ack alrt_IDENTIFIER \
  --actor analyst \
  --note "Review started"
aidac alerts resolve alrt_IDENTIFIER \
  --actor analyst \
  --note "Incident closed"
aidac alerts prune \
  --older-than-days 90 \
  --status resolved \
  --yes
```

Alert lifecycle states include:

- `new`
- `acknowledged`
- `resolved`

Lifecycle transitions are recorded transactionally and remain auditable.

---

## Incident Correlation and Triple-Loop Learning

AI-DAC correlates current alert snapshots using:

- source system;
- database;
- actor identity; and
- a bounded correlation window.

Correlation is deterministic.

It does not silently execute response actions or modify the protected database.

### Incident Commands

```bash
aidac incidents list
aidac incidents list --status open --min-risk 0.8 --json
aidac incidents show inc_IDENTIFIER
aidac incidents correlate \
  --output ~/.local/state/aidac/incidents.json
```

Each correlated incident contains an explainable Triple-Loop Learning assessment.

### Loop 1 — Detection and Explanation

Loop 1 evaluates the immediate operational evidence, including:

- evidence count;
- signal strength;
- recurrence;
- observed classifications;
- alert severity;
- risk indicators.

### Loop 2 — Response Adaptation

Loop 2 evaluates the response strategy, including:

- response priority;
- response mode;
- evidence preservation;
- recurrence handling;
- escalation requirements.

### Loop 3 — Governance Reflection

Loop 3 evaluates the broader governance implications, including:

- control-effectiveness review;
- policy review;
- documented rationale;
- feedback candidacy;
- long-term improvement considerations.

High-severity and critical incidents require human-controlled review.

AI-DAC does not automatically:

- block database activity;
- terminate sessions;
- quarantine users;
- modify database objects;
- execute destructive response actions.

---

### Signed Incident Notifications

AI-DAC can send signed incident summaries without exposing SQL statements, credentials, tokens, or database connection strings.

Configure a webhook secret:

```bash
export AIDAC_INCIDENT_WEBHOOK_SECRET="replace-with-random-secret"
```

Send incident notifications:

```bash
aidac incidents notify \
  --webhook-url https://operations.example/aidac-incidents \
  --min-severity high
```

The default incident-correlation window is 30 minutes.

Configure it globally:

```bash
export AIDAC_INCIDENT_WINDOW_MINUTES=30
```

Alternatively, pass the correlation window directly to the relevant CLI command:

```bash
aidac incidents correlate --window-minutes 30
```

---

## Backup and Restore

AI-DAC provides consistent backup and restore operations for alert lifecycle data.

### Create a Backup

```bash
aidac storage backup
```

To specify an explicit output location:

```bash
aidac storage backup \
    --output ~/Backups/aidac-alerts.db
```

Backups preserve alert lifecycle information and metadata required for operational continuity.

---

### Restore a Backup

After validating the backup, restore it using:

```bash
aidac storage restore ~/Backups/aidac-alerts.db --yes
```

Restore operations require explicit confirmation to help prevent accidental data loss.

---

## Tamper-Evident Audit Log

AI-DAC maintains a tamper-evident audit log designed to support traceability and integrity verification.

Each audit record contains:

- a monotonically increasing sequence number;
- the hash of the previous record;
- its own SHA-256 record hash.

This chained structure allows integrity verification without modifying existing records.

Legacy audit records remain readable, while newly generated records continue the integrity chain.

Verify the audit log:

```bash
aidac audit verify
```

JSON output:

```bash
aidac audit verify --json
```

---

## Role-Aware REST API

AI-DAC includes a REST API supporting authenticated access for different operational roles.

### Create API Tokens

Generate independent tokens for each role.

```bash
export AIDAC_API_VIEWER_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

export AIDAC_API_ANALYST_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

export AIDAC_API_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

The legacy variable

```text
AIDAC_API_TOKEN
```

continues to function as an administrator token for backward compatibility.

---

### Start the API

```bash
aidac api serve --rate-limit 120
```

---

### Access Roles

| Role | Capabilities |
|------|--------------|
| **viewer** | View alerts, incidents, summaries, dashboards, and metrics |
| **analyst** | Viewer permissions plus acknowledge and resolve alerts |
| **admin** | Analyst permissions plus storage management and audit diagnostics |

---

### Common REST Endpoints

Health

```text
GET /health/live
GET /health/ready
```

Alerts

```text
GET /api/v1/alerts
GET /api/v1/alerts/summary
GET /api/v1/alerts/{alert_id}

POST /api/v1/alerts/{alert_id}/ack
POST /api/v1/alerts/{alert_id}/resolve
```

Incidents

```text
GET /api/v1/incidents
GET /api/v1/incidents/summary
GET /api/v1/incidents/{incident_id}
GET /api/v1/incidents/{incident_id}/assessment
```

System

```text
GET /api/v1/system/storage
GET /api/v1/system/audit/verify
GET /api/v1/system/components
```

Metrics

```text
GET /metrics
```

A valid Viewer token is required.

---

### OpenAPI Documentation

When the API is running locally, interactive OpenAPI documentation is available at

```text
http://127.0.0.1:8000/docs
```

---

## Prometheus Metrics

AI-DAC exports Prometheus-compatible metrics for operational monitoring.

The authenticated `/metrics` endpoint exposes:

- HTTP request counters;
- request duration statistics;
- alert counts;
- correlated incident counts;
- recurrence information;
- storage availability;
- component health.

Prometheus may authenticate using the Viewer token.

Example:

```bash
curl \
  -H "Authorization: Bearer $AIDAC_API_VIEWER_TOKEN" \
  http://127.0.0.1:8000/metrics
```

To preserve operational privacy, metric labels never include:

- SQL statements;
- alert identifiers;
- usernames;
- DSNs;
- authentication tokens.

---

## Structured Logging

AI-DAC records application events as structured JSON Lines logs.

Example:

```bash
aidac api serve \
    --log-format json \
    --log-file ~/.local/state/aidac/service.jsonl
```

The log file is created with file mode:

```text
600
```

HTTP request records include:

- method;
- normalized path;
- status code;
- request duration.

Sensitive information such as bearer tokens, SQL statements, and dynamic alert identifiers is intentionally excluded from structured logs.

---

## User-Level systemd Deployment

Generate a hardened user service:

```bash
aidac service install
```

This creates:

- a hardened `systemd` unit;
- a private environment template.

Configure:

```text
~/.config/aidac/aidac.env
```

Then start the service:

```bash
systemctl --user enable --now aidac-api.service

aidac service status

aidac service logs --lines 100
```

The generated service uses security hardening including:

- loopback-only binding;
- `NoNewPrivileges`;
- `ProtectSystem=strict`;
- `ProtectHome=read-only`;
- private temporary directories;
- restart-on-failure;
- restrictive file permissions (`UMask=0077`).

---

## Operations Bundle

AI-DAC can generate a complete observability bundle without embedding secrets.

Create the bundle:

```bash
aidac ops init \
    --output-dir ./aidac-operations \
    --aidac-url http://127.0.0.1:8000 \
    --viewer-token-file ~/.config/aidac/viewer.token
```

Validate the generated assets:

```bash
aidac ops validate \
    --directory ./aidac-operations
```

Generated assets include:

- Prometheus configuration;
- Alertmanager configuration;
- Grafana dashboards;
- OpenTelemetry Collector configuration;
- Docker Compose deployment;
- component-health templates.

Viewer tokens are referenced through external files and are never embedded into generated configuration files.

---

## Start the Operations Stack

```bash
cd aidac-operations

chmod 600 grafana-admin-password

export AIDAC_UID="$(id -u)"
export AIDAC_GID="$(id -g)"

docker compose \
    -f docker-compose.ops.yml up -d
```

---

## Distributed Component Health

AI-DAC continuously monitors operational components through configurable health probes.

Example configuration:

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

Execute a health check:

```bash
aidac ops health \
    --config ~/.config/aidac/components.toml \
    --report ~/.local/state/aidac/component-health.json
```

To make both the REST API and Prometheus metrics use the same component list:

```bash
export AIDAC_COMPONENTS_FILE=~/.config/aidac/components.toml
```

When configured, degraded health states may trigger signed webhook notifications while protecting operational secrets.

---

## OpenTelemetry Trace Export

AI-DAC supports distributed tracing using the OpenTelemetry Protocol (OTLP) over HTTP.

Tracing provides end-to-end visibility into API requests while preserving operational privacy.

Dynamic alert identifiers are normalized before becoming span attributes, reducing the exposure of operational details.

### Configure OTLP Export

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces
export OTEL_SERVICE_NAME=aidac-api
```

Start the API:

```bash
aidac api serve
```

If no OTLP endpoint is configured, trace export remains disabled.

For production deployments, traces should be forwarded to an OpenTelemetry Collector before being exported to the organization's approved observability platform.

---

## Web Dashboard

AI-DAC includes an authenticated browser-based security operations dashboard.

### Create a Dashboard Token

```bash
export AIDAC_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Start the dashboard:

```bash
aidac api serve --dashboard
```

Open your browser:

```text
http://127.0.0.1:8000/dashboard
```

The dashboard provides operational visibility into alerts, incidents, system status, and monitoring information.

Security-sensitive API bearer tokens are never stored in:

- browser JavaScript;
- Local Storage;
- session URLs;
- rendered HTML pages.

---

## Production Configuration

Generate a hardened production configuration template.

```bash
aidac config production \
    --path ./aidac.production.toml
```

Display the effective configuration:

```bash
aidac config show --json
```

The generated configuration template includes:

- PostgreSQL collection settings;
- local storage locations;
- API binding configuration;
- rate-limiting settings;
- dashboard session configuration;
- lifecycle-store configuration.

Sensitive information—including passwords, authentication tokens, and database credentials—should remain in environment variables or an approved secrets-management system.

---

## Diagnostics

AI-DAC includes built-in diagnostic tools to verify software integrity and deployment readiness.

Run diagnostics:

```bash
aidac doctor
```

Generate structured diagnostic output:

```bash
aidac doctor --json
```

The diagnostic process verifies:

- configuration parsing;
- storage integrity;
- audit-chain integrity;
- private file permissions;
- API token availability;
- operational configuration.

These diagnostics are intended to simplify troubleshooting while preserving operational security.

---

## Network Safety

The REST API is designed with secure default behavior.

By default:

- the API listens only on the loopback interface;
- remote access is disabled;
- CORS is disabled.

Binding to a non-loopback interface requires:

- `--allow-remote`;
- TLS certificate files;
- TLS private key files.

AI-DAC operates in **observation mode**.

The software does **not** automatically:

- block database sessions;
- terminate client connections;
- modify SQL statements;
- change database objects;
- execute destructive response actions.

Human operators remain responsible for all operational decisions.

---

# Research Context

AI-DAC is the reference software implementation developed in support of the doctoral research project:

> **Triple-Loop Learning for Lifecycle-Aware Database Cybersecurity: A Recursive Learning Framework**

The repository focuses on the engineering implementation of the framework, including software architecture, APIs, operational tooling, and testing infrastructure.

The associated doctoral dissertation presents the scientific contributions, theoretical framework, methodology, experimental design, and confirmatory evaluation.

Although developed together, the software repository and the dissertation serve different purposes and should be cited independently where appropriate.

---
# Citation

When using AI-DAC in academic or technical work, cite this software repository.

## Software Citation

William Kandolo.

**AI-DAC Python Library: Reference Software Implementation for Lifecycle-Aware Database Cybersecurity.**

Version 1.4.0.dev0, 2026.

```text
https://github.com/a09726537/aidac-python
```

### BibTeX

```bibtex
@software{kandolo2026aidacpython,
  author    = {William Kandolo},
  title     = {{AI-DAC Python Library}: Reference Software Implementation for Lifecycle-Aware Database Cybersecurity},
  year      = {2026},
  version   = {1.4.0.dev0},
  url       = {https://github.com/a09726537/aidac-python},
  doi       = {},
  license   = {Apache-2.0}
}
```
# Citation

If AI-DAC contributes to your research, please cite both the software repository and the associated doctoral research where appropriate.

## Software Citation

William Kandolo.

**AI-DAC: Artificial Intelligence–Driven Anomaly Detection and Control.**

GitHub Repository.

```text
https://github.com/a09726537/AI-DAC
```

### BibTeX

```bibtex
@software{kandolo2026aidac,
  author  = {William Kandolo},
  title   = {AI-DAC: Artificial Intelligence--Driven Anomaly Detection and Control},
  year    = {2026},
  url     = {https://github.com/a09726537/AI-DAC},
  license = {Apache-2.0}
}
```

---

# Contributing

Contributions that improve software quality, documentation, testing, portability, maintainability, or reproducibility are welcome.

Recommended workflow:

```text
Fork Repository
       │
       ▼
Create Feature Branch
       │
       ▼
Develop
       │
       ▼
Run Tests
       │
       ▼
Update Documentation
       │
       ▼
Submit Pull Request
```

Please ensure that contributions:

- follow existing coding conventions;
- include documentation updates where appropriate;
- preserve backward compatibility whenever practical;
- include tests for new functionality.

---

# Reproducibility Policy

This repository contains the **reference software implementation** of AI-DAC.

It is intended to support software development, experimentation, and engineering validation.

To preserve scientific integrity, the following research artifacts are maintained separately from the evolving source code:

- protocol documentation;
- benchmark manifests;
- dataset provenance;
- statistical analysis plans;
- evaluation records;
- reproducibility reports;
- execution manifests;
- archived evaluation environments.

A protocol-frozen evaluation release is planned following the confirmatory phase of the associated doctoral research.

That release is expected to document the software version, execution procedures, benchmark configurations, statistical methodology, and evaluation artifacts used for the dissertation.

---

# License

AI-DAC is distributed under the **Apache License 2.0**.

See the `LICENSE` file for the complete license text.

---

# Acknowledgements

The development of AI-DAC has benefited from publicly available research literature, open-source software, and the broader cybersecurity research community.

The author gratefully acknowledges the academic environment supporting the associated doctoral research at the University of Vienna.

---

# Contact

**William Kandolo**

Doctoral Researcher

University of Vienna

GitHub

```text
https://github.com/a09726537/AI-DAC
```

ORCID

```text
https://orcid.org/0009-0007-2373-8509
```


