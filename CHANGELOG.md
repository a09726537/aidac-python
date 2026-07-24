# Changelog

## 1.3.0

- Added deterministic incident correlation by source system, database, actor identity, and bounded time window.
- Added derived `open`, `investigating`, and `resolved` incident states from alert lifecycle snapshots.
- Added explainable Triple-Loop Learning assessments covering detection, response adaptation, and governance reflection.
- Added `aidac incidents list`, `show`, `correlate`, and `notify` commands.
- Added signed incident notification payloads that exclude SQL text, credentials, tokens, and DSNs.
- Added viewer-authorized incident list, summary, detail, and assessment API endpoints.
- Added incident and recurrence Prometheus gauges with bounded labels and normalized incident API paths.
- Added critical-incident and recurring-incident Prometheus rules plus Grafana incident panels.
- Added `AIDAC_INCIDENT_WINDOW_MINUTES` and incident webhook guidance to the hardened service environment template.
- Preserved alert storage, PostgreSQL collection, API roles, dashboard, audit, observability, and systemd interfaces from AI-DAC 1.2.0.

## 1.2.0

- Added `aidac ops init` and `aidac ops validate` for a secret-free Prometheus, Alertmanager, Grafana, and OpenTelemetry Collector deployment bundle.
- Added Prometheus rules for service availability, alert-store failures, critical alerts, distributed component failures, and API server errors.
- Added a provisioned Grafana security-operations dashboard and Prometheus data source.
- Added `aidac ops health` for bounded distributed HTTP component checks and private JSON reports.
- Added signed operational webhook notifications for degraded component health.
- Added authenticated component-health diagnostics and component gauges in `/metrics`.
- Added optional OpenTelemetry OTLP/HTTP API request tracing through the `otel` extra.
- Extended the systemd environment template for component checks and standard OpenTelemetry variables.
- Preserved PostgreSQL, SQLite, JSONL, API, dashboard, audit, and systemd interfaces from AI-DAC 1.1.0.

## 1.1.0

- Added an optional PostgreSQL alert lifecycle store selected with `AIDAC_ALERT_STORE_DSN`.
- Added PostgreSQL schema migration, lifecycle querying, updates, pruning, import, backup, and restore.
- Added an authenticated Prometheus `/metrics` endpoint with bounded labels.
- Added structured JSON application logging with private log-file permissions.
- Added `aidac service install`, `status`, `logs`, and `remove` for a hardened user systemd service.
- Updated diagnostics for PostgreSQL-managed storage permissions.
- Preserved SQLite and JSONL compatibility and all stable 1.0 interfaces.

## 1.0.0

- Added a transactional SQLite alert store with versioned schema migrations.
- Added JSONL-to-SQLite migration while retaining the legacy JSONL backend.
- Added storage initialization, information, backup, and validated restore commands.
- Added role-aware API authentication for viewer, analyst, and administrator tokens.
- Added API pagination, text search, severity/risk filters, and rate limiting.
- Added tamper-evident audit records with sequence and SHA-256 hash chaining.
- Added audit-chain verification and local installation diagnostics.
- Added a production-oriented configuration template without embedded secrets.
- Preserved the PostgreSQL monitoring, webhook, alert lifecycle, REST API, and dashboard
  functionality introduced in the 0.x releases.
