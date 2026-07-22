# Changelog

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
