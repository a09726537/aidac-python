# Changelog

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
