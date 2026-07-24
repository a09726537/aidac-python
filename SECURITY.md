# Security guidance

AI-DAC must be deployed with least-privilege database credentials and strong random tokens.
Do not commit passwords, DSNs, API tokens, dashboard tokens, TLS private keys, or webhook
secrets to the repository or `config.toml`.

For remote API access:

- use `--allow-remote` only with TLS certificate and key files;
- create separate viewer, analyst, and administrator tokens;
- keep the default rate limit unless a documented capacity test supports a change;
- protect SQLite files, audit logs, structured logs, environment files, and backups with operating-system permissions;
- use a dedicated PostgreSQL lifecycle-store role rather than the read-only collector role;
- grant the lifecycle-store role access only to the selected AI-DAC schema;
- keep `AIDAC_ALERT_STORE_DSN` only in a private environment or secret manager;
- protect `/metrics` with a viewer bearer token and avoid public exposure;
- keep component-health target names low-cardinality and never embed credentials in target URLs;
- restrict `AIDAC_COMPONENTS_FILE` and generated operations assets to trusted administrators;
- replace generated Alertmanager placeholders before deployment and store webhook secrets outside YAML;
- send OTLP only to trusted collectors over an authenticated or segmented transport;
- run `aidac doctor` and `aidac audit verify` regularly;
- test backup restoration before relying on it operationally.

AI-DAC is an observation and decision-support tool. It does not replace database access
controls, backups, network segmentation, patching, or human incident-response procedures.

## Incident correlation and learning safeguards

AI-DAC 1.3 incident correlation operates only on current alert snapshots and uses bounded,
deterministic grouping rules. Incident notification payloads intentionally omit SQL text, alert
identifiers, credentials, bearer tokens, webhook secrets, and database connection strings.
Triple-Loop Learning output is advisory and explainable; high-impact response or policy changes
remain subject to human approval and organizational governance.
