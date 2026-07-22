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
- run `aidac doctor` and `aidac audit verify` regularly;
- test backup restoration before relying on it operationally.

AI-DAC is an observation and decision-support tool. It does not replace database access
controls, backups, network segmentation, patching, or human incident-response procedures.
