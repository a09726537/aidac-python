# AI-DAC Python Library

AI-DAC is an adaptive and explainable database-cybersecurity framework for detecting and managing potentially dangerous SQL activity.

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
- Python API and command-line interface

## Installation

```bash
python -m pip install aidac-sec
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

AI-DAC 0.7.0 assigns deterministic alert identifiers, deduplicates repeated matching database events, and maintains the states `new`, `acknowledged`, and `resolved`.

```bash
aidac alerts list
aidac alerts list --status new --json
aidac alerts show alrt_IDENTIFIER
aidac alerts ack alrt_IDENTIFIER --actor analyst --note "Review started"
aidac alerts resolve alrt_IDENTIFIER --actor analyst --note "Incident closed"
aidac alerts prune --older-than-days 90 --status resolved --yes
```

The alert log remains compatible with JSONL records created by AI-DAC 0.6.0. Files created by AI-DAC use private permissions where the operating system supports POSIX permissions.

## Safety

AI-DAC operates in observation mode. It does not automatically modify or block database activity. Passwords, complete DSNs, and webhook secrets should be provided through environment variables rather than stored in the configuration file.

## License

Apache License 2.0.
