# AI-DAC Python Library

AI-DAC is an adaptive and explainable database cybersecurity framework for detecting potentially dangerous SQL activity.

## Features

- SQL security-event normalization
- Rule-based anomaly detection
- Risk scoring and severity classification
- Human-readable explanations
- Safe observation-only response recommendations
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
```

AI-DAC version 0.1.x operates in observation mode and does not automatically modify or block database activity.

## License

Apache License 2.0.
