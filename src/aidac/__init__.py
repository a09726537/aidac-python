"""Public interface for the AI-DAC Python package."""

from aidac.alert_store import AlertStatus, AlertStoreError
from aidac.connectors import (
    PostgreSQLAuditConfig,
    PostgreSQLAuditConnector,
    PostgreSQLConnectorError,
)
from aidac.engine import AIDAC
from aidac.models import (
    DatabaseEvent,
    DetectionResult,
    SecurityDecision,
    Severity,
)

__all__ = [
    "AIDAC",
    "AlertStatus",
    "AlertStoreError",
    "DatabaseEvent",
    "DetectionResult",
    "PostgreSQLAuditConfig",
    "PostgreSQLAuditConnector",
    "PostgreSQLConnectorError",
    "SecurityDecision",
    "Severity",
]


__version__ = "1.2.0"
