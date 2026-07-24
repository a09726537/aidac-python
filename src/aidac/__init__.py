"""Public interface for the AI-DAC Python package."""

from aidac.alert_store import AlertStatus, AlertStoreError
from aidac.connectors import (
    PostgreSQLAuditConfig,
    PostgreSQLAuditConnector,
    PostgreSQLConnectorError,
)
from aidac.engine import AIDAC
from aidac.incidents import IncidentError, IncidentStatus, correlate_alerts
from aidac.learning import TripleLoopAssessment, assess_incident
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
    "IncidentError",
    "IncidentStatus",
    "DetectionResult",
    "PostgreSQLAuditConfig",
    "PostgreSQLAuditConnector",
    "PostgreSQLConnectorError",
    "SecurityDecision",
    "Severity",
    "TripleLoopAssessment",
    "assess_incident",
    "correlate_alerts",
]


__version__ = "1.3.0"
