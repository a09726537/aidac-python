"""Core data models for the AI-DAC framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4


class Severity(StrEnum):
    """AI-DAC security severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class DatabaseEvent:
    """Normalized database-security event."""

    query: str
    username: str
    database: str
    source_system: str
    client_ip: str | None = None
    duration_ms: float | None = None
    rows_affected: int | None = None
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Normalize and validate event data."""

        self.query = self.query.strip()
        self.username = self.username.strip()

        self.database = self.database.strip()

        self.source_system = self.source_system.strip().lower()

        if not self.query:
            raise ValueError("The SQL query cannot be empty.")

        if not self.username:
            raise ValueError("The username cannot be empty.")

        if not self.database:
            raise ValueError("The database name cannot be empty.")

        if not self.source_system:
            raise ValueError("The source system cannot be empty.")

        if self.duration_ms is not None and self.duration_ms < 0:
            raise ValueError("duration_ms cannot be negative.")

        if self.rows_affected is not None and self.rows_affected < 0:
            raise ValueError("rows_affected cannot be negative.")


@dataclass(slots=True)
class DetectionResult:
    """Result returned by an AI-DAC detector."""

    risk_score: float

    severity: Severity

    classification: str

    indicators: list[str]

    detector_name: str

    detector_version: str

    def __post_init__(self) -> None:
        """Validate the detector result."""

        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0.")

    @property
    def is_anomalous(self) -> bool:
        """Return True when the event requires attention."""

        return self.risk_score >= 0.50


@dataclass(slots=True)
class SecurityDecision:
    """Final security decision produced by AI-DAC."""

    event_id: str

    risk_score: float

    severity: Severity

    classification: str

    indicators: list[str]

    explanation: str

    recommended_action: str

    automatic_action: str | None = None

    def __post_init__(self) -> None:
        """Validate the final security decision."""

        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0.")
