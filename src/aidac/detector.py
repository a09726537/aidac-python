"""Rule-based SQL security detector for AI-DAC."""

from __future__ import annotations

import re
from dataclasses import dataclass

from aidac.models import DatabaseEvent, DetectionResult, Severity


@dataclass(frozen=True, slots=True)
class RiskRule:
    """Definition of a weighted SQL security rule."""

    name: str
    pattern: re.Pattern[str]
    weight: float
    description: str


class RuleBasedDetector:
    """Detect potentially dangerous SQL activity using weighted rules."""

    name = "aidac-rule-detector"
    version = "0.1.0"

    def __init__(self) -> None:
        """Initialize the SQL security rules."""

        self._rules: tuple[RiskRule, ...] = (
            RiskRule(
                name="drop-database",
                pattern=re.compile(
                    r"\bDROP\s+DATABASE\b",
                    re.IGNORECASE,
                ),
                weight=0.95,
                description="Database deletion statement detected.",
            ),
            RiskRule(
                name="drop-table",
                pattern=re.compile(
                    r"\bDROP\s+TABLE\b",
                    re.IGNORECASE,
                ),
                weight=0.80,
                description="Table deletion statement detected.",
            ),
            RiskRule(
                name="truncate-table",
                pattern=re.compile(
                    r"\bTRUNCATE\s+(?:TABLE\s+)?",
                    re.IGNORECASE,
                ),
                weight=0.75,
                description="Table truncation statement detected.",
            ),
            RiskRule(
                name="delete-without-where",
                pattern=re.compile(
                    r"^\s*DELETE\s+FROM\s+[\w.\"`\[\]]+\s*;?\s*$",
                    re.IGNORECASE,
                ),
                weight=0.85,
                description="DELETE statement without a WHERE clause detected.",
            ),
            RiskRule(
                name="grant-privileges",
                pattern=re.compile(
                    r"\bGRANT\s+.+\s+TO\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                weight=0.65,
                description="Database privilege grant operation detected.",
            ),
            RiskRule(
                name="revoke-privileges",
                pattern=re.compile(
                    r"\bREVOKE\s+.+\s+FROM\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                weight=0.55,
                description="Database privilege revocation operation detected.",
            ),
            RiskRule(
                name="union-select",
                pattern=re.compile(
                    r"\bUNION\s+(?:ALL\s+)?SELECT\b",
                    re.IGNORECASE,
                ),
                weight=0.55,
                description="Potential UNION-based SQL injection pattern detected.",
            ),
            RiskRule(
                name="always-true-condition",
                pattern=re.compile(
                    r"\bOR\s+(['\"]?)(\w+)\1\s*=\s*(['\"]?)\2\3",
                    re.IGNORECASE,
                ),
                weight=0.60,
                description="Potential always-true SQL condition detected.",
            ),
            RiskRule(
                name="sql-comment",
                pattern=re.compile(
                    r"(--|/\*)",
                    re.IGNORECASE,
                ),
                weight=0.20,
                description="SQL comment syntax detected.",
            ),
            RiskRule(
                name="xp-cmdshell",
                pattern=re.compile(
                    r"\bxp_cmdshell\b",
                    re.IGNORECASE,
                ),
                weight=0.95,
                description="Operating-system command execution detected.",
            ),
            RiskRule(
                name="load-file",
                pattern=re.compile(
                    r"\bLOAD_FILE\s*\(",
                    re.IGNORECASE,
                ),
                weight=0.75,
                description="Database file-reading function detected.",
            ),
            RiskRule(
                name="sleep-function",
                pattern=re.compile(
                    r"\b(?:SLEEP|PG_SLEEP|WAITFOR)\b",
                    re.IGNORECASE,
                ),
                weight=0.55,
                description="Potential time-based SQL injection function detected.",
            ),
        )

    def predict(self, event: DatabaseEvent) -> DetectionResult:
        """Analyse one database event and return its detection result."""

        indicators: list[str] = []
        weights: list[float] = []

        for rule in self._rules:
            if rule.pattern.search(event.query):
                indicators.append(rule.description)
                weights.append(rule.weight)

        risk_score = self._combine_weights(weights)
        severity = self._determine_severity(risk_score)

        classification = "suspicious_sql_activity" if indicators else "normal_sql_activity"

        return DetectionResult(
            risk_score=risk_score,
            severity=severity,
            classification=classification,
            indicators=indicators,
            detector_name=self.name,
            detector_version=self.version,
        )

    @staticmethod
    def _combine_weights(weights: list[float]) -> float:
        """
        Combine several risk weights.

        The formula allows the strongest rule to dominate while additional
        matches progressively increase the final score.
        """

        if not weights:
            return 0.0

        remaining_safety = 1.0

        for weight in weights:
            normalized_weight = min(max(weight, 0.0), 1.0)
            remaining_safety *= 1.0 - normalized_weight

        risk_score = 1.0 - remaining_safety

        return round(min(risk_score, 1.0), 4)

    @staticmethod
    def _determine_severity(risk_score: float) -> Severity:
        """Convert a numerical risk score into a severity level."""

        if risk_score >= 0.90:
            return Severity.CRITICAL

        if risk_score >= 0.75:
            return Severity.HIGH

        if risk_score >= 0.50:
            return Severity.MEDIUM

        if risk_score > 0.0:
            return Severity.LOW

        return Severity.INFO
