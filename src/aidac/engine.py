"""Main security-analysis engine for AI-DAC."""

from __future__ import annotations

from aidac.detector import RuleBasedDetector
from aidac.models import DatabaseEvent, DetectionResult, SecurityDecision, Severity


class AIDAC:
    """Main public security-analysis engine."""

    def __init__(self, detector: RuleBasedDetector | None = None) -> None:
        """
        Initialize the AI-DAC engine.

        When no detector is provided, AI-DAC uses the default
        rule-based SQL detector.
        """

        self.detector = detector or RuleBasedDetector()

    def analyze(self, event: DatabaseEvent) -> SecurityDecision:
        """
        Analyse one normalized database event.

        AI-DAC currently works in observation mode. It recommends
        security actions but does not automatically modify the database.
        """

        detection = self.detector.predict(event)

        return SecurityDecision(
            event_id=event.event_id,
            risk_score=detection.risk_score,
            severity=detection.severity,
            classification=detection.classification,
            indicators=detection.indicators,
            explanation=self._create_explanation(detection),
            recommended_action=self._recommend_action(detection.severity),
            automatic_action=None,
        )

    @staticmethod
    def _create_explanation(detection: DetectionResult) -> str:
        """Create a human-readable explanation of the detection result."""

        if not detection.indicators:
            return (
                "No suspicious SQL pattern was identified by the "
                f"{detection.detector_name} detector."
            )

        indicator_text = " ".join(detection.indicators)

        return f"The event received a risk score of {detection.risk_score:.2f}. {indicator_text}"

    @staticmethod
    def _recommend_action(severity: Severity) -> str:
        """Return a safe response recommendation for the severity level."""

        recommendations = {
            Severity.INFO: ("No immediate action is required. Continue normal monitoring."),
            Severity.LOW: ("Record the event and continue enhanced monitoring."),
            Severity.MEDIUM: ("Create a security alert and request analyst review."),
            Severity.HIGH: (
                "Create a high-priority alert, preserve the available "
                "evidence and request immediate analyst review."
            ),
            Severity.CRITICAL: (
                "Create a critical alert, preserve the available evidence "
                "and initiate the human-controlled incident-response procedure."
            ),
        }

        return recommendations[severity]
