"""Deterministic Triple-Loop Learning assessments for AI-DAC incidents."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from aidac.models import Severity

_SEVERITY_WEIGHT = {
    Severity.INFO.value: 0.05,
    Severity.LOW.value: 0.15,
    Severity.MEDIUM.value: 0.35,
    Severity.HIGH.value: 0.65,
    Severity.CRITICAL.value: 0.90,
}


@dataclass(frozen=True, slots=True)
class TripleLoopAssessment:
    """Explainable three-loop assessment derived from an incident snapshot."""

    loop1_detection: dict[str, Any]
    loop2_adaptation: dict[str, Any]
    loop3_reflection: dict[str, Any]
    learning_score: float
    escalation_required: bool
    human_approval_required: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        return asdict(self)


def assess_incident(incident: dict[str, Any]) -> TripleLoopAssessment:
    """Create a bounded and explainable Triple-Loop Learning assessment."""

    severity = str(incident.get("severity", Severity.INFO.value)).casefold()
    risk_score = _bounded_float(incident.get("risk_score"))
    alert_count = _positive_integer(incident.get("alert_count"), 1)
    occurrence_count = _positive_integer(incident.get("occurrence_count"), alert_count)
    classifications = [
        str(value) for value in incident.get("classifications", []) if str(value).strip()
    ]

    loop1 = {
        "objective": "detect_and_explain",
        "signal_strength": round(risk_score, 4),
        "evidence_alerts": alert_count,
        "observed_occurrences": occurrence_count,
        "classifications": classifications,
    }

    if severity in {Severity.CRITICAL.value, Severity.HIGH.value}:
        response_mode = "immediate_human_review"
        response_priority = "urgent"
    elif occurrence_count >= 3:
        response_mode = "enhanced_monitoring_and_control_tuning"
        response_priority = "elevated"
    else:
        response_mode = "standard_analyst_review"
        response_priority = "normal"

    loop2 = {
        "objective": "adapt_response",
        "response_mode": response_mode,
        "response_priority": response_priority,
        "preserve_evidence": severity
        in {Severity.MEDIUM.value, Severity.HIGH.value, Severity.CRITICAL.value},
        "recurrence_detected": occurrence_count > alert_count or occurrence_count >= 3,
    }

    if severity == Severity.CRITICAL.value or occurrence_count >= 5:
        governance_action = "policy_and_control_review"
    elif severity == Severity.HIGH.value or occurrence_count >= 3:
        governance_action = "control_effectiveness_review"
    else:
        governance_action = "retain_current_policy"

    loop3 = {
        "objective": "reflect_on_governance",
        "governance_action": governance_action,
        "requires_documented_rationale": governance_action != "retain_current_policy",
        "feedback_candidate": occurrence_count >= 3,
    }

    recurrence_factor = min(1.0, occurrence_count / 10.0)
    diversity_factor = min(1.0, len(set(classifications)) / 4.0)
    severity_factor = _SEVERITY_WEIGHT.get(severity, 0.05)
    learning_score = min(
        1.0,
        (0.45 * risk_score)
        + (0.30 * severity_factor)
        + (0.15 * recurrence_factor)
        + (0.10 * diversity_factor),
    )
    escalation_required = (
        severity
        in {
            Severity.HIGH.value,
            Severity.CRITICAL.value,
        }
        or occurrence_count >= 3
    )
    human_approval_required = severity in {
        Severity.HIGH.value,
        Severity.CRITICAL.value,
    }

    return TripleLoopAssessment(
        loop1_detection=loop1,
        loop2_adaptation=loop2,
        loop3_reflection=loop3,
        learning_score=round(learning_score, 4),
        escalation_required=escalation_required,
        human_approval_required=human_approval_required,
    )


def _bounded_float(value: object) -> float:
    if not isinstance(value, (str, int, float)):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, number))


def _positive_integer(value: object, default: int) -> int:
    if not isinstance(value, (str, int, float)):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default
