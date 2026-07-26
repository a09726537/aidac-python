"""Human-controlled adaptive feedback for AI-DAC policy recommendations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FeedbackError(RuntimeError):
    """Raised when analyst feedback or a recommendation is invalid."""


class FeedbackDecision(StrEnum):
    """Supported analyst decisions for a policy recommendation."""

    ACCEPT = "accept"
    REJECT = "reject"
    REVISION_REQUIRED = "revision_required"


class RecommendationStatus(StrEnum):
    """Lifecycle states of a human-controlled policy recommendation."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    REVISION_REQUIRED = "revision_required"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class AnalystFeedback:
    """One documented analyst decision about a policy recommendation."""

    feedback_id: str
    recommendation_id: str
    incident_id: str
    analyst: str
    decision: FeedbackDecision
    rationale: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        return {
            "type": "aidac_analyst_feedback",
            "feedback_id": self.feedback_id,
            "recommendation_id": self.recommendation_id,
            "incident_id": self.incident_id,
            "analyst": self.analyst,
            "decision": self.decision.value,
            "rationale": self.rationale,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class PolicyRecommendation:
    """A policy proposal that can never be applied without human approval."""

    recommendation_id: str
    incident_id: str
    proposed_action: str
    rationale: str
    learning_score: float
    status: RecommendationStatus
    requires_human_approval: bool
    auto_apply: bool
    created_at: datetime
    previous_recommendation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        return {
            "type": "aidac_policy_recommendation",
            "recommendation_id": self.recommendation_id,
            "incident_id": self.incident_id,
            "proposed_action": self.proposed_action,
            "rationale": self.rationale,
            "learning_score": self.learning_score,
            "status": self.status.value,
            "requires_human_approval": self.requires_human_approval,
            "auto_apply": self.auto_apply,
            "created_at": self.created_at.isoformat(),
            "previous_recommendation_id": self.previous_recommendation_id,
        }


class FeedbackStore:
    """In-memory reference store used before persistent adapters are introduced."""

    def __init__(self) -> None:
        self._recommendations: dict[str, PolicyRecommendation] = {}
        self._feedback: dict[str, AnalystFeedback] = {}

    def save_recommendation(self, recommendation: PolicyRecommendation) -> None:
        """Store a recommendation idempotently and reject conflicting identifiers."""

        existing = self._recommendations.get(recommendation.recommendation_id)
        if existing is not None and existing != recommendation:
            raise FeedbackError(
                f"Conflicting recommendation identifier: {recommendation.recommendation_id}"
            )
        self._recommendations[recommendation.recommendation_id] = recommendation

    def get_recommendation(self, recommendation_id: str) -> PolicyRecommendation:
        """Return a recommendation by identifier."""

        normalized_id = _required_text(recommendation_id, "recommendation_id")
        try:
            return self._recommendations[normalized_id]
        except KeyError as error:
            raise FeedbackError(f"Recommendation not found: {normalized_id}") from error

    def list_recommendations(
        self,
        *,
        incident_id: str | None = None,
    ) -> list[PolicyRecommendation]:
        """Return recommendations ordered from newest to oldest."""

        normalized_incident = _optional_text(incident_id)
        recommendations = [
            recommendation
            for recommendation in self._recommendations.values()
            if normalized_incident is None or recommendation.incident_id == normalized_incident
        ]
        return sorted(recommendations, key=lambda item: item.created_at, reverse=True)

    def record_feedback(self, feedback: AnalystFeedback) -> PolicyRecommendation:
        """Record feedback and update recommendation state without applying a policy."""

        if feedback.feedback_id in self._feedback:
            existing = self._feedback[feedback.feedback_id]
            if existing != feedback:
                raise FeedbackError(f"Conflicting feedback identifier: {feedback.feedback_id}")
            return self.get_recommendation(feedback.recommendation_id)

        recommendation = self.get_recommendation(feedback.recommendation_id)
        if recommendation.incident_id != feedback.incident_id:
            raise FeedbackError("Feedback incident does not match its recommendation.")
        if recommendation.status is not RecommendationStatus.PROPOSED:
            raise FeedbackError(
                f"Recommendation already decided: {recommendation.recommendation_id}"
            )

        status_by_decision = {
            FeedbackDecision.ACCEPT: RecommendationStatus.ACCEPTED,
            FeedbackDecision.REJECT: RecommendationStatus.REJECTED,
            FeedbackDecision.REVISION_REQUIRED: RecommendationStatus.REVISION_REQUIRED,
        }
        updated = replace(recommendation, status=status_by_decision[feedback.decision])
        self._recommendations[recommendation.recommendation_id] = updated
        self._feedback[feedback.feedback_id] = feedback
        return updated

    def list_feedback(
        self,
        *,
        incident_id: str | None = None,
        recommendation_id: str | None = None,
    ) -> list[AnalystFeedback]:
        """Return analyst feedback ordered from newest to oldest."""

        normalized_incident = _optional_text(incident_id)
        normalized_recommendation = _optional_text(recommendation_id)
        records = [
            feedback
            for feedback in self._feedback.values()
            if (normalized_incident is None or feedback.incident_id == normalized_incident)
            and (
                normalized_recommendation is None
                or feedback.recommendation_id == normalized_recommendation
            )
        ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)


def build_policy_recommendation(
    incident: dict[str, Any],
    *,
    created_at: datetime | None = None,
    previous_recommendation_id: str | None = None,
) -> PolicyRecommendation:
    """Create a deterministic, non-executing recommendation from an incident."""

    incident_id = _required_text(incident.get("incident_id"), "incident_id")
    assessment = incident.get("triple_loop", {})
    if not isinstance(assessment, dict):
        raise FeedbackError("Incident triple_loop assessment must be an object.")
    loop3 = assessment.get("loop3_reflection", {})
    if not isinstance(loop3, dict):
        raise FeedbackError("Incident loop3_reflection assessment must be an object.")

    proposed_action = _required_text(
        loop3.get("governance_action", "retain_current_policy"),
        "governance_action",
    )
    learning_score = _bounded_score(assessment.get("learning_score", 0.0))
    severity = str(incident.get("severity", "unknown")).strip().casefold() or "unknown"
    occurrence_count = _positive_integer(incident.get("occurrence_count"), 1)
    timestamp = _utc_datetime(created_at)
    rationale = (
        f"Review {proposed_action} for {severity} incident {incident_id}; "
        f"observed occurrences={occurrence_count}, learning score={learning_score:.4f}."
    )
    payload = {
        "incident_id": incident_id,
        "proposed_action": proposed_action,
        "learning_score": learning_score,
        "previous_recommendation_id": _optional_text(previous_recommendation_id),
    }
    recommendation_id = "prec_" + _stable_identifier(payload)
    return PolicyRecommendation(
        recommendation_id=recommendation_id,
        incident_id=incident_id,
        proposed_action=proposed_action,
        rationale=rationale,
        learning_score=learning_score,
        status=RecommendationStatus.PROPOSED,
        requires_human_approval=True,
        auto_apply=False,
        created_at=timestamp,
        previous_recommendation_id=_optional_text(previous_recommendation_id),
    )


def create_analyst_feedback(
    recommendation: PolicyRecommendation,
    *,
    analyst: str,
    decision: FeedbackDecision,
    rationale: str,
    created_at: datetime | None = None,
) -> AnalystFeedback:
    """Create documented feedback for one proposed recommendation."""

    if recommendation.status is not RecommendationStatus.PROPOSED:
        raise FeedbackError("Feedback can only target a proposed recommendation.")
    normalized_analyst = _required_text(analyst, "analyst")
    normalized_rationale = _required_text(rationale, "rationale")
    if len(normalized_rationale) < 8:
        raise FeedbackError("Feedback rationale must contain at least 8 characters.")
    timestamp = _utc_datetime(created_at)
    payload = {
        "recommendation_id": recommendation.recommendation_id,
        "analyst": normalized_analyst,
        "decision": decision.value,
        "rationale": normalized_rationale,
        "created_at": timestamp.isoformat(),
    }
    return AnalystFeedback(
        feedback_id="fdbk_" + _stable_identifier(payload),
        recommendation_id=recommendation.recommendation_id,
        incident_id=recommendation.incident_id,
        analyst=normalized_analyst,
        decision=decision,
        rationale=normalized_rationale,
        created_at=timestamp,
    )


def _stable_identifier(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _required_text(value: object, field: str) -> str:
    normalized = str(value).strip() if value is not None else ""
    if not normalized:
        raise FeedbackError(f"{field} cannot be empty.")
    return normalized


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _bounded_score(value: object) -> float:
    if not isinstance(value, (str, int, float)):
        return 0.0
    try:
        score = float(value)
    except ValueError:
        return 0.0
    return round(min(1.0, max(0.0, score)), 4)


def _positive_integer(value: object, default: int) -> int:
    if not isinstance(value, (str, int, float)):
        return default
    try:
        number = int(value)
    except ValueError:
        return default
    return number if number > 0 else default


def _utc_datetime(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        raise FeedbackError("Feedback timestamps must include a timezone.")
    return value.astimezone(UTC)
