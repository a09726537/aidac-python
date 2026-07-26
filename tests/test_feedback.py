from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aidac.feedback import (
    FeedbackDecision,
    FeedbackError,
    FeedbackStore,
    RecommendationStatus,
    build_policy_recommendation,
    create_analyst_feedback,
)


def _incident() -> dict[str, object]:
    return {
        "incident_id": "inc_critical_001",
        "severity": "critical",
        "occurrence_count": 4,
        "triple_loop": {
            "learning_score": 0.82,
            "loop3_reflection": {
                "governance_action": "policy_and_control_review",
            },
        },
    }


def test_policy_recommendation_never_auto_applies() -> None:
    recommendation = build_policy_recommendation(
        _incident(),
        created_at=datetime(2026, 7, 24, 1, 0, tzinfo=UTC),
    )

    assert recommendation.status is RecommendationStatus.PROPOSED
    assert recommendation.requires_human_approval is True
    assert recommendation.auto_apply is False
    assert recommendation.proposed_action == "policy_and_control_review"
    assert recommendation.to_dict()["learning_score"] == 0.82


def test_store_records_acceptance_without_applying_policy() -> None:
    store = FeedbackStore()
    recommendation = build_policy_recommendation(
        _incident(),
        created_at=datetime(2026, 7, 24, 1, 0, tzinfo=UTC),
    )
    store.save_recommendation(recommendation)
    feedback = create_analyst_feedback(
        recommendation,
        analyst="analyst@example.org",
        decision=FeedbackDecision.ACCEPT,
        rationale="Evidence supports a controlled policy review.",
        created_at=datetime(2026, 7, 24, 1, 5, tzinfo=UTC),
    )

    updated = store.record_feedback(feedback)

    assert updated.status is RecommendationStatus.ACCEPTED
    assert updated.auto_apply is False
    assert store.list_feedback(incident_id="inc_critical_001") == [feedback]


def test_store_rejects_second_decision_for_same_recommendation() -> None:
    store = FeedbackStore()
    recommendation = build_policy_recommendation(_incident())
    store.save_recommendation(recommendation)
    accepted = create_analyst_feedback(
        recommendation,
        analyst="analyst-one",
        decision=FeedbackDecision.ACCEPT,
        rationale="Accept after documented evidence review.",
    )
    store.record_feedback(accepted)
    rejected = create_analyst_feedback(
        recommendation,
        analyst="analyst-two",
        decision=FeedbackDecision.REJECT,
        rationale="Reject after independent evidence review.",
    )

    with pytest.raises(FeedbackError, match="already decided"):
        store.record_feedback(rejected)


def test_feedback_requires_documented_rationale() -> None:
    recommendation = build_policy_recommendation(_incident())

    with pytest.raises(FeedbackError, match="at least 8 characters"):
        create_analyst_feedback(
            recommendation,
            analyst="analyst-one",
            decision=FeedbackDecision.REVISION_REQUIRED,
            rationale="short",
        )


def test_recommendation_identifier_is_stable_for_same_incident_snapshot() -> None:
    first = build_policy_recommendation(
        _incident(),
        created_at=datetime(2026, 7, 24, 1, 0, tzinfo=UTC),
    )
    second = build_policy_recommendation(
        _incident(),
        created_at=datetime(2026, 7, 24, 2, 0, tzinfo=UTC),
    )

    assert first.recommendation_id == second.recommendation_id
