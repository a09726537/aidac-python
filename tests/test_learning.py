from __future__ import annotations

from aidac.learning import assess_incident


def test_triple_loop_assessment_escalates_recurrent_high_risk_incident() -> None:
    assessment = assess_incident(
        {
            "severity": "high",
            "risk_score": 0.9,
            "alert_count": 2,
            "occurrence_count": 5,
            "classifications": ["sql_injection", "privilege_escalation"],
        }
    )

    assert assessment.escalation_required is True
    assert assessment.human_approval_required is True
    assert assessment.loop1_detection["evidence_alerts"] == 2
    assert assessment.loop2_adaptation["response_mode"] == "immediate_human_review"
    assert assessment.loop3_reflection["governance_action"] == "policy_and_control_review"
    assert 0.0 <= assessment.learning_score <= 1.0


def test_low_risk_single_occurrence_retains_current_policy() -> None:
    assessment = assess_incident(
        {
            "severity": "low",
            "risk_score": 0.2,
            "alert_count": 1,
            "occurrence_count": 1,
            "classifications": ["unusual_query"],
        }
    )

    assert assessment.escalation_required is False
    assert assessment.loop3_reflection["governance_action"] == "retain_current_policy"
