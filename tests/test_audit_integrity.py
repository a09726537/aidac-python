"""Tests for the tamper-evident AI-DAC audit chain."""

from __future__ import annotations

import json
from pathlib import Path

from aidac.alerting import verify_audit_log, write_audit_event


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    """Changing a chained record should invalidate its cryptographic hash."""

    audit_log = tmp_path / "audit.jsonl"
    write_audit_event(audit_log, action="alert_ack", status="success")
    write_audit_event(audit_log, action="alert_resolve", status="success")

    assert verify_audit_log(audit_log).valid is True

    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    records[0]["action"] = "tampered"
    audit_log.write_text(
        "\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n",
        encoding="utf-8",
    )

    result = verify_audit_log(audit_log)
    assert result.valid is False
    assert result.failure_line == 1
    assert result.message == "record_hash_mismatch"


def test_new_chain_can_follow_legacy_audit_records(tmp_path: Path) -> None:
    """AI-DAC should preserve and chain forward from legacy audit JSONL."""

    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        json.dumps(
            {
                "type": "aidac_audit_event",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "action": "legacy",
                "status": "success",
                "details": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    write_audit_event(audit_log, action="current", status="success")
    result = verify_audit_log(audit_log)

    assert result.valid is True
    assert result.legacy_records == 1
    assert result.chained_records == 1
