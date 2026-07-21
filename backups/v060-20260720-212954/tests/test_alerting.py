"""Tests for AI-DAC persistent alert delivery helpers."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

import aidac.alerting as alerting_module
from aidac.alerting import (
    AlertingError,
    WebhookSettings,
    append_alert_records,
    build_alert_batch,
    send_signed_webhook,
    write_audit_event,
    write_batch_export,
)


def test_alert_records_are_persisted_privately(
    tmp_path: Path,
) -> None:
    """Alert JSONL files should use mode 600."""

    output_file = tmp_path / "state" / "alerts.jsonl"
    batch = build_alert_batch(
        [
            {
                "query": "DROP TABLE customers;",
                "risk_score": 0.95,
                "severity": "critical",
            }
        ]
    )

    result = append_alert_records(output_file, batch)

    assert result == output_file
    lines = output_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    payload = json.loads(lines[0])

    assert payload["type"] == "aidac_alert"
    assert payload["batch_id"] == batch["batch_id"]
    assert payload["risk_score"] == 0.95
    assert stat.S_IMODE(output_file.stat().st_mode) == 0o600


def test_audit_event_is_appended_privately(
    tmp_path: Path,
) -> None:
    """Local audit records should be structured JSONL."""

    audit_file = tmp_path / "audit.jsonl"

    write_audit_event(
        audit_file,
        action="unit_test",
        status="success",
        details={"count": 1},
    )

    payload = json.loads(audit_file.read_text(encoding="utf-8").strip())

    assert payload["action"] == "unit_test"
    assert payload["status"] == "success"
    assert payload["details"]["count"] == 1
    assert stat.S_IMODE(audit_file.stat().st_mode) == 0o600


def test_batch_export_is_private_json(
    tmp_path: Path,
) -> None:
    """Automatic exports should be valid private JSON."""

    batch = build_alert_batch([{"risk_score": 0.8}])

    output_file = write_batch_export(
        tmp_path / "exports",
        batch,
    )

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["batch_id"] == batch["batch_id"]
    assert stat.S_IMODE(output_file.stat().st_mode) == 0o600


def test_webhook_requires_https() -> None:
    """Insecure HTTP webhook URLs must be rejected."""

    with pytest.raises(
        AlertingError,
        match="HTTPS",
    ):
        WebhookSettings(url="http://example.test/alerts")


def test_signed_webhook_uses_hmac_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Webhook requests should include HMAC headers."""

    captured: dict[str, Any] = {}

    class FakeResponse:
        """Minimal successful HTTP response."""

        status = 204

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> None:
            return None

    def fake_urlopen(
        request: object,
        *,
        timeout: float,
    ) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv(
        "AIDAC_WEBHOOK_SECRET",
        "test-secret",
    )
    monkeypatch.setattr(
        alerting_module,
        "urlopen",
        fake_urlopen,
    )

    status = send_signed_webhook(
        WebhookSettings(
            url="https://example.test/alerts",
            timeout_seconds=3.5,
        ),
        build_alert_batch([{"risk_score": 0.9}]),
    )

    request = captured["request"]

    assert status == 204
    assert captured["timeout"] == 3.5
    assert request.get_header("X-aidac-signature").startswith("sha256=")
    assert request.get_header("X-aidac-timestamp")
