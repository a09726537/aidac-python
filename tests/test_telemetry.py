from __future__ import annotations

import pytest

from aidac.telemetry import (
    TelemetryError,
    configure_telemetry,
    validate_otel_endpoint,
    validate_service_name,
)


def test_telemetry_is_noop_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    telemetry = configure_telemetry()
    assert telemetry.enabled is False
    with telemetry.start_span("test", {"key": "value"}) as span:
        assert span is None


def test_telemetry_validation() -> None:
    assert validate_otel_endpoint("http://127.0.0.1:4318/v1/traces") == (
        "http://127.0.0.1:4318/v1/traces"
    )
    assert validate_service_name("aidac-api") == "aidac-api"
    with pytest.raises(TelemetryError):
        validate_otel_endpoint("ftp://example.test/traces")
    with pytest.raises(TelemetryError):
        validate_otel_endpoint("https://user:secret@example.test/v1/traces")
    with pytest.raises(TelemetryError):
        validate_service_name("\n")
