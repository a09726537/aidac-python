"""Optional OpenTelemetry OTLP trace export for AI-DAC."""

from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse

from aidac import __version__

DEFAULT_OTEL_SERVICE_NAME = "aidac-api"


class TelemetryError(RuntimeError):
    """Raised when optional OpenTelemetry configuration cannot be applied."""


class Telemetry:
    """Small wrapper that remains a no-op when telemetry is disabled."""

    def __init__(self, *, tracer: Any | None = None, provider: Any | None = None) -> None:
        self._tracer = tracer
        self._provider = provider

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    @contextmanager
    def start_span(self, name: str, attributes: dict[str, Any]) -> Iterator[Any | None]:
        if self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(name, attributes=attributes) as span:
            yield span

    def shutdown(self) -> None:
        if self._provider is not None:
            shutdown = getattr(self._provider, "shutdown", None)
            if callable(shutdown):
                shutdown()


def configure_telemetry(
    *,
    endpoint: str | None = None,
    service_name: str | None = None,
) -> Telemetry:
    """Configure OTLP/HTTP tracing when an endpoint is supplied."""

    traces_endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    generic_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    effective_endpoint = endpoint or traces_endpoint
    if effective_endpoint is None and generic_endpoint:
        effective_endpoint = generic_endpoint.rstrip("/") + "/v1/traces"
    if effective_endpoint is None or not effective_endpoint.strip():
        return Telemetry()

    normalized_endpoint = validate_otel_endpoint(effective_endpoint)
    normalized_service_name = validate_service_name(
        service_name or os.getenv("OTEL_SERVICE_NAME") or DEFAULT_OTEL_SERVICE_NAME
    )

    try:
        trace_module = importlib.import_module("opentelemetry.trace")
        exporter_module = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        )
        resources_module = importlib.import_module("opentelemetry.sdk.resources")
        trace_sdk_module = importlib.import_module("opentelemetry.sdk.trace")
        trace_export_module = importlib.import_module("opentelemetry.sdk.trace.export")
    except ImportError as error:
        raise TelemetryError(
            "OpenTelemetry dependencies are missing. Install them with: "
            "python -m pip install 'aidac-sec[otel]'"
        ) from error

    del trace_module
    resource_class = resources_module.Resource
    service_name_key = resources_module.SERVICE_NAME
    service_version_key = resources_module.SERVICE_VERSION
    provider_class = trace_sdk_module.TracerProvider
    batch_processor_class = trace_export_module.BatchSpanProcessor
    exporter_class = exporter_module.OTLPSpanExporter

    resource = resource_class.create(
        {
            service_name_key: normalized_service_name,
            service_version_key: __version__,
            "service.namespace": "aidac",
        }
    )
    provider = provider_class(resource=resource)
    exporter = exporter_class(endpoint=normalized_endpoint)
    provider.add_span_processor(batch_processor_class(exporter))
    tracer = provider.get_tracer("aidac.api", __version__)
    return Telemetry(tracer=tracer, provider=provider)


def validate_otel_endpoint(endpoint: str) -> str:
    """Validate a non-credentialed OTLP HTTP endpoint."""

    normalized = endpoint.strip()
    parsed = urlparse(normalized)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        raise TelemetryError("OpenTelemetry endpoint must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise TelemetryError("OpenTelemetry endpoint must not embed credentials.")
    if parsed.fragment:
        raise TelemetryError("OpenTelemetry endpoint must not contain a fragment.")
    return normalized


def validate_service_name(service_name: str) -> str:
    """Validate the low-cardinality OpenTelemetry service name."""

    normalized = service_name.strip()
    if not normalized or len(normalized) > 100:
        raise TelemetryError("OpenTelemetry service name must contain 1 to 100 characters.")
    if any(character in normalized for character in "\r\n\x00"):
        raise TelemetryError("OpenTelemetry service name contains invalid characters.")
    return normalized
