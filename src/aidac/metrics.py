"""Dependency-free Prometheus metrics for the AI-DAC API."""

from __future__ import annotations

import re
import threading
from collections import Counter, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from aidac import __version__
from aidac.alert_store import AlertStoreError, load_alerts, store_info
from aidac.incidents import IncidentStatus, correlate_alerts

if TYPE_CHECKING:
    from aidac.component_health import ComponentHealthRegistry

_DYNAMIC_ALERT_PATH = re.compile(r"^/api/v1/alerts/[^/]+(?:/(?:ack|resolve))?$")
_DYNAMIC_INCIDENT_PATH = re.compile(r"^/api/v1/incidents/[^/]+(?:/assessment)?$")


class MetricsRegistry:
    """Thread-safe in-process HTTP counters and storage gauges."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._duration_sum: defaultdict[tuple[str, str], float] = defaultdict(float)
        self._duration_count: Counter[tuple[str, str]] = Counter()

    def observe_http_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        """Record one HTTP request without retaining high-cardinality identifiers."""

        normalized_method = method.upper().strip() or "UNKNOWN"
        normalized_path = normalize_metric_path(path)
        key = (normalized_method, normalized_path)
        with self._lock:
            self._requests[(normalized_method, normalized_path, status_code)] += 1
            self._duration_sum[key] += max(duration_seconds, 0.0)
            self._duration_count[key] += 1

    def render(
        self,
        alert_store: Path,
        component_registry: ComponentHealthRegistry | None = None,
        *,
        incident_window_minutes: int = 30,
    ) -> str:
        """Render Prometheus text exposition format."""

        with self._lock:
            request_counts = dict(self._requests)
            duration_sums = dict(self._duration_sum)
            duration_counts = dict(self._duration_count)

        lines = [
            "# HELP aidac_info AI-DAC package information.",
            "# TYPE aidac_info gauge",
            f'aidac_info{{version="{_escape(__version__)}"}} 1',
            "# HELP aidac_http_requests_total Total API HTTP requests.",
            "# TYPE aidac_http_requests_total counter",
        ]
        for (method, path, status_code), count in sorted(request_counts.items()):
            lines.append(
                "aidac_http_requests_total"
                f'{{method="{_escape(method)}",path="{_escape(path)}",status="{status_code}"}} '
                f"{count}"
            )

        lines.extend(
            [
                "# HELP aidac_http_request_duration_seconds_sum Sum of API request durations.",
                "# TYPE aidac_http_request_duration_seconds_sum counter",
            ]
        )
        for (method, path), value in sorted(duration_sums.items()):
            lines.append(
                "aidac_http_request_duration_seconds_sum"
                f'{{method="{_escape(method)}",path="{_escape(path)}"}} {value:.9f}'
            )
        lines.extend(
            [
                "# HELP aidac_http_request_duration_seconds_count Count of measured API requests.",
                "# TYPE aidac_http_request_duration_seconds_count counter",
            ]
        )
        for (method, path), value in sorted(duration_counts.items()):
            lines.append(
                "aidac_http_request_duration_seconds_count"
                f'{{method="{_escape(method)}",path="{_escape(path)}"}} {value}'
            )

        try:
            alerts = load_alerts(alert_store)
            information = store_info(alert_store)
            status_counts: Counter[str] = Counter(
                str(alert.get("status", "unknown")) for alert in alerts
            )
            severity_counts: Counter[str] = Counter(
                str(alert.get("severity", "unknown")) for alert in alerts
            )
            backend = str(information.get("backend", "unknown"))
            lines.extend(
                [
                    "# HELP aidac_alerts_total Current deduplicated alerts by lifecycle status.",
                    "# TYPE aidac_alerts_total gauge",
                ]
            )
            for alert_status, count in sorted(status_counts.items()):
                lines.append(f'aidac_alerts_total{{status="{_escape(alert_status)}"}} {count}')
            lines.extend(
                [
                    "# HELP aidac_alerts_by_severity Current deduplicated alerts by severity.",
                    "# TYPE aidac_alerts_by_severity gauge",
                ]
            )
            for severity, count in sorted(severity_counts.items()):
                lines.append(f'aidac_alerts_by_severity{{severity="{_escape(severity)}"}} {count}')
            lines.extend(
                [
                    "# HELP aidac_alert_store_up Whether the configured alert store is readable.",
                    "# TYPE aidac_alert_store_up gauge",
                    f'aidac_alert_store_up{{backend="{_escape(backend)}"}} 1',
                ]
            )
            incidents = correlate_alerts(alerts, window_minutes=incident_window_minutes)
            incident_counts: Counter[tuple[str, str]] = Counter(
                (str(item.get("status", "unknown")), str(item.get("severity", "unknown")))
                for item in incidents
            )
            lines.extend(
                [
                    "# HELP aidac_incidents_total Current correlated incidents "
                    "by status and severity.",
                    "# TYPE aidac_incidents_total gauge",
                ]
            )
            for (incident_status, incident_severity), count in sorted(incident_counts.items()):
                lines.append(
                    "aidac_incidents_total"
                    f'{{status="{_escape(incident_status)}",'
                    f'severity="{_escape(incident_severity)}"}} '
                    f"{count}"
                )
            active = [
                item for item in incidents if item.get("status") != IncidentStatus.RESOLVED.value
            ]
            recurrence_max = max(
                (int(item.get("occurrence_count", 0)) for item in active),
                default=0,
            )
            lines.extend(
                [
                    "# HELP aidac_incident_recurrence_max Maximum occurrences "
                    "in an active incident.",
                    "# TYPE aidac_incident_recurrence_max gauge",
                    f"aidac_incident_recurrence_max {recurrence_max}",
                ]
            )
        except AlertStoreError:
            lines.extend(
                [
                    "# HELP aidac_alert_store_up Whether the configured alert store is readable.",
                    "# TYPE aidac_alert_store_up gauge",
                    'aidac_alert_store_up{backend="unknown"} 0',
                ]
            )

        if component_registry is not None:
            lines.extend(component_registry.render_prometheus())

        return "\n".join(lines) + "\n"


def normalize_metric_path(path: str) -> str:
    """Replace alert identifiers with a bounded route label."""

    normalized = path.strip() or "/"
    if _DYNAMIC_ALERT_PATH.fullmatch(normalized):
        if normalized.endswith("/ack"):
            return "/api/v1/alerts/{alert_id}/ack"
        if normalized.endswith("/resolve"):
            return "/api/v1/alerts/{alert_id}/resolve"
        return "/api/v1/alerts/{alert_id}"
    if _DYNAMIC_INCIDENT_PATH.fullmatch(normalized):
        if normalized.endswith("/assessment"):
            return "/api/v1/incidents/{incident_id}/assessment"
        return "/api/v1/incidents/{incident_id}"
    return normalized


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
