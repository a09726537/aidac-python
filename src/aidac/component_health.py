"""Distributed component health probes for AI-DAC operations."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

_COMPONENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_COMPONENTS = 100
_MAX_CONFIG_BYTES = 1_000_000


class ComponentHealthError(RuntimeError):
    """Raised when component health configuration or probing is invalid."""


@dataclass(frozen=True, slots=True)
class ComponentTarget:
    """One bounded HTTP health target."""

    name: str
    url: str
    required: bool = True
    token_env: str | None = None
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        name = self.name.strip()
        url = self.url.strip()
        token_env = None if self.token_env is None else self.token_env.strip()
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "token_env", token_env or None)

        if not _COMPONENT_NAME.fullmatch(name):
            raise ComponentHealthError(
                "Component names must contain only letters, numbers, dots, dashes, or underscores."
            )
        parsed = urlparse(url)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
            raise ComponentHealthError("Component URLs must be absolute HTTP or HTTPS URLs.")
        if parsed.username is not None or parsed.password is not None:
            raise ComponentHealthError("Component URLs must not embed credentials.")
        if token_env is not None and not _ENVIRONMENT_NAME.fullmatch(token_env):
            raise ComponentHealthError("Component token_env must be a valid environment name.")
        if not 0.2 <= self.timeout_seconds <= 60.0:
            raise ComponentHealthError("Component timeout must be between 0.2 and 60 seconds.")


@dataclass(frozen=True, slots=True)
class ComponentResult:
    """Result of one component probe without secret material."""

    name: str
    url: str
    required: bool
    healthy: bool
    status_code: int | None
    duration_seconds: float
    detail: str
    checked_at_epoch: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_component_targets(path: Path) -> list[ComponentTarget]:
    """Load component targets from a small TOML file."""

    expanded = path.expanduser()
    try:
        if expanded.stat().st_size > _MAX_CONFIG_BYTES:
            raise ComponentHealthError("Component health configuration is too large.")
        with expanded.open("rb") as stream:
            payload = tomllib.load(stream)
    except FileNotFoundError as error:
        raise ComponentHealthError(
            f"Component health configuration not found: {expanded}"
        ) from error
    except tomllib.TOMLDecodeError as error:
        raise ComponentHealthError(f"Invalid component health TOML: {expanded}") from error
    except OSError as error:
        raise ComponentHealthError(
            f"Unable to read component health configuration: {expanded}"
        ) from error

    raw_components = payload.get("components", [])
    if not isinstance(raw_components, list):
        raise ComponentHealthError("The components setting must be an array of TOML tables.")
    if len(raw_components) > _MAX_COMPONENTS:
        raise ComponentHealthError(f"At most {_MAX_COMPONENTS} components may be configured.")

    targets: list[ComponentTarget] = []
    names: set[str] = set()
    for index, raw in enumerate(raw_components, start=1):
        if not isinstance(raw, dict):
            raise ComponentHealthError(f"Component #{index} must be a TOML table.")
        allowed = {"name", "url", "required", "token_env", "timeout_seconds"}
        unknown = set(raw) - allowed
        if unknown:
            raise ComponentHealthError(
                f"Unknown component fields for #{index}: {', '.join(sorted(unknown))}"
            )
        try:
            target = ComponentTarget(
                name=_required_text(raw, "name", index),
                url=_required_text(raw, "url", index),
                required=_optional_bool(raw, "required", True, index),
                token_env=_optional_text(raw, "token_env", index),
                timeout_seconds=_optional_float(raw, "timeout_seconds", 3.0, index),
            )
        except (TypeError, ValueError) as error:
            raise ComponentHealthError(f"Invalid component #{index}: {error}") from error
        if target.name in names:
            raise ComponentHealthError(f"Duplicate component name: {target.name}")
        names.add(target.name)
        targets.append(target)

    return targets


def probe_component(target: ComponentTarget) -> ComponentResult:
    """Probe one component with a bounded HTTP GET request."""

    headers = {
        "Accept": "application/json, text/plain;q=0.8, */*;q=0.1",
        "User-Agent": "aidac-sec/component-health",
    }
    if target.token_env is not None:
        token = os.getenv(target.token_env, "")
        if not token:
            return ComponentResult(
                name=target.name,
                url=target.url,
                required=target.required,
                healthy=False,
                status_code=None,
                duration_seconds=0.0,
                detail=f"missing_token:{target.token_env}",
                checked_at_epoch=time.time(),
            )
        headers["Authorization"] = f"Bearer {token}"

    request = Request(target.url, method="GET", headers=headers)
    started = time.perf_counter()
    status_code: int | None = None
    detail = "ok"
    healthy = False
    try:
        with urlopen(request, timeout=target.timeout_seconds) as response:
            status_code = int(response.status)
            response.read(4096)
            healthy = 200 <= status_code < 300
            if not healthy:
                detail = f"http_{status_code}"
    except HTTPError as error:
        status_code = int(error.code)
        detail = f"http_{error.code}"
    except URLError as error:
        detail = f"connection_error:{_safe_reason(error.reason)}"
    except TimeoutError:
        detail = "timeout"
    except OSError as error:
        detail = f"io_error:{error.__class__.__name__}"

    return ComponentResult(
        name=target.name,
        url=target.url,
        required=target.required,
        healthy=healthy,
        status_code=status_code,
        duration_seconds=max(0.0, time.perf_counter() - started),
        detail=detail,
        checked_at_epoch=time.time(),
    )


def check_components(targets: list[ComponentTarget]) -> list[ComponentResult]:
    """Probe configured components sequentially in deterministic order."""

    return [probe_component(target) for target in targets]


def health_summary(results: list[ComponentResult]) -> dict[str, Any]:
    """Build a non-sensitive aggregate health summary."""

    required_failures = [
        result.name for result in results if result.required and not result.healthy
    ]
    optional_failures = [
        result.name for result in results if not result.required and not result.healthy
    ]
    return {
        "status": "healthy" if not required_failures else "degraded",
        "component_count": len(results),
        "healthy_count": sum(result.healthy for result in results),
        "required_failures": required_failures,
        "optional_failures": optional_failures,
        "components": [result.as_dict() for result in results],
    }


class ComponentHealthRegistry:
    """Thread-safe last-known component status for Prometheus rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._results: dict[str, ComponentResult] = {}

    def replace(self, results: list[ComponentResult]) -> None:
        with self._lock:
            self._results = {result.name: result for result in results}

    def snapshot(self) -> list[ComponentResult]:
        with self._lock:
            return [self._results[name] for name in sorted(self._results)]

    def render_prometheus(self) -> list[str]:
        results = self.snapshot()
        lines = [
            "# HELP aidac_component_up Last distributed component probe result.",
            "# TYPE aidac_component_up gauge",
        ]
        for result in results:
            name = _escape_label(result.name)
            lines.append(f'aidac_component_up{{component="{name}"}} {1 if result.healthy else 0}')
        lines.extend(
            [
                "# HELP aidac_component_probe_duration_seconds Last component probe duration.",
                "# TYPE aidac_component_probe_duration_seconds gauge",
            ]
        )
        for result in results:
            name = _escape_label(result.name)
            lines.append(
                "aidac_component_probe_duration_seconds"
                f'{{component="{name}"}} {result.duration_seconds:.9f}'
            )
        lines.extend(
            [
                "# HELP aidac_component_required Whether the component is required for readiness.",
                "# TYPE aidac_component_required gauge",
            ]
        )
        for result in results:
            name = _escape_label(result.name)
            lines.append(
                f'aidac_component_required{{component="{name}"}} {1 if result.required else 0}'
            )
        return lines


def write_health_report(path: Path, summary: dict[str, Any]) -> Path:
    """Atomically write a private JSON component-health report."""

    expanded = path.expanduser()
    expanded.parent.mkdir(parents=True, exist_ok=True)
    expanded.parent.chmod(0o700)
    temporary = expanded.with_suffix(expanded.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(expanded)
        expanded.chmod(0o600)
    except OSError as error:
        raise ComponentHealthError(
            f"Unable to write component health report: {expanded}"
        ) from error
    return expanded


def _required_text(raw: dict[str, Any], key: str, index: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ComponentHealthError(f"Component #{index} requires non-empty {key} text.")
    return value


def _optional_text(raw: dict[str, Any], key: str, index: int) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ComponentHealthError(f"Component #{index} field {key} must be text.")
    return value


def _optional_bool(raw: dict[str, Any], key: str, default: bool, index: int) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ComponentHealthError(f"Component #{index} field {key} must be true or false.")
    return value


def _optional_float(raw: dict[str, Any], key: str, default: float, index: int) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ComponentHealthError(f"Component #{index} field {key} must be numeric.")
    return float(value)


def _safe_reason(reason: object) -> str:
    text = str(reason).replace("\n", " ").replace("\r", " ").strip()
    return text[:160] or reason.__class__.__name__


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
