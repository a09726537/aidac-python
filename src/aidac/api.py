"""Authenticated, role-aware REST API for AI-DAC alert operations."""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from aidac import __version__
from aidac.alert_store import (
    AlertStatus,
    AlertStoreError,
    get_alert,
    load_alerts,
    query_alerts,
    store_info,
    update_alert_status,
    verify_store,
)
from aidac.alerting import (
    DEFAULT_ALERT_LOG,
    DEFAULT_AUDIT_LOG,
    AlertingError,
    verify_audit_log,
    write_audit_event,
)
from aidac.dashboard import (
    DEFAULT_DASHBOARD_SESSION_MINUTES,
    DEFAULT_DASHBOARD_TOKEN_ENV,
    install_dashboard_routes,
)
from aidac.metrics import MetricsRegistry
from aidac.structured_logging import get_logger

DEFAULT_API_TOKEN_ENV = "AIDAC_API_TOKEN"
DEFAULT_VIEWER_TOKEN_ENV = "AIDAC_API_VIEWER_TOKEN"
DEFAULT_ANALYST_TOKEN_ENV = "AIDAC_API_ANALYST_TOKEN"
DEFAULT_ADMIN_TOKEN_ENV = "AIDAC_API_ADMIN_TOKEN"
MINIMUM_API_TOKEN_LENGTH = 32
DEFAULT_RATE_LIMIT_PER_MINUTE = 120


class APIRole(StrEnum):
    """API authorization roles ordered by privilege."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


_ROLE_RANK = {
    APIRole.VIEWER: 0,
    APIRole.ANALYST: 1,
    APIRole.ADMIN: 2,
}


@dataclass(frozen=True, slots=True)
class APIPrincipal:
    """Authenticated API caller without retaining the clear-text token."""

    role: APIRole
    token_id: str


class AlertActionRequest(BaseModel):
    """Body accepted by alert lifecycle mutation endpoints."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    actor: str = Field(min_length=1, max_length=200)
    note: str | None = Field(default=None, max_length=2_000)


class HealthResponse(BaseModel):
    """Service health response."""

    status: str
    version: str


class ReadinessResponse(HealthResponse):
    """Readiness response with non-sensitive component state."""

    token_configured: bool
    alert_store_readable: bool
    audit_log_valid: bool


class AlertListResponse(BaseModel):
    """Paginated current alert collection response."""

    alert_count: int
    total: int
    limit: int
    offset: int
    next_offset: int | None
    alerts: list[dict[str, Any]]


class AlertSummaryResponse(BaseModel):
    """Aggregate current alert counts."""

    alert_count: int
    status_counts: dict[str, int]
    severity_counts: dict[str, int]


class _RateLimiter:
    """Small in-memory sliding-window limiter for one service process."""

    def __init__(self, requests_per_minute: int) -> None:
        if not 1 <= requests_per_minute <= 100_000:
            raise ValueError("API rate limit must be between 1 and 100000 requests per minute.")
        self._limit = requests_per_minute
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        cutoff = current - 60.0
        with self._lock:
            events = self._events.setdefault(key, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self._limit:
                retry_after = max(1, int(60.0 - (current - events[0])))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="API rate limit exceeded.",
                    headers={"Retry-After": str(retry_after)},
                )
            events.append(current)


def create_app(
    *,
    alert_log: Path = DEFAULT_ALERT_LOG,
    audit_log: Path = DEFAULT_AUDIT_LOG,
    token_env: str = DEFAULT_API_TOKEN_ENV,
    viewer_token_env: str = DEFAULT_VIEWER_TOKEN_ENV,
    analyst_token_env: str = DEFAULT_ANALYST_TOKEN_ENV,
    admin_token_env: str = DEFAULT_ADMIN_TOKEN_ENV,
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
    dashboard_enabled: bool = False,
    dashboard_token_env: str = DEFAULT_DASHBOARD_TOKEN_ENV,
    dashboard_session_minutes: int = DEFAULT_DASHBOARD_SESSION_MINUTES,
) -> FastAPI:
    """Create a configured AI-DAC FastAPI application."""

    expanded_alert_log = alert_log.expanduser()
    expanded_audit_log = audit_log.expanduser()
    token_environments = {
        APIRole.VIEWER: viewer_token_env.strip(),
        APIRole.ANALYST: analyst_token_env.strip(),
        APIRole.ADMIN: admin_token_env.strip(),
    }
    normalized_token_env = token_env.strip()
    if not normalized_token_env or any(not value for value in token_environments.values()):
        raise ValueError("API token environment variable names cannot be empty.")

    bearer = HTTPBearer(auto_error=False)
    store_lock = threading.RLock()
    limiter = _RateLimiter(rate_limit_per_minute)
    metrics = MetricsRegistry()
    logger = get_logger()

    app = FastAPI(
        title="AI-DAC Alert API",
        version=__version__,
        description=(
            "Role-aware access to the AI-DAC alert lifecycle store. "
            "Viewer tokens are read-only; analyst tokens can change alert state; "
            "admin tokens can also inspect system diagnostics."
        ),
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.metrics_registry = metrics

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Any:
        started = time.perf_counter()
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            duration = time.perf_counter() - started
            metrics.observe_http_request(
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                duration_seconds=duration,
            )
            logger.exception(
                "API request failed",
                extra={
                    "event": "http_request",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_seconds": round(duration, 9),
                },
            )
            raise

        duration = time.perf_counter() - started
        metrics.observe_http_request(
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            duration_seconds=duration,
        )
        logger.info(
            "API request completed",
            extra={
                "event": "http_request",
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_seconds": round(duration, 9),
            },
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    bearer_dependency = Depends(bearer)

    def authenticate(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = bearer_dependency,
    ) -> APIPrincipal:
        configured = _configured_tokens(
            legacy_env=normalized_token_env,
            role_environments=token_environments,
        )
        if not configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured.",
            )
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        principal = _match_token(credentials.credentials, configured)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        client_host = "unknown" if request.client is None else request.client.host
        limiter.check(f"{principal.token_id}:{client_host}")
        return principal

    authentication_dependency = Depends(authenticate)

    def require_role(minimum: APIRole) -> Callable[[APIPrincipal], APIPrincipal]:
        def dependency(principal: APIPrincipal = authentication_dependency) -> APIPrincipal:
            if _ROLE_RANK[principal.role] < _ROLE_RANK[minimum]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"The {minimum.value} role is required.",
                )
            return principal

        return dependency

    viewer_authentication = Depends(require_role(APIRole.VIEWER))
    analyst_authentication = Depends(require_role(APIRole.ANALYST))
    admin_authentication = Depends(require_role(APIRole.ADMIN))

    @app.exception_handler(AlertStoreError)
    async def alert_store_error_handler(
        request: Request,
        error: AlertStoreError,
    ) -> JSONResponse:
        del request
        error_status = (
            status.HTTP_404_NOT_FOUND
            if str(error).startswith("Alert not found:")
            else status.HTTP_400_BAD_REQUEST
        )
        return JSONResponse(status_code=error_status, content={"detail": str(error)})

    @app.exception_handler(AlertingError)
    async def alerting_error_handler(
        request: Request,
        error: AlertingError,
    ) -> JSONResponse:
        del request
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": str(error)},
        )

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        response = {
            "service": "AI-DAC Alert API",
            "version": __version__,
            "documentation": "/docs",
        }
        if dashboard_enabled:
            response["dashboard"] = "/dashboard"
        return response

    @app.get("/health/live", response_model=HealthResponse, tags=["health"])
    def health_live() -> HealthResponse:
        return HealthResponse(status="live", version=__version__)

    @app.get(
        "/health/ready",
        response_model=ReadinessResponse,
        tags=["health"],
        responses={503: {"description": "Service is not ready"}},
    )
    def health_ready() -> ReadinessResponse:
        token_configured = bool(
            _configured_tokens(
                legacy_env=normalized_token_env,
                role_environments=token_environments,
            )
        )
        alert_store_readable = True
        audit_log_valid = True
        try:
            with store_lock:
                verify_store(expanded_alert_log)
        except AlertStoreError:
            alert_store_readable = False
        try:
            audit_log_valid = verify_audit_log(expanded_audit_log).valid
        except AlertingError:
            audit_log_valid = False

        is_ready = token_configured and alert_store_readable and audit_log_valid
        response = ReadinessResponse(
            status="ready" if is_ready else "not_ready",
            version=__version__,
            token_configured=token_configured,
            alert_store_readable=alert_store_readable,
            audit_log_valid=audit_log_valid,
        )
        if not is_ready:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=response.model_dump(),
            )
        return response

    @app.get(
        "/metrics",
        response_class=PlainTextResponse,
        tags=["system"],
        summary="Prometheus metrics",
    )
    def prometheus_metrics(
        principal: APIPrincipal = viewer_authentication,
    ) -> PlainTextResponse:
        del principal
        with store_lock:
            body = metrics.render(expanded_alert_log)
        return PlainTextResponse(
            content=body,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get(
        "/api/v1/alerts/summary",
        response_model=AlertSummaryResponse,
        tags=["alerts"],
    )
    def alerts_summary(
        principal: APIPrincipal = viewer_authentication,
    ) -> AlertSummaryResponse:
        del principal
        with store_lock:
            alerts = load_alerts(expanded_alert_log)
        status_counts: Counter[str] = Counter(str(item.get("status", "unknown")) for item in alerts)
        severity_counts: Counter[str] = Counter(
            str(item.get("severity", "unknown")) for item in alerts
        )
        return AlertSummaryResponse(
            alert_count=len(alerts),
            status_counts=dict(status_counts),
            severity_counts=dict(severity_counts),
        )

    @app.get(
        "/api/v1/alerts",
        response_model=AlertListResponse,
        tags=["alerts"],
    )
    def alerts_list(
        principal: APIPrincipal = viewer_authentication,
        alert_status: Annotated[
            AlertStatus | None,
            Query(alias="status", description="Optional lifecycle status filter."),
        ] = None,
        severity: Annotated[
            str | None,
            Query(description="Optional exact severity filter.", max_length=30),
        ] = None,
        minimum_risk: Annotated[
            float,
            Query(alias="min_risk", ge=0.0, le=1.0),
        ] = 0.0,
        search: Annotated[
            str | None,
            Query(alias="q", description="Search identity, database, IP, class, or query."),
        ] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 50,
        offset: Annotated[int, Query(ge=0, le=10_000_000)] = 0,
    ) -> AlertListResponse:
        del principal
        with store_lock:
            alerts, total = query_alerts(
                expanded_alert_log,
                status=alert_status,
                severity=severity,
                minimum_risk=minimum_risk,
                search=search,
                limit=limit,
                offset=offset,
            )
        next_offset = offset + len(alerts) if offset + len(alerts) < total else None
        return AlertListResponse(
            alert_count=len(alerts),
            total=total,
            limit=limit,
            offset=offset,
            next_offset=next_offset,
            alerts=alerts,
        )

    @app.get(
        "/api/v1/alerts/{alert_id}",
        response_model=dict[str, Any],
        tags=["alerts"],
    )
    def alerts_show(
        alert_id: str,
        principal: APIPrincipal = viewer_authentication,
    ) -> dict[str, Any]:
        del principal
        with store_lock:
            return get_alert(expanded_alert_log, alert_id)

    @app.post(
        "/api/v1/alerts/{alert_id}/ack",
        response_model=dict[str, Any],
        tags=["alerts"],
    )
    def alerts_acknowledge(
        alert_id: str,
        action: AlertActionRequest,
        principal: APIPrincipal = analyst_authentication,
    ) -> dict[str, Any]:
        return _change_alert_status(
            alert_id,
            action,
            principal=principal,
            target_status=AlertStatus.ACKNOWLEDGED,
        )

    @app.post(
        "/api/v1/alerts/{alert_id}/resolve",
        response_model=dict[str, Any],
        tags=["alerts"],
    )
    def alerts_resolve(
        alert_id: str,
        action: AlertActionRequest,
        principal: APIPrincipal = analyst_authentication,
    ) -> dict[str, Any]:
        return _change_alert_status(
            alert_id,
            action,
            principal=principal,
            target_status=AlertStatus.RESOLVED,
        )

    def _change_alert_status(
        alert_id: str,
        action: AlertActionRequest,
        *,
        principal: APIPrincipal,
        target_status: AlertStatus,
    ) -> dict[str, Any]:
        with store_lock:
            alert = update_alert_status(
                expanded_alert_log,
                alert_id,
                status=target_status,
                actor=action.actor,
                note=action.note,
            )
            write_audit_event(
                expanded_audit_log,
                action=f"api_alert_{target_status.value}",
                status="success",
                details={
                    "alert_id": alert_id,
                    "actor": action.actor,
                    "note": action.note,
                    "api_role": principal.role.value,
                    "token_id": principal.token_id,
                },
            )
        logger.info(
            "Alert lifecycle state changed",
            extra={
                "event": "alert_status_changed",
                "role": principal.role.value,
                "token_id": principal.token_id,
                "alert_id": alert_id,
            },
        )
        return alert

    @app.get("/api/v1/system/storage", tags=["system"])
    def system_storage(
        principal: APIPrincipal = admin_authentication,
    ) -> dict[str, Any]:
        del principal
        with store_lock:
            return store_info(expanded_alert_log)

    @app.get("/api/v1/system/audit/verify", tags=["system"])
    def system_audit_verify(
        principal: APIPrincipal = admin_authentication,
    ) -> dict[str, Any]:
        del principal
        verification = verify_audit_log(expanded_audit_log)
        return {
            "valid": verification.valid,
            "records": verification.records,
            "chained_records": verification.chained_records,
            "legacy_records": verification.legacy_records,
            "failure_line": verification.failure_line,
            "message": verification.message,
        }

    if dashboard_enabled:
        install_dashboard_routes(
            app,
            alert_log=expanded_alert_log,
            audit_log=expanded_audit_log,
            token_env=dashboard_token_env,
            session_minutes=dashboard_session_minutes,
            store_lock=store_lock,
        )

    return app


def _configured_tokens(
    *,
    legacy_env: str,
    role_environments: dict[APIRole, str],
) -> list[tuple[str, APIRole, str]]:
    configured: list[tuple[str, APIRole, str]] = []
    for role in (APIRole.ADMIN, APIRole.ANALYST, APIRole.VIEWER):
        environment = role_environments[role]
        value = os.getenv(environment, "")
        if len(value) >= MINIMUM_API_TOKEN_LENGTH:
            configured.append((value, role, _token_identifier(environment, value)))

    legacy_value = os.getenv(legacy_env, "")
    if len(legacy_value) >= MINIMUM_API_TOKEN_LENGTH:
        configured.append(
            (legacy_value, APIRole.ADMIN, _token_identifier(legacy_env, legacy_value))
        )
    return configured


def _match_token(
    supplied: str,
    configured: list[tuple[str, APIRole, str]],
) -> APIPrincipal | None:
    selected: APIPrincipal | None = None
    for token, role, token_id in configured:
        if hmac.compare_digest(supplied, token):
            candidate = APIPrincipal(role=role, token_id=token_id)
            if selected is None or _ROLE_RANK[candidate.role] > _ROLE_RANK[selected.role]:
                selected = candidate
    return selected


def _token_identifier(environment: str, token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return f"{environment}:{digest}"
