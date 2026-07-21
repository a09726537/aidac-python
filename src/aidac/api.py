"""Authenticated REST API for AI-DAC alert lifecycle operations."""

from __future__ import annotations

import hmac
import os
import threading
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from aidac import __version__
from aidac.alert_store import (
    AlertStatus,
    AlertStoreError,
    filter_alerts,
    get_alert,
    load_alerts,
    update_alert_status,
)
from aidac.alerting import (
    DEFAULT_ALERT_LOG,
    DEFAULT_AUDIT_LOG,
    AlertingError,
    write_audit_event,
)

DEFAULT_API_TOKEN_ENV = "AIDAC_API_TOKEN"
MINIMUM_API_TOKEN_LENGTH = 32


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


class AlertListResponse(BaseModel):
    """Current alert collection response."""

    alert_count: int
    alerts: list[dict[str, Any]]


class AlertSummaryResponse(BaseModel):
    """Aggregate current alert counts."""

    alert_count: int
    status_counts: dict[str, int]
    severity_counts: dict[str, int]


def create_app(
    *,
    alert_log: Path = DEFAULT_ALERT_LOG,
    audit_log: Path = DEFAULT_AUDIT_LOG,
    token_env: str = DEFAULT_API_TOKEN_ENV,
) -> FastAPI:
    """Create a configured AI-DAC FastAPI application."""

    expanded_alert_log = alert_log.expanduser()
    expanded_audit_log = audit_log.expanduser()
    normalized_token_env = token_env.strip()
    if not normalized_token_env:
        raise ValueError("API token environment variable name cannot be empty.")

    bearer = HTTPBearer(auto_error=False)
    store_lock = threading.RLock()

    app = FastAPI(
        title="AI-DAC Alert API",
        version=__version__,
        description=("Authenticated, observation-only access to the AI-DAC alert lifecycle store."),
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    bearer_dependency = Depends(bearer)

    def require_api_token(
        credentials: HTTPAuthorizationCredentials | None = bearer_dependency,
    ) -> None:
        configured_token = os.getenv(normalized_token_env, "")
        if len(configured_token) < MINIMUM_API_TOKEN_LENGTH:
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

        if not hmac.compare_digest(credentials.credentials, configured_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    authentication = Depends(require_api_token)

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
        return JSONResponse(
            status_code=error_status,
            content={"detail": str(error)},
        )

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
        return {
            "service": "AI-DAC Alert API",
            "version": __version__,
            "documentation": "/docs",
        }

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
        token_configured = len(os.getenv(normalized_token_env, "")) >= MINIMUM_API_TOKEN_LENGTH
        alert_store_readable = True
        try:
            with store_lock:
                load_alerts(expanded_alert_log)
        except AlertStoreError:
            alert_store_readable = False

        response = ReadinessResponse(
            status=("ready" if token_configured and alert_store_readable else "not_ready"),
            version=__version__,
            token_configured=token_configured,
            alert_store_readable=alert_store_readable,
        )
        if response.status != "ready":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=response.model_dump(),
            )
        return response

    @app.get(
        "/api/v1/alerts/summary",
        response_model=AlertSummaryResponse,
        tags=["alerts"],
        dependencies=[authentication],
    )
    def alerts_summary() -> AlertSummaryResponse:
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
        dependencies=[authentication],
    )
    def alerts_list(
        alert_status: Annotated[
            AlertStatus | None,
            Query(alias="status", description="Optional lifecycle status filter."),
        ] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 50,
    ) -> AlertListResponse:
        with store_lock:
            alerts = filter_alerts(
                load_alerts(expanded_alert_log),
                status=alert_status,
                limit=limit,
            )
        return AlertListResponse(alert_count=len(alerts), alerts=alerts)

    @app.get(
        "/api/v1/alerts/{alert_id}",
        response_model=dict[str, Any],
        tags=["alerts"],
        dependencies=[authentication],
    )
    def alerts_show(alert_id: str) -> dict[str, Any]:
        with store_lock:
            return get_alert(expanded_alert_log, alert_id)

    @app.post(
        "/api/v1/alerts/{alert_id}/ack",
        response_model=dict[str, Any],
        tags=["alerts"],
        dependencies=[authentication],
    )
    def alerts_acknowledge(alert_id: str, action: AlertActionRequest) -> dict[str, Any]:
        return _change_alert_status(
            alert_id,
            action,
            target_status=AlertStatus.ACKNOWLEDGED,
        )

    @app.post(
        "/api/v1/alerts/{alert_id}/resolve",
        response_model=dict[str, Any],
        tags=["alerts"],
        dependencies=[authentication],
    )
    def alerts_resolve(alert_id: str, action: AlertActionRequest) -> dict[str, Any]:
        return _change_alert_status(
            alert_id,
            action,
            target_status=AlertStatus.RESOLVED,
        )

    def _change_alert_status(
        alert_id: str,
        action: AlertActionRequest,
        *,
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
                },
            )
        return alert

    return app
