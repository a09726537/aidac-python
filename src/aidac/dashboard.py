"""Server-rendered web dashboard for the AI-DAC alert lifecycle store."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import secrets
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from aidac import __version__
from aidac.alert_store import (
    AlertStatus,
    AlertStoreError,
    get_alert,
    load_alerts,
    update_alert_status,
)
from aidac.alerting import write_audit_event

DEFAULT_DASHBOARD_TOKEN_ENV = "AIDAC_DASHBOARD_TOKEN"
MINIMUM_DASHBOARD_TOKEN_LENGTH = 32
DEFAULT_DASHBOARD_SESSION_MINUTES = 480
DASHBOARD_COOKIE_NAME = "aidac_dashboard_session"
_MAX_FORM_BYTES = 65_536
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_ALLOWED_REFRESH_SECONDS = {0, 15, 30, 60, 120}


@dataclass(frozen=True, slots=True)
class _DashboardSession:
    """Authenticated dashboard session metadata."""

    expires_at: int
    nonce: str


def install_dashboard_routes(
    app: FastAPI,
    *,
    alert_log: Path,
    audit_log: Path,
    token_env: str = DEFAULT_DASHBOARD_TOKEN_ENV,
    session_minutes: int = DEFAULT_DASHBOARD_SESSION_MINUTES,
    store_lock: Any,
) -> None:
    """Mount an authenticated, server-rendered dashboard on a FastAPI application."""

    expanded_alert_log = alert_log.expanduser()
    expanded_audit_log = audit_log.expanduser()
    normalized_token_env = token_env.strip()

    if not normalized_token_env:
        raise ValueError("Dashboard token environment variable name cannot be empty.")
    if not 5 <= session_minutes <= 1_440:
        raise ValueError("Dashboard session duration must be between 5 and 1440 minutes.")

    session_seconds = session_minutes * 60

    def configured_secret() -> str:
        secret = os.getenv(normalized_token_env, "")
        if len(secret) < MINIMUM_DASHBOARD_TOKEN_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Dashboard authentication is not configured.",
            )
        return secret

    def require_session(request: Request) -> _DashboardSession:
        session_cookie = request.cookies.get(DASHBOARD_COOKIE_NAME, "")
        session = _decode_session(session_cookie, configured_secret())
        if session is None:
            next_path = request.url.path
            if request.url.query:
                next_path = f"{next_path}?{request.url.query}"
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail=f"/dashboard/login?next={quote(next_path, safe='')}",
            )
        return session

    @app.exception_handler(HTTPException)
    async def dashboard_http_exception_handler(request: Request, error: HTTPException) -> Any:
        if request.url.path.startswith("/dashboard") and error.status_code == 303:
            return RedirectResponse(str(error.detail), status_code=303)
        from fastapi.exception_handlers import http_exception_handler

        return await http_exception_handler(request, error)

    @app.get("/dashboard/login", response_class=HTMLResponse, include_in_schema=False)
    def dashboard_login_page(
        request: Request,
        next_path: str = Query(default="/dashboard", alias="next"),
    ) -> Response:
        existing = request.cookies.get(DASHBOARD_COOKIE_NAME, "")
        try:
            authenticated = _decode_session(existing, configured_secret()) is not None
        except HTTPException:
            authenticated = False
        if authenticated:
            return _redirect(_safe_next_path(next_path))
        return _html_response(_login_page(next_path=_safe_next_path(next_path)))

    @app.post("/dashboard/login", include_in_schema=False)
    async def dashboard_login(request: Request) -> Response:
        form = await _read_form(request)
        supplied_token = form.get("token", "")
        next_path = _safe_next_path(form.get("next", "/dashboard"))
        secret = configured_secret()

        if not hmac.compare_digest(supplied_token, secret):
            return _html_response(
                _login_page(next_path=next_path, error="Invalid dashboard token."),
                status_code=401,
            )

        cookie_value = _encode_session(secret, ttl_seconds=session_seconds)
        response = _redirect(next_path)
        response.set_cookie(
            key=DASHBOARD_COOKIE_NAME,
            value=cookie_value,
            max_age=session_seconds,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            path="/dashboard",
        )
        return response

    @app.post("/dashboard/logout", include_in_schema=False)
    async def dashboard_logout(request: Request) -> RedirectResponse:
        session = require_session(request)
        form = await _read_form(request)
        _verify_csrf(form.get("csrf", ""), session, configured_secret())
        response = _redirect("/dashboard/login")
        response.delete_cookie(DASHBOARD_COOKIE_NAME, path="/dashboard")
        return response

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    def dashboard_home(
        request: Request,
        lifecycle_status: str | None = Query(default=None, alias="status"),
        severity: str | None = None,
        minimum_risk: float = Query(default=0.0, alias="min_risk", ge=0.0, le=1.0),
        search: str | None = Query(default=None, alias="q", max_length=200),
        limit: int = Query(default=100, ge=1, le=1_000),
        refresh: int = Query(default=30),
    ) -> HTMLResponse:
        session = require_session(request)
        normalized_status = _normalize_status(lifecycle_status)
        normalized_severity = _normalize_severity(severity)
        normalized_refresh = _normalize_refresh(refresh)

        with store_lock:
            alerts = load_alerts(expanded_alert_log)

        filtered = _filter_dashboard_alerts(
            alerts,
            lifecycle_status=normalized_status,
            severity=normalized_severity,
            minimum_risk=minimum_risk,
            search=search,
            limit=limit,
        )
        page = _dashboard_page(
            alerts=alerts,
            filtered=filtered,
            selected_status=normalized_status,
            selected_severity=normalized_severity,
            minimum_risk=minimum_risk,
            search=search or "",
            limit=limit,
            refresh=normalized_refresh,
            csrf=_csrf_token(session, configured_secret()),
        )
        return _html_response(page)

    @app.get(
        "/dashboard/alerts/{alert_id}",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def dashboard_alert_detail(request: Request, alert_id: str) -> HTMLResponse:
        session = require_session(request)
        try:
            with store_lock:
                alert = get_alert(expanded_alert_log, alert_id)
        except AlertStoreError as error:
            return _html_response(_error_page(str(error)), status_code=404)
        return _html_response(
            _alert_detail_page(
                alert,
                csrf=_csrf_token(session, configured_secret()),
            )
        )

    @app.post("/dashboard/alerts/{alert_id}/ack", include_in_schema=False)
    async def dashboard_acknowledge(request: Request, alert_id: str) -> RedirectResponse:
        return await _dashboard_change_status(
            request,
            alert_id,
            target_status=AlertStatus.ACKNOWLEDGED,
        )

    @app.post("/dashboard/alerts/{alert_id}/resolve", include_in_schema=False)
    async def dashboard_resolve(request: Request, alert_id: str) -> RedirectResponse:
        return await _dashboard_change_status(
            request,
            alert_id,
            target_status=AlertStatus.RESOLVED,
        )

    async def _dashboard_change_status(
        request: Request,
        alert_id: str,
        *,
        target_status: AlertStatus,
    ) -> RedirectResponse:
        session = require_session(request)
        form = await _read_form(request)
        secret = configured_secret()
        _verify_csrf(form.get("csrf", ""), session, secret)
        actor = form.get("actor", "dashboard-analyst").strip()
        note = form.get("note", "").strip() or None

        if not actor or len(actor) > 200:
            raise HTTPException(status_code=400, detail="Actor must contain 1 to 200 characters.")
        if note is not None and len(note) > 2_000:
            raise HTTPException(status_code=400, detail="Note cannot exceed 2000 characters.")

        try:
            with store_lock:
                update_alert_status(
                    expanded_alert_log,
                    alert_id,
                    status=target_status,
                    actor=actor,
                    note=note,
                )
                write_audit_event(
                    expanded_audit_log,
                    action=f"dashboard_alert_{target_status.value}",
                    status="success",
                    details={
                        "alert_id": alert_id,
                        "actor": actor,
                        "note": note,
                    },
                )
        except AlertStoreError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        return _redirect(f"/dashboard/alerts/{quote(alert_id, safe='')}")


def _encode_session(secret: str, *, ttl_seconds: int, now: int | None = None) -> str:
    issued_at = int(time.time()) if now is None else now
    expires_at = issued_at + ttl_seconds
    nonce = secrets.token_urlsafe(18)
    payload = f"v1.{expires_at}.{nonce}"
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{payload}.{encoded_signature}"


def _decode_session(
    value: str,
    secret: str,
    *,
    now: int | None = None,
) -> _DashboardSession | None:
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        return None

    _, raw_expiry, nonce, supplied_signature = parts
    try:
        expires_at = int(raw_expiry)
    except ValueError:
        return None

    payload = f"v1.{expires_at}.{nonce}"
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    expected_signature = base64.urlsafe_b64encode(expected).decode().rstrip("=")

    if not hmac.compare_digest(supplied_signature, expected_signature):
        return None
    current_time = int(time.time()) if now is None else now
    if expires_at <= current_time:
        return None
    return _DashboardSession(expires_at=expires_at, nonce=nonce)


def _csrf_token(session: _DashboardSession, secret: str) -> str:
    payload = f"csrf.{session.expires_at}.{session.nonce}"
    digest = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _verify_csrf(value: str, session: _DashboardSession, secret: str) -> None:
    if not value or not hmac.compare_digest(value, _csrf_token(session, secret)):
        raise HTTPException(status_code=403, detail="Invalid dashboard CSRF token.")


async def _read_form(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", maxsplit=1)[0].strip()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Form encoding is required.")

    body = await request.body()
    if len(body) > _MAX_FORM_BYTES:
        raise HTTPException(status_code=413, detail="Dashboard form is too large.")

    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Dashboard form is not UTF-8.") from error

    values = parse_qs(decoded, keep_blank_values=True, max_num_fields=20)
    return {key: items[-1] for key, items in values.items() if items}


def _safe_next_path(value: str) -> str:
    candidate = value.strip()
    if not candidate.startswith("/dashboard") or candidate.startswith("//"):
        return "/dashboard"
    return candidate


def _normalize_status(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().casefold()
    if normalized not in {item.value for item in AlertStatus}:
        raise HTTPException(status_code=400, detail="Invalid dashboard status filter.")
    return normalized


def _normalize_severity(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().casefold()
    if normalized not in _ALLOWED_SEVERITIES:
        raise HTTPException(status_code=400, detail="Invalid dashboard severity filter.")
    return normalized


def _normalize_refresh(value: int) -> int:
    if value not in _ALLOWED_REFRESH_SECONDS:
        raise HTTPException(status_code=400, detail="Invalid dashboard refresh interval.")
    return value


def _filter_dashboard_alerts(
    alerts: list[dict[str, Any]],
    *,
    lifecycle_status: str | None,
    severity: str | None,
    minimum_risk: float,
    search: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    normalized_search = "" if search is None else search.strip().casefold()
    filtered: list[dict[str, Any]] = []

    for alert in alerts:
        if lifecycle_status is not None and str(alert.get("status", "")) != lifecycle_status:
            continue
        if severity is not None and str(alert.get("severity", "")).casefold() != severity:
            continue
        try:
            risk_score = float(alert.get("risk_score", 0.0))
        except (TypeError, ValueError):
            risk_score = 0.0
        if risk_score < minimum_risk:
            continue
        if normalized_search:
            searchable = " ".join(
                str(alert.get(field, ""))
                for field in (
                    "alert_id",
                    "username",
                    "database",
                    "client_ip",
                    "classification",
                    "query",
                )
            ).casefold()
            if normalized_search not in searchable:
                continue
        filtered.append(alert)
        if len(filtered) >= limit:
            break
    return filtered


def _html_response(content: str, *, status_code: int = 200) -> HTMLResponse:
    response = HTMLResponse(content, status_code=status_code)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "script-src 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=303)


def _layout(title: str, body: str, *, refresh: int = 0) -> str:
    refresh_tag = "" if refresh == 0 else f'<meta http-equiv="refresh" content="{refresh}">'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh_tag}
<title>{html.escape(title)} · AI-DAC</title>
<style>
:root {{ color-scheme: dark; --bg:#0b1220; --panel:#111b2e; --panel2:#17233a;
--text:#edf4ff; --muted:#9eb0c9; --accent:#55d6be; --danger:#ff6b6b; --warn:#ffd166;
--line:#263852; --blue:#63a7ff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:linear-gradient(145deg,#07101e,#101a2d); color:var(--text);
font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif; min-height:100vh; }}
a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
header {{ border-bottom:1px solid var(--line); background:rgba(7,16,30,.92); padding:18px 0; }}
.container {{ width:min(1200px,94vw); margin:0 auto; }}
.brand {{ display:flex; align-items:center; justify-content:space-between; gap:18px; }}
.brand h1 {{ margin:0; font-size:22px; letter-spacing:.4px; }}
.brand small {{ color:var(--muted); }}
nav {{ display:flex; gap:14px; align-items:center; }}
main {{ padding:28px 0 50px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:14px; }}
.card {{ background:rgba(17,27,46,.94); border:1px solid var(--line); border-radius:14px;
padding:18px; box-shadow:0 12px 30px rgba(0,0,0,.18); }}
.metric {{ font-size:31px; font-weight:750; margin-top:6px; }}
.muted {{ color:var(--muted); }}
.filters {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px;
align-items:end; }}
label {{ display:block; color:var(--muted); font-size:13px; margin-bottom:5px; }}
input,select,button {{ width:100%; border:1px solid var(--line); border-radius:9px; padding:10px 11px;
background:#0b1425; color:var(--text); font:inherit; }}
button {{ cursor:pointer; background:#17334a; border-color:#2e5f78; font-weight:650; }}
button:hover {{ background:#20465f; }}
button.danger {{ background:#4a2026; border-color:#7d3941; }}
.inline {{ display:inline-block; width:auto; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th,td {{ text-align:left; padding:11px 9px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; }}
.table-wrap {{ overflow-x:auto; }}
.badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:12px;
background:#203047; border:1px solid #344c6a; }}
.badge-critical {{ color:#ffb4b4; border-color:#7d3941; }} .badge-high {{ color:#ffd3a4; }}
.badge-new {{ color:#9bdcff; }} .badge-acknowledged {{ color:#ffe099; }}
.badge-resolved {{ color:#9ee8c8; }}
.query {{ max-width:390px; white-space:normal; overflow-wrap:anywhere; }}
.section-title {{ display:flex; justify-content:space-between; align-items:end; gap:12px; margin:26px 0 12px; }}
.section-title h2 {{ margin:0; font-size:19px; }}
.bars {{ display:grid; gap:9px; }} .bar-row {{ display:grid; grid-template-columns:90px 1fr 48px; gap:9px;
align-items:center; }} .bar-track {{ height:10px; background:#0b1425; border-radius:999px; overflow:hidden; }}
.bar-fill {{ height:100%; background:linear-gradient(90deg,var(--blue),var(--accent)); }}
pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#08111f; border:1px solid var(--line);
padding:14px; border-radius:10px; }}
.actions {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }}
.error {{ border-color:#7d3941; color:#ffd1d1; }}
footer {{ color:var(--muted); padding:20px 0 30px; text-align:center; }}
@media (max-width:700px) {{ .brand {{ align-items:flex-start; flex-direction:column; }}
th:nth-child(3),td:nth-child(3),th:nth-child(5),td:nth-child(5) {{ display:none; }} }}
</style>
</head>
<body>
<header><div class="container brand"><div><h1>AI-DAC Security Operations</h1>
<small>Alert lifecycle dashboard · v{html.escape(__version__)}</small></div>
<nav><a href="/dashboard">Dashboard</a><a href="/docs">API docs</a></nav></div></header>
<main><div class="container">{body}</div></main>
<footer>Observation-only database cybersecurity monitoring</footer>
</body></html>"""


def _login_page(*, next_path: str, error: str | None = None) -> str:
    error_block = "" if error is None else f'<div class="card error">{html.escape(error)}</div>'
    body = f"""
<div style="max-width:480px;margin:55px auto">
{error_block}
<div class="card">
<h2>Dashboard sign in</h2>
<p class="muted">Use the separate dashboard token. The REST API bearer token is never stored in
browser JavaScript.</p>
<form method="post" action="/dashboard/login">
<input type="hidden" name="next" value="{html.escape(next_path, quote=True)}">
<label for="token">Dashboard token</label>
<input id="token" name="token" type="password" minlength="32" required autocomplete="current-password">
<div style="height:12px"></div><button type="submit">Open dashboard</button>
</form>
</div></div>"""
    return _layout("Dashboard sign in", body)


def _dashboard_page(
    *,
    alerts: list[dict[str, Any]],
    filtered: list[dict[str, Any]],
    selected_status: str | None,
    selected_severity: str | None,
    minimum_risk: float,
    search: str,
    limit: int,
    refresh: int,
    csrf: str,
) -> str:
    status_counts = Counter(str(item.get("status", "unknown")) for item in alerts)
    severity_counts = Counter(str(item.get("severity", "unknown")) for item in alerts)
    urgent = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

    cards = "".join(
        _metric_card(label, value)
        for label, value in (
            ("Total alerts", len(alerts)),
            ("New", status_counts.get("new", 0)),
            ("Acknowledged", status_counts.get("acknowledged", 0)),
            ("Resolved", status_counts.get("resolved", 0)),
            ("High + critical", urgent),
        )
    )

    max_severity = max(severity_counts.values(), default=1)
    bars = "".join(
        _severity_bar(name, severity_counts.get(name, 0), max_severity)
        for name in ("critical", "high", "medium", "low", "info")
    )
    rows = "".join(_alert_row(alert) for alert in filtered)
    if not rows:
        rows = '<tr><td colspan="7" class="muted">No alerts match the selected filters.</td></tr>'

    status_options = _options(
        [
            ("", "All statuses"),
            ("new", "New"),
            ("acknowledged", "Acknowledged"),
            ("resolved", "Resolved"),
        ],
        selected_status or "",
    )
    severity_options = _options(
        [
            ("", "All severities"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        ],
        selected_severity or "",
    )
    refresh_options = _options(
        [
            ("0", "Off"),
            ("15", "15 seconds"),
            ("30", "30 seconds"),
            ("60", "60 seconds"),
            ("120", "2 minutes"),
        ],
        str(refresh),
    )

    body = f"""
<div class="grid">{cards}</div>
<div class="section-title"><h2>Severity distribution</h2><span class="muted">Current lifecycle state</span></div>
<div class="card bars">{bars}</div>
<div class="section-title"><h2>Alert explorer</h2><span class="muted">Showing {len(filtered)} alerts</span></div>
<div class="card">
<form method="get" action="/dashboard" class="filters">
<div><label>Status</label><select name="status">{status_options}</select></div>
<div><label>Severity</label><select name="severity">{severity_options}</select></div>
<div><label>Minimum risk</label><input name="min_risk" type="number" min="0" max="1" step="0.05"
value="{minimum_risk:.2f}"></div>
<div><label>Search</label><input name="q" maxlength="200" value="{html.escape(search, quote=True)}"
placeholder="user, database, IP, SQL…"></div>
<div><label>Limit</label><input name="limit" type="number" min="1" max="1000" value="{limit}"></div>
<div><label>Auto-refresh</label><select name="refresh">{refresh_options}</select></div>
<div><button type="submit">Apply filters</button></div>
</form>
</div>
<div class="card table-wrap" style="margin-top:14px">
<table><thead><tr><th>Severity</th><th>Status</th><th>Risk</th><th>Identity</th><th>Database</th>
<th>Last seen</th><th>Query</th></tr></thead><tbody>{rows}</tbody></table>
</div>
<div style="margin-top:18px;text-align:right">
<form method="post" action="/dashboard/logout" class="inline">
<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
<button type="submit" class="inline">Sign out</button></form></div>"""
    return _layout("Dashboard", body, refresh=refresh)


def _metric_card(label: str, value: int) -> str:
    return f'<div class="card"><div class="muted">{html.escape(label)}</div><div class="metric">{value}</div></div>'


def _severity_bar(name: str, value: int, maximum: int) -> str:
    width = 0 if maximum <= 0 else round(value / maximum * 100)
    return (
        f'<div class="bar-row"><span>{html.escape(name.title())}</span><div class="bar-track">'
        f'<div class="bar-fill" style="width:{width}%"></div></div><strong>{value}</strong></div>'
    )


def _alert_row(alert: dict[str, Any]) -> str:
    alert_id = str(alert.get("alert_id", ""))
    severity = str(alert.get("severity", "unknown"))
    lifecycle_status = str(alert.get("status", "unknown"))
    query_text = " ".join(str(alert.get("query", "")).split())
    if len(query_text) > 120:
        query_text = f"{query_text[:117]}..."
    try:
        risk = float(alert.get("risk_score", 0.0))
    except (TypeError, ValueError):
        risk = 0.0
    identity = html.escape(str(alert.get("username", "unknown")))
    client_ip = str(alert.get("client_ip", ""))
    if client_ip:
        identity = f'{identity}<br><span class="muted">{html.escape(client_ip)}</span>'
    return f"""<tr>
<td><span class="badge badge-{html.escape(severity)}">{html.escape(severity)}</span></td>
<td><span class="badge badge-{html.escape(lifecycle_status)}">{html.escape(lifecycle_status)}</span></td>
<td>{risk:.3f}</td><td>{identity}</td><td>{html.escape(str(alert.get("database", "")))}</td>
<td>{html.escape(str(alert.get("last_seen", "")))}</td>
<td class="query"><a href="/dashboard/alerts/{quote(alert_id, safe="")}">{html.escape(query_text or alert_id)}</a></td>
</tr>"""


def _alert_detail_page(alert: dict[str, Any], *, csrf: str) -> str:
    alert_id = str(alert.get("alert_id", ""))
    lifecycle_status = str(alert.get("status", "unknown"))
    severity = str(alert.get("severity", "unknown"))
    fields = (
        ("Alert ID", alert_id),
        ("Status", lifecycle_status),
        ("Severity", severity),
        ("Risk score", alert.get("risk_score", "")),
        ("Classification", alert.get("classification", "")),
        ("Username", alert.get("username", "")),
        ("Database", alert.get("database", "")),
        ("Client IP", alert.get("client_ip", "")),
        ("Occurrences", alert.get("occurrence_count", 1)),
        ("First seen", alert.get("first_seen", "")),
        ("Last seen", alert.get("last_seen", "")),
        ("Updated by", alert.get("updated_by", "")),
        ("Status note", alert.get("status_note", "")),
    )
    rows = "".join(
        f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(value))}</td></tr>"
        for label, value in fields
    )
    query_text = html.escape(str(alert.get("query", "")))
    action_forms = ""
    if lifecycle_status != AlertStatus.RESOLVED.value:
        acknowledge = ""
        if lifecycle_status != AlertStatus.ACKNOWLEDGED.value:
            acknowledge = _action_form(alert_id, "ack", "Acknowledge", csrf, danger=False)
        resolve = _action_form(alert_id, "resolve", "Resolve", csrf, danger=True)
        action_forms = f'<div class="section-title"><h2>Lifecycle actions</h2></div><div class="actions">{acknowledge}{resolve}</div>'

    body = f"""
<p><a href="/dashboard">← Back to dashboard</a></p>
<div class="section-title"><h2>Alert detail</h2><span class="badge badge-{html.escape(severity)}">{html.escape(severity)}</span></div>
<div class="card table-wrap"><table><tbody>{rows}</tbody></table></div>
<div class="section-title"><h2>SQL evidence</h2></div><pre>{query_text}</pre>
{action_forms}"""
    return _layout(f"Alert {alert_id}", body)


def _action_form(
    alert_id: str,
    action: str,
    label: str,
    csrf: str,
    *,
    danger: bool,
) -> str:
    button_class = "danger" if danger else ""
    return f"""<div class="card"><h3>{html.escape(label)} alert</h3>
<form method="post" action="/dashboard/alerts/{quote(alert_id, safe="")}/{html.escape(action)}">
<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
<label>Actor</label><input name="actor" value="dashboard-analyst" maxlength="200" required>
<label style="margin-top:10px">Note</label><input name="note" maxlength="2000" placeholder="Optional review note">
<div style="height:12px"></div><button class="{button_class}" type="submit">{html.escape(label)}</button>
</form></div>"""


def _options(options: list[tuple[str, str]], selected: str) -> str:
    rendered: list[str] = []
    for value, label in options:
        selected_attribute = " selected" if value == selected else ""
        rendered.append(
            f'<option value="{html.escape(value, quote=True)}"{selected_attribute}>{html.escape(label)}</option>'
        )
    return "".join(rendered)


def _error_page(message: str) -> str:
    body = f'<div class="card error"><h2>Dashboard error</h2><p>{html.escape(message)}</p></div>'
    return _layout("Dashboard error", body)
