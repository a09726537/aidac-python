"""Tests for the server-rendered AI-DAC web dashboard."""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from aidac.alert_store import persist_alert_batch
from aidac.alerting import build_alert_batch
from aidac.api import create_app
from aidac.dashboard import _decode_session, _encode_session

_API_TOKEN = "api-token-0123456789-abcdefghijklmnopqrstuvwxyz"
_DASHBOARD_TOKEN = "dashboard-token-0123456789-abcdefghijklmnopqrstuvwxyz"


def _records() -> list[dict[str, object]]:
    return [
        {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "username": "security_test",
            "database": "sales",
            "source_system": "postgresql",
            "client_ip": "192.0.2.10",
            "query": "DROP TABLE customers;",
            "risk_score": 0.95,
            "severity": "critical",
            "classification": "destructive_sql",
        },
        {
            "timestamp": "2026-01-01T00:01:00+00:00",
            "username": "reporting",
            "database": "warehouse",
            "source_system": "postgresql",
            "client_ip": "192.0.2.20",
            "query": "SELECT * FROM daily_sales;",
            "risk_score": 0.25,
            "severity": "low",
            "classification": "unusual_read",
        },
        {
            "timestamp": "2026-01-01T00:02:00+00:00",
            "username": "<script>alert(1)</script>",
            "database": "finance",
            "source_system": "postgresql",
            "client_ip": "192.0.2.30",
            "query": "ALTER ROLE admin SUPERUSER;",
            "risk_score": 0.84,
            "severity": "high",
            "classification": "privilege_escalation",
        },
    ]


def _client(tmp_path: Path, monkeypatch: object) -> tuple[TestClient, Path, Path]:
    alert_log = tmp_path / "alerts.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AIDAC_API_TOKEN", _API_TOKEN)  # type: ignore[attr-defined]
    monkeypatch.setenv("AIDAC_DASHBOARD_TOKEN", _DASHBOARD_TOKEN)  # type: ignore[attr-defined]
    persist_alert_batch(alert_log, build_alert_batch(_records()))
    application = create_app(
        alert_log=alert_log,
        audit_log=audit_log,
        dashboard_enabled=True,
    )
    return TestClient(application), alert_log, audit_log


def _login(client: TestClient) -> None:
    response = client.post(
        "/dashboard/login",
        data={"token": _DASHBOARD_TOKEN, "next": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def _csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', page)
    assert match is not None
    return match.group(1)


def test_dashboard_is_disabled_by_default(tmp_path: Path, monkeypatch: object) -> None:
    """The REST API should remain backward compatible unless the dashboard is enabled."""

    monkeypatch.setenv("AIDAC_API_TOKEN", _API_TOKEN)  # type: ignore[attr-defined]
    client = TestClient(
        create_app(alert_log=tmp_path / "alerts.jsonl", audit_log=tmp_path / "audit.jsonl")
    )

    assert client.get("/dashboard").status_code == 404


def test_dashboard_redirects_unauthenticated_users(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    """Unauthenticated browser requests should be redirected to the sign-in page."""

    client, _, _ = _client(tmp_path, monkeypatch)

    response = client.get("/dashboard?severity=critical", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/dashboard/login?next=")


def test_invalid_dashboard_login_fails_closed(tmp_path: Path, monkeypatch: object) -> None:
    """An invalid dashboard token must not create a session."""

    client, _, _ = _client(tmp_path, monkeypatch)

    response = client.post(
        "/dashboard/login",
        data={"token": "incorrect", "next": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert "Invalid dashboard token" in response.text
    assert "aidac_dashboard_session" not in response.cookies


def test_login_cookie_is_http_only_and_does_not_expose_tokens(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    """The browser should receive only an opaque signed session cookie."""

    client, _, _ = _client(tmp_path, monkeypatch)

    response = client.post(
        "/dashboard/login",
        data={"token": _DASHBOARD_TOKEN, "next": "/dashboard"},
        follow_redirects=False,
    )

    cookie_header = response.headers["set-cookie"]
    assert response.status_code == 303
    assert "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header
    assert _API_TOKEN not in cookie_header
    assert _DASHBOARD_TOKEN not in cookie_header


def test_dashboard_displays_statistics_filters_and_escaped_data(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    """The dashboard should render statistics and server-side filtered alerts safely."""

    client, _, _ = _client(tmp_path, monkeypatch)
    _login(client)

    response = client.get(
        "/dashboard",
        params={"severity": "critical", "min_risk": "0.90", "q": "drop", "refresh": "0"},
    )

    assert response.status_code == 200
    assert "Total alerts" in response.text
    assert ">3<" in response.text
    assert "DROP TABLE customers" in response.text
    assert "SELECT * FROM daily_sales" not in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "script-src 'none'" in response.headers["content-security-policy"]

    unfiltered = client.get("/dashboard", params={"refresh": "0"})
    assert "<script>alert(1)</script>" not in unfiltered.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in unfiltered.text


def test_dashboard_alert_detail_and_acknowledgement_are_audited(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    """Lifecycle actions from the dashboard should update the store and audit log."""

    client, alert_log, audit_log = _client(tmp_path, monkeypatch)
    alert_id = str(json.loads(alert_log.read_text(encoding="utf-8").splitlines()[0])["alert_id"])
    _login(client)

    detail = client.get(f"/dashboard/alerts/{alert_id}")
    response = client.post(
        f"/dashboard/alerts/{alert_id}/ack",
        data={
            "csrf": _csrf(detail.text),
            "actor": "soc-analyst",
            "note": "Reviewed in dashboard",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    updated = client.get(f"/dashboard/alerts/{alert_id}")
    assert "acknowledged" in updated.text
    assert "soc-analyst" in updated.text
    audit_actions = {
        json.loads(line)["action"] for line in audit_log.read_text(encoding="utf-8").splitlines()
    }
    assert "dashboard_alert_acknowledged" in audit_actions


def test_dashboard_resolution_requires_valid_csrf(tmp_path: Path, monkeypatch: object) -> None:
    """Dashboard mutation forms must reject missing or forged CSRF tokens."""

    client, alert_log, _ = _client(tmp_path, monkeypatch)
    alert_id = str(json.loads(alert_log.read_text(encoding="utf-8").splitlines()[0])["alert_id"])
    _login(client)

    response = client.post(
        f"/dashboard/alerts/{alert_id}/resolve",
        data={"actor": "soc-analyst", "csrf": "forged"},
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_dashboard_logout_clears_session(tmp_path: Path, monkeypatch: object) -> None:
    """Signing out should invalidate the browser session cookie."""

    client, _, _ = _client(tmp_path, monkeypatch)
    _login(client)
    dashboard = client.get("/dashboard?refresh=0")

    response = client.post(
        "/dashboard/logout",
        data={"csrf": _csrf(dashboard.text)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_dashboard_session_signatures_expire_and_reject_tampering() -> None:
    """Signed dashboard sessions should be opaque, tamper evident and time limited."""

    session = _encode_session(_DASHBOARD_TOKEN, ttl_seconds=60, now=1_000)

    assert _decode_session(session, _DASHBOARD_TOKEN, now=1_030) is not None
    assert _decode_session(session, _DASHBOARD_TOKEN, now=1_061) is None
    assert _decode_session(f"{session}x", _DASHBOARD_TOKEN, now=1_030) is None
