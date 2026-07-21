"""Tests for the AI-DAC API command group."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aidac.api_cli import _validate_transport
from aidac.cli import app

runner = CliRunner()


def test_api_group_is_available() -> None:
    """The main CLI should expose the API server command."""

    result = runner.invoke(app, ["api", "--help"])

    assert result.exit_code == 0
    assert "serve" in result.output


def test_api_server_requires_token(monkeypatch: object) -> None:
    """The API must fail before startup when no strong token exists."""

    monkeypatch.delenv("AIDAC_API_TOKEN", raising=False)  # type: ignore[attr-defined]

    result = runner.invoke(app, ["api", "serve"])

    assert result.exit_code == 1
    assert "at least 32 characters" in result.output


def test_remote_binding_requires_explicit_tls(tmp_path: Path) -> None:
    """A non-loopback listener should require opt-in and TLS material."""

    certificate = tmp_path / "cert.pem"
    private_key = tmp_path / "key.pem"
    certificate.write_text("certificate", encoding="utf-8")
    private_key.write_text("private-key", encoding="utf-8")

    try:
        _validate_transport(
            host="0.0.0.0",
            allow_remote=False,
            ssl_certfile=certificate,
            ssl_keyfile=private_key,
        )
    except ValueError as error:
        assert "--allow-remote" in str(error)
    else:
        raise AssertionError("Remote binding unexpectedly passed without --allow-remote")

    selected_certificate, selected_key = _validate_transport(
        host="0.0.0.0",
        allow_remote=True,
        ssl_certfile=certificate,
        ssl_keyfile=private_key,
    )

    assert selected_certificate == certificate
    assert selected_key == private_key
