"""Persistent alert delivery and local audit helpers for AI-DAC."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_ALERT_LOG = Path("~/.local/state/aidac/alerts.jsonl")
DEFAULT_AUDIT_LOG = Path("~/.local/state/aidac/audit.jsonl")
DEFAULT_WEBHOOK_SECRET_ENV = "AIDAC_WEBHOOK_SECRET"


class AlertingError(RuntimeError):
    """Raised when an alert cannot be persisted or delivered."""


@dataclass(frozen=True, slots=True)
class WebhookSettings:
    """Validated HTTPS webhook settings."""

    url: str
    secret_env: str = DEFAULT_WEBHOOK_SECRET_ENV
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        """Normalize and validate webhook settings."""

        normalized_url = self.url.strip()
        normalized_secret_env = self.secret_env.strip()

        object.__setattr__(self, "url", normalized_url)
        object.__setattr__(
            self,
            "secret_env",
            normalized_secret_env,
        )

        parsed = urlparse(normalized_url)

        if parsed.scheme.casefold() != "https":
            raise AlertingError("Webhook URL must use HTTPS.")

        if not parsed.netloc:
            raise AlertingError("Webhook URL must include a host.")

        if not normalized_secret_env:
            raise AlertingError("Webhook secret environment name cannot be empty.")

        if not 0.5 <= self.timeout_seconds <= 60.0:
            raise AlertingError("Webhook timeout must be between 0.5 and 60 seconds.")


def utc_timestamp() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return datetime.now(UTC).isoformat()


def build_alert_batch(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a uniquely identified alert batch."""

    return {
        "type": "aidac_alert_batch",
        "batch_id": secrets.token_hex(16),
        "generated_at": utc_timestamp(),
        "alert_count": len(records),
        "alerts": records,
    }


def append_alert_records(
    path: Path,
    batch: dict[str, Any],
) -> Path:
    """Append one JSONL record for every alert."""

    expanded_path = path.expanduser()
    alerts = batch.get("alerts", [])

    if not isinstance(alerts, list):
        raise AlertingError("Alert batch does not contain a valid alerts list.")

    records: list[dict[str, Any]] = []

    for alert in alerts:
        if not isinstance(alert, dict):
            raise AlertingError("Alert records must be JSON objects.")

        records.append(
            {
                "type": "aidac_alert",
                "batch_id": batch["batch_id"],
                "generated_at": batch["generated_at"],
                **alert,
            }
        )

    _append_jsonl(expanded_path, records)
    return expanded_path


def write_audit_event(
    path: Path,
    *,
    action: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> Path:
    """Append one structured local audit event."""

    expanded_path = path.expanduser()

    record = {
        "type": "aidac_audit_event",
        "timestamp": utc_timestamp(),
        "action": action,
        "status": status,
        "details": details or {},
    }

    _append_jsonl(expanded_path, [record])
    return expanded_path


def write_batch_export(
    directory: Path,
    batch: dict[str, Any],
) -> Path:
    """Write one private JSON export for an alert batch."""

    expanded_directory = directory.expanduser()
    _ensure_private_directory(expanded_directory)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    batch_id = str(batch.get("batch_id", "unknown"))[:12]
    output_file = expanded_directory / (f"aidac-alerts-{timestamp}-{batch_id}.json")
    temporary_file = output_file.with_suffix(output_file.suffix + ".tmp")

    try:
        temporary_file.write_text(
            json.dumps(
                batch,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary_file.chmod(0o600)
        temporary_file.replace(output_file)
        output_file.chmod(0o600)
    except OSError as error:
        raise AlertingError(f"Unable to write alert export: {output_file}") from error

    return output_file


def resolve_webhook_secret(
    settings: WebhookSettings,
) -> str:
    """Read the webhook secret from its environment variable."""

    secret = os.getenv(settings.secret_env, "")

    if not secret:
        raise AlertingError(
            f"Webhook secret is missing from environment variable {settings.secret_env}."
        )

    return secret


def send_signed_webhook(
    settings: WebhookSettings,
    batch: dict[str, Any],
) -> int:
    """Send a signed JSON alert batch to an HTTPS webhook."""

    secret = resolve_webhook_secret(settings)
    body = json.dumps(
        batch,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    timestamp = str(int(datetime.now(UTC).timestamp()))
    signed_message = timestamp.encode("ascii") + b"." + body
    signature = hmac.new(
        secret.encode("utf-8"),
        signed_message,
        hashlib.sha256,
    ).hexdigest()

    request = Request(
        settings.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aidac-sec/0.6",
            "X-AIDAC-Timestamp": timestamp,
            "X-AIDAC-Signature": f"sha256={signature}",
        },
    )

    try:
        with urlopen(
            request,
            timeout=settings.timeout_seconds,
        ) as response:
            status = int(response.status)
    except HTTPError as error:
        raise AlertingError(f"Webhook returned HTTP {error.code}.") from error
    except URLError as error:
        raise AlertingError(f"Webhook connection failed: {error.reason}") from error
    except OSError as error:
        raise AlertingError("Webhook delivery failed.") from error

    if not 200 <= status < 300:
        raise AlertingError(f"Webhook returned unexpected HTTP {status}.")

    return status


def _append_jsonl(
    path: Path,
    records: list[dict[str, Any]],
) -> None:
    """Append JSON objects to a private JSONL file."""

    if not records:
        return

    _ensure_private_directory(path.parent)

    payload = "".join(
        json.dumps(
            record,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
        for record in records
    ).encode("utf-8")

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND

    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        path.chmod(0o600)
    except OSError as error:
        raise AlertingError(f"Unable to append JSONL file: {path}") from error


def _ensure_private_directory(path: Path) -> None:
    """Create a directory with private permissions."""

    try:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as error:
        raise AlertingError(f"Unable to prepare private directory: {path}") from error
