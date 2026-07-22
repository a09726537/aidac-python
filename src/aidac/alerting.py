"""Persistent alert delivery and local audit helpers for AI-DAC."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from aidac import __version__
from aidac.alert_store import enrich_alert_record, persist_alert_batch, uses_database_store

DEFAULT_ALERT_LOG = Path("~/.local/state/aidac/alerts.db")
DEFAULT_AUDIT_LOG = Path("~/.local/state/aidac/audit.jsonl")
DEFAULT_WEBHOOK_SECRET_ENV = "AIDAC_WEBHOOK_SECRET"


class AlertingError(RuntimeError):
    """Raised when an alert cannot be persisted or delivered."""


@dataclass(frozen=True, slots=True)
class AuditVerification:
    """Result of verifying the local audit hash chain."""

    valid: bool
    records: int
    chained_records: int
    legacy_records: int
    failure_line: int | None = None
    message: str = "ok"


_AUDIT_LOCK = threading.RLock()
_AUDIT_GENESIS_HASH = "0" * 64


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
    """Build a uniquely identified alert batch with lifecycle metadata."""

    batch_id = secrets.token_hex(16)
    generated_at = utc_timestamp()
    alerts = [
        enrich_alert_record(
            record,
            batch_id=batch_id,
            generated_at=generated_at,
        )
        for record in records
    ]

    return {
        "type": "aidac_alert_batch",
        "batch_id": batch_id,
        "generated_at": generated_at,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


def append_alert_records(
    path: Path,
    batch: dict[str, Any],
) -> Path:
    """Append one JSONL record for every alert."""

    expanded_path = path.expanduser()
    if uses_database_store(expanded_path):
        persist_alert_batch(expanded_path, batch)
        return expanded_path

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
    """Append one structured audit event linked to the previous record hash."""

    expanded_path = path.expanduser()
    normalized_action = action.strip()
    normalized_status = status.strip()
    if not normalized_action or not normalized_status:
        raise AlertingError("Audit action and status cannot be empty.")

    with _AUDIT_LOCK:
        sequence, previous_hash = _audit_tail(expanded_path)
        record: dict[str, Any] = {
            "type": "aidac_audit_event",
            "sequence": sequence + 1,
            "timestamp": utc_timestamp(),
            "action": normalized_action,
            "status": normalized_status,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        record["record_hash"] = _audit_record_hash(record)
        _append_jsonl(expanded_path, [record])
    return expanded_path


def verify_audit_log(path: Path) -> AuditVerification:
    """Verify JSON syntax, sequence numbers and the tamper-evident audit chain."""

    expanded_path = path.expanduser()
    if not expanded_path.exists():
        return AuditVerification(
            valid=True,
            records=0,
            chained_records=0,
            legacy_records=0,
        )

    previous_hash = _AUDIT_GENESIS_HASH
    expected_sequence = 1
    chained_records = 0
    legacy_records = 0

    try:
        with expanded_path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    return AuditVerification(
                        valid=False,
                        records=line_number,
                        chained_records=chained_records,
                        legacy_records=legacy_records,
                        failure_line=line_number,
                        message="invalid_json",
                    )
                if not isinstance(payload, dict):
                    return AuditVerification(
                        valid=False,
                        records=line_number,
                        chained_records=chained_records,
                        legacy_records=legacy_records,
                        failure_line=line_number,
                        message="record_is_not_an_object",
                    )

                record_hash = payload.get("record_hash")
                supplied_previous = payload.get("previous_hash")
                supplied_sequence = payload.get("sequence")
                if not isinstance(record_hash, str):
                    legacy_records += 1
                    previous_hash = _sha256_json(payload)
                    expected_sequence += 1
                    continue

                if supplied_sequence != expected_sequence:
                    return AuditVerification(
                        valid=False,
                        records=line_number,
                        chained_records=chained_records,
                        legacy_records=legacy_records,
                        failure_line=line_number,
                        message="invalid_sequence",
                    )
                if supplied_previous != previous_hash:
                    return AuditVerification(
                        valid=False,
                        records=line_number,
                        chained_records=chained_records,
                        legacy_records=legacy_records,
                        failure_line=line_number,
                        message="previous_hash_mismatch",
                    )
                if not hmac.compare_digest(record_hash, _audit_record_hash(payload)):
                    return AuditVerification(
                        valid=False,
                        records=line_number,
                        chained_records=chained_records,
                        legacy_records=legacy_records,
                        failure_line=line_number,
                        message="record_hash_mismatch",
                    )

                chained_records += 1
                previous_hash = record_hash
                expected_sequence += 1
    except OSError as error:
        raise AlertingError(f"Unable to read audit log: {expanded_path}") from error

    total = chained_records + legacy_records
    return AuditVerification(
        valid=True,
        records=total,
        chained_records=chained_records,
        legacy_records=legacy_records,
    )


def _audit_tail(path: Path) -> tuple[int, str]:
    if not path.exists():
        return 0, _AUDIT_GENESIS_HASH

    last_payload: dict[str, Any] | None = None
    record_count = 0
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                record_count += 1
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as error:
                    raise AlertingError(f"Invalid JSON in audit log: {path}") from error
                if not isinstance(payload, dict):
                    raise AlertingError(f"Audit records must be JSON objects: {path}")
                last_payload = payload
    except OSError as error:
        raise AlertingError(f"Unable to read audit log: {path}") from error

    if last_payload is None:
        return 0, _AUDIT_GENESIS_HASH
    last_hash = last_payload.get("record_hash")
    return record_count, last_hash if isinstance(last_hash, str) else _sha256_json(last_payload)


def _audit_record_hash(record: dict[str, Any]) -> str:
    canonical = {key: value for key, value in record.items() if key != "record_hash"}
    return _sha256_json(canonical)


def _sha256_json(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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
            "User-Agent": f"aidac-sec/{__version__}",
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
