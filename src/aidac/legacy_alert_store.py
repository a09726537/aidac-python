"""Persistent alert lifecycle and deduplication for AI-DAC."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any


class AlertStoreError(RuntimeError):
    """Raised when an alert store operation fails."""


class AlertStatus(StrEnum):
    """Supported alert lifecycle states."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


_STATUS_VALUES = {status.value for status in AlertStatus}
_FINGERPRINT_FIELDS = (
    "source_system",
    "database",
    "username",
    "client_ip",
    "classification",
    "query",
)


def alert_fingerprint(record: dict[str, Any]) -> str:
    """Return a stable fingerprint for deduplicating equivalent alerts."""

    identity: dict[str, str] = {}

    for field in _FINGERPRINT_FIELDS:
        value = record.get(field)
        normalized = "" if value is None else str(value).strip()
        if field == "query":
            normalized = " ".join(normalized.split()).casefold()
        else:
            normalized = normalized.casefold()
        identity[field] = normalized

    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def alert_identifier(record: dict[str, Any]) -> str:
    """Return a deterministic public alert identifier."""

    fingerprint = str(record.get("fingerprint") or alert_fingerprint(record))
    return f"alrt_{fingerprint[:24]}"


def enrich_alert_record(
    record: dict[str, Any],
    *,
    batch_id: str,
    generated_at: str,
    status: AlertStatus = AlertStatus.NEW,
) -> dict[str, Any]:
    """Add lifecycle metadata to one alert record."""

    enriched = dict(record)
    fingerprint = alert_fingerprint(enriched)
    event_time = _text_timestamp(enriched.get("timestamp"), generated_at)

    enriched.update(
        {
            "type": "aidac_alert",
            "alert_id": alert_identifier({"fingerprint": fingerprint}),
            "fingerprint": fingerprint,
            "batch_id": batch_id,
            "generated_at": generated_at,
            "status": status.value,
            "occurrence_count": 1,
            "first_seen": event_time,
            "last_seen": event_time,
        }
    )
    return enriched


def persist_alert_batch(
    path: Path,
    batch: dict[str, Any],
) -> list[dict[str, Any]]:
    """Persist a batch, deduplicate occurrences and return current alert states."""

    expanded_path = path.expanduser()
    raw_alerts = batch.get("alerts", [])

    if not isinstance(raw_alerts, list):
        raise AlertStoreError("Alert batch does not contain a valid alerts list.")

    batch_id = str(batch.get("batch_id", "")).strip()
    generated_at = _text_timestamp(batch.get("generated_at"), _utc_timestamp())

    if not batch_id:
        raise AlertStoreError("Alert batch does not contain a batch_id.")

    current = {alert["alert_id"]: alert for alert in load_alerts(expanded_path)}
    append_records: list[dict[str, Any]] = []

    for raw_alert in raw_alerts:
        if not isinstance(raw_alert, dict):
            raise AlertStoreError("Alert records must be JSON objects.")

        preliminary = enrich_alert_record(
            raw_alert,
            batch_id=batch_id,
            generated_at=generated_at,
        )
        alert_id = str(preliminary["alert_id"])
        existing = current.get(alert_id)
        status = AlertStatus.NEW

        if existing is not None:
            existing_status = _parse_status(existing.get("status"))
            status = AlertStatus.NEW if existing_status is AlertStatus.RESOLVED else existing_status

        occurrence = enrich_alert_record(
            raw_alert,
            batch_id=batch_id,
            generated_at=generated_at,
            status=status,
        )
        append_records.append(occurrence)

        if existing is not None and _parse_status(existing.get("status")) is AlertStatus.RESOLVED:
            append_records.append(
                _status_update_record(
                    alert_id,
                    status=AlertStatus.NEW,
                    action="reopened",
                    actor="system",
                    note="A new matching database event reopened the resolved alert.",
                )
            )

    _append_jsonl(expanded_path, append_records)
    return load_alerts(expanded_path)


def load_alerts(path: Path) -> list[dict[str, Any]]:
    """Replay a v0.6+ JSONL alert log into current alert states."""

    expanded_path = path.expanduser()
    if not expanded_path.exists():
        return []

    states: dict[str, dict[str, Any]] = {}

    try:
        with expanded_path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as error:
                    raise AlertStoreError(
                        f"Invalid JSON in alert log {expanded_path} at line {line_number}."
                    ) from error

                if not isinstance(record, dict):
                    raise AlertStoreError(
                        f"Alert log record at line {line_number} must be a JSON object."
                    )

                record_type = str(record.get("type", "aidac_alert"))
                if record_type == "aidac_alert_update":
                    _apply_update(states, record)
                elif record_type == "aidac_alert":
                    normalized = _normalize_loaded_alert(record)
                    _merge_occurrence(states, normalized)
    except OSError as error:
        raise AlertStoreError(f"Unable to read alert log: {expanded_path}") from error

    return sorted(
        states.values(),
        key=lambda alert: _timestamp_sort_key(alert.get("last_seen")),
        reverse=True,
    )


def get_alert(path: Path, alert_id: str) -> dict[str, Any]:
    """Return one alert by identifier."""

    normalized_id = alert_id.strip()
    for alert in load_alerts(path):
        if alert.get("alert_id") == normalized_id:
            return alert
    raise AlertStoreError(f"Alert not found: {normalized_id}")


def filter_alerts(
    alerts: list[dict[str, Any]],
    *,
    status: AlertStatus | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Filter and limit current alerts."""

    if not 1 <= limit <= 100_000:
        raise AlertStoreError("Alert list limit must be between 1 and 100000.")

    filtered = alerts
    if status is not None:
        filtered = [alert for alert in alerts if alert.get("status") == status.value]
    return filtered[:limit]


def update_alert_status(
    path: Path,
    alert_id: str,
    *,
    status: AlertStatus,
    actor: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Append an acknowledged or resolved lifecycle transition."""

    expanded_path = path.expanduser()
    current = get_alert(expanded_path, alert_id)
    current_status = _parse_status(current.get("status"))

    if status is AlertStatus.NEW:
        raise AlertStoreError("Use automatic event detection to reopen an alert.")
    if current_status is AlertStatus.RESOLVED:
        raise AlertStoreError("A resolved alert cannot be modified until it is reopened.")
    if status is AlertStatus.ACKNOWLEDGED and current_status is AlertStatus.ACKNOWLEDGED:
        raise AlertStoreError("Alert is already acknowledged.")

    normalized_actor = actor.strip()
    if not normalized_actor:
        raise AlertStoreError("Alert actor cannot be empty.")

    action = "acknowledged" if status is AlertStatus.ACKNOWLEDGED else "resolved"
    update = _status_update_record(
        alert_id.strip(),
        status=status,
        action=action,
        actor=normalized_actor,
        note=note,
    )
    _append_jsonl(expanded_path, [update])
    return get_alert(expanded_path, alert_id)


def prune_alert_log(
    path: Path,
    *,
    older_than_days: int,
    status: AlertStatus = AlertStatus.RESOLVED,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Remove old alerts and compact the remaining lifecycle log."""

    if not 1 <= older_than_days <= 365_000:
        raise AlertStoreError("Retention days must be between 1 and 365000.")

    expanded_path = path.expanduser()
    alerts = load_alerts(expanded_path)
    reference_time = now or datetime.now(UTC)
    cutoff = reference_time - timedelta(days=older_than_days)

    retained: list[dict[str, Any]] = []
    removed = 0

    for alert in alerts:
        last_seen = _parse_datetime(alert.get("last_seen"))
        should_remove = alert.get("status") == status.value and last_seen < cutoff
        if should_remove:
            removed += 1
        else:
            retained.append(alert)

    _rewrite_compacted_log(expanded_path, retained)
    return removed, len(retained)


def parse_alert_status(value: str | None) -> AlertStatus | None:
    """Validate an optional user-supplied alert status."""

    if value is None:
        return None
    try:
        return AlertStatus(value.strip().casefold())
    except ValueError as error:
        allowed = ", ".join(status.value for status in AlertStatus)
        raise AlertStoreError(f"Alert status must be one of: {allowed}.") from error


def _normalize_loaded_alert(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    generated_at = _text_timestamp(normalized.get("generated_at"), _utc_timestamp())
    event_time = _text_timestamp(normalized.get("timestamp"), generated_at)
    fingerprint = str(normalized.get("fingerprint") or alert_fingerprint(normalized))
    alert_id = str(normalized.get("alert_id") or alert_identifier({"fingerprint": fingerprint}))
    occurrence_count = _positive_integer(normalized.get("occurrence_count"), 1)
    status = _parse_status(normalized.get("status"))

    normalized.update(
        {
            "type": "aidac_alert",
            "alert_id": alert_id,
            "fingerprint": fingerprint,
            "status": status.value,
            "occurrence_count": occurrence_count,
            "first_seen": _text_timestamp(normalized.get("first_seen"), event_time),
            "last_seen": _text_timestamp(normalized.get("last_seen"), event_time),
            "generated_at": generated_at,
        }
    )
    return normalized


def _merge_occurrence(
    states: dict[str, dict[str, Any]],
    occurrence: dict[str, Any],
) -> None:
    alert_id = str(occurrence["alert_id"])
    existing = states.get(alert_id)
    if existing is None:
        states[alert_id] = occurrence
        return

    existing_count = _positive_integer(existing.get("occurrence_count"), 1)
    occurrence_count = _positive_integer(occurrence.get("occurrence_count"), 1)
    first_seen = min(
        _parse_datetime(existing.get("first_seen")),
        _parse_datetime(occurrence.get("first_seen")),
    ).isoformat()
    last_seen = max(
        _parse_datetime(existing.get("last_seen")),
        _parse_datetime(occurrence.get("last_seen")),
    ).isoformat()
    current_status = _parse_status(existing.get("status"))

    latest = dict(existing)
    latest.update(occurrence)
    latest.update(
        {
            "status": current_status.value,
            "occurrence_count": existing_count + occurrence_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    )
    states[alert_id] = latest


def _apply_update(
    states: dict[str, dict[str, Any]],
    update: dict[str, Any],
) -> None:
    alert_id = str(update.get("alert_id", "")).strip()
    if not alert_id or alert_id not in states:
        return

    current = dict(states[alert_id])
    if "status" in update:
        current["status"] = _parse_status(update.get("status")).value
    if "actor" in update:
        current["updated_by"] = update["actor"]
    if "note" in update and update["note"] is not None:
        current["status_note"] = update["note"]
    if "timestamp" in update:
        current["status_updated_at"] = update["timestamp"]
    if "action" in update:
        current["last_action"] = update["action"]
    states[alert_id] = current


def _status_update_record(
    alert_id: str,
    *,
    status: AlertStatus,
    action: str,
    actor: str,
    note: str | None,
) -> dict[str, Any]:
    return {
        "type": "aidac_alert_update",
        "alert_id": alert_id,
        "timestamp": _utc_timestamp(),
        "action": action,
        "status": status.value,
        "actor": actor,
        "note": None if note is None else note.strip(),
    }


def _rewrite_compacted_log(path: Path, alerts: list[dict[str, Any]]) -> None:
    _ensure_private_directory(path.parent)
    temporary_file = path.with_suffix(path.suffix + ".tmp")
    payload = "".join(
        json.dumps(alert, sort_keys=True, ensure_ascii=False) + "\n" for alert in alerts
    )

    try:
        temporary_file.write_text(payload, encoding="utf-8")
        temporary_file.chmod(0o600)
        temporary_file.replace(path)
        path.chmod(0o600)
    except OSError as error:
        raise AlertStoreError(f"Unable to compact alert log: {path}") from error


def _append_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        return

    _ensure_private_directory(path.parent)
    payload = "".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n" for record in records
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
        raise AlertStoreError(f"Unable to append alert log: {path}") from error


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as error:
        raise AlertStoreError(f"Unable to prepare private directory: {path}") from error


def _parse_status(value: object) -> AlertStatus:
    if isinstance(value, AlertStatus):
        return value
    normalized = AlertStatus.NEW.value if value is None else str(value).strip().casefold()
    try:
        return AlertStatus(normalized)
    except ValueError as error:
        raise AlertStoreError(f"Invalid alert status: {value}") from error


def _positive_integer(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and value > 0:
        return value
    return default


def _text_timestamp(value: object, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return _parse_datetime(value).isoformat()
    return _parse_datetime(default).isoformat()


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AlertStoreError("Alert timestamp must be a non-empty ISO-8601 string.")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise AlertStoreError(f"Invalid alert timestamp: {value}") from error

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _timestamp_sort_key(value: object) -> datetime:
    return _parse_datetime(value)


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()
