"""Persistent AI-DAC alert storage with SQLite and JSONL compatibility."""

from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aidac import legacy_alert_store as legacy

AlertStoreError = legacy.AlertStoreError
AlertStatus = legacy.AlertStatus
alert_fingerprint = legacy.alert_fingerprint
alert_identifier = legacy.alert_identifier
enrich_alert_record = legacy.enrich_alert_record
parse_alert_status = legacy.parse_alert_status

CURRENT_SCHEMA_VERSION = 1
_SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}


def is_sqlite_store(path: Path) -> bool:
    """Return whether a path selects the SQLite storage backend."""

    return path.expanduser().suffix.casefold() in _SQLITE_SUFFIXES


def initialize_store(path: Path) -> Path:
    """Create or migrate a SQLite alert store to the current schema."""

    expanded_path = path.expanduser()
    if not is_sqlite_store(expanded_path):
        raise AlertStoreError("SQLite alert stores must end with .db, .sqlite, or .sqlite3.")

    _ensure_private_directory(expanded_path.parent)

    try:
        with _connect(expanded_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            current_version = _schema_version(connection)
            if current_version > CURRENT_SCHEMA_VERSION:
                raise AlertStoreError("Alert store schema is newer than this AI-DAC installation.")
            if current_version < 1:
                _apply_schema_v1(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (1, _utc_timestamp()),
                )
            connection.commit()
        expanded_path.chmod(0o600)
    except sqlite3.Error as error:
        raise AlertStoreError(
            f"Unable to initialize SQLite alert store: {expanded_path}"
        ) from error
    except OSError as error:
        raise AlertStoreError(f"Unable to secure SQLite alert store: {expanded_path}") from error

    return expanded_path


def persist_alert_batch(path: Path, batch: dict[str, Any]) -> list[dict[str, Any]]:
    """Persist a batch and return current deduplicated alert states."""

    expanded_path = path.expanduser()
    if not is_sqlite_store(expanded_path):
        return legacy.persist_alert_batch(expanded_path, batch)

    raw_alerts = batch.get("alerts", [])
    if not isinstance(raw_alerts, list):
        raise AlertStoreError("Alert batch does not contain a valid alerts list.")

    batch_id = str(batch.get("batch_id", "")).strip()
    generated_at = _text_timestamp(batch.get("generated_at"), _utc_timestamp())
    if not batch_id:
        raise AlertStoreError("Alert batch does not contain a batch_id.")

    initialize_store(expanded_path)

    try:
        with _connect(expanded_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for raw_alert in raw_alerts:
                if not isinstance(raw_alert, dict):
                    raise AlertStoreError("Alert records must be JSON objects.")
                occurrence = enrich_alert_record(
                    raw_alert,
                    batch_id=batch_id,
                    generated_at=generated_at,
                )
                _upsert_occurrence(connection, occurrence)
            connection.commit()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to persist SQLite alert batch: {expanded_path}") from error

    return load_alerts(expanded_path)


def load_alerts(path: Path) -> list[dict[str, Any]]:
    """Load current alert states from SQLite or a legacy JSONL log."""

    expanded_path = path.expanduser()
    if not is_sqlite_store(expanded_path):
        return legacy.load_alerts(expanded_path)
    if not expanded_path.exists():
        return []

    initialize_store(expanded_path)
    try:
        with _connect(expanded_path) as connection:
            rows = connection.execute(
                "SELECT payload_json FROM alerts ORDER BY last_seen DESC, alert_id ASC"
            ).fetchall()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to read SQLite alert store: {expanded_path}") from error

    return [_decode_payload(str(row[0]), expanded_path) for row in rows]


def query_alerts(
    path: Path,
    *,
    status: AlertStatus | None = None,
    severity: str | None = None,
    minimum_risk: float = 0.0,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Search, paginate and count current alerts."""

    _validate_query_parameters(minimum_risk=minimum_risk, limit=limit, offset=offset)
    normalized_severity = _normalize_optional_text(severity)
    normalized_search = _normalize_optional_text(search)
    expanded_path = path.expanduser()

    if not is_sqlite_store(expanded_path):
        alerts = _filter_in_memory(
            legacy.load_alerts(expanded_path),
            status=status,
            severity=normalized_severity,
            minimum_risk=minimum_risk,
            search=normalized_search,
        )
        return alerts[offset : offset + limit], len(alerts)

    if not expanded_path.exists():
        return [], 0

    initialize_store(expanded_path)
    clauses: list[str] = []
    parameters: list[object] = []

    if status is not None:
        clauses.append("status = ?")
        parameters.append(status.value)
    if normalized_severity is not None:
        clauses.append("LOWER(severity) = ?")
        parameters.append(normalized_severity.casefold())
    if minimum_risk > 0.0:
        clauses.append("risk_score >= ?")
        parameters.append(minimum_risk)
    if normalized_search is not None:
        clauses.append(
            "("
            + " OR ".join(
                [
                    "LOWER(alert_id) LIKE ?",
                    "LOWER(username) LIKE ?",
                    "LOWER(database_name) LIKE ?",
                    "LOWER(client_ip) LIKE ?",
                    "LOWER(classification) LIKE ?",
                    "LOWER(query_text) LIKE ?",
                ]
            )
            + ")"
        )
        wildcard = f"%{normalized_search.casefold()}%"
        parameters.extend([wildcard] * 6)

    where = "" if not clauses else " WHERE " + " AND ".join(clauses)
    count_sql = "SELECT COUNT(*) FROM alerts" + where
    select_sql = (
        "SELECT payload_json FROM alerts"
        + where
        + " ORDER BY last_seen DESC, alert_id ASC LIMIT ? OFFSET ?"
    )

    try:
        with _connect(expanded_path) as connection:
            total_row = connection.execute(count_sql, parameters).fetchone()
            rows = connection.execute(select_sql, [*parameters, limit, offset]).fetchall()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to query SQLite alert store: {expanded_path}") from error

    total = 0 if total_row is None else int(total_row[0])
    return [_decode_payload(str(row[0]), expanded_path) for row in rows], total


def get_alert(path: Path, alert_id: str) -> dict[str, Any]:
    """Return one alert by identifier."""

    expanded_path = path.expanduser()
    normalized_id = alert_id.strip()
    if not normalized_id:
        raise AlertStoreError("Alert identifier cannot be empty.")
    if not is_sqlite_store(expanded_path):
        return legacy.get_alert(expanded_path, normalized_id)
    if not expanded_path.exists():
        raise AlertStoreError(f"Alert not found: {normalized_id}")

    initialize_store(expanded_path)
    try:
        with _connect(expanded_path) as connection:
            row = connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ?",
                (normalized_id,),
            ).fetchone()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to read SQLite alert store: {expanded_path}") from error

    if row is None:
        raise AlertStoreError(f"Alert not found: {normalized_id}")
    return _decode_payload(str(row[0]), expanded_path)


def filter_alerts(
    alerts: list[dict[str, Any]],
    *,
    status: AlertStatus | None = None,
    severity: str | None = None,
    minimum_risk: float = 0.0,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Filter an in-memory alert list while preserving the public v0.7 API."""

    _validate_query_parameters(minimum_risk=minimum_risk, limit=limit, offset=offset)
    filtered = _filter_in_memory(
        alerts,
        status=status,
        severity=_normalize_optional_text(severity),
        minimum_risk=minimum_risk,
        search=_normalize_optional_text(search),
    )
    return filtered[offset : offset + limit]


def update_alert_status(
    path: Path,
    alert_id: str,
    *,
    status: AlertStatus,
    actor: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Persist an acknowledged or resolved lifecycle transition."""

    expanded_path = path.expanduser()
    if not is_sqlite_store(expanded_path):
        return legacy.update_alert_status(
            expanded_path,
            alert_id,
            status=status,
            actor=actor,
            note=note,
        )

    normalized_id = alert_id.strip()
    normalized_actor = actor.strip()
    if not normalized_actor:
        raise AlertStoreError("Alert actor cannot be empty.")
    if status is AlertStatus.NEW:
        raise AlertStoreError("Use automatic event detection to reopen an alert.")

    initialize_store(expanded_path)
    try:
        with _connect(expanded_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                raise AlertStoreError(f"Alert not found: {normalized_id}")

            current = _decode_payload(str(row[0]), expanded_path)
            current_status = _parse_status(current.get("status"))
            if current_status is AlertStatus.RESOLVED:
                raise AlertStoreError("A resolved alert cannot be modified until it is reopened.")
            if status is AlertStatus.ACKNOWLEDGED and current_status is AlertStatus.ACKNOWLEDGED:
                raise AlertStoreError("Alert is already acknowledged.")

            timestamp = _utc_timestamp()
            action = "acknowledged" if status is AlertStatus.ACKNOWLEDGED else "resolved"
            current.update(
                {
                    "status": status.value,
                    "updated_by": normalized_actor,
                    "status_note": None if note is None else note.strip(),
                    "status_updated_at": timestamp,
                    "last_action": action,
                }
            )
            connection.execute(
                """
                UPDATE alerts
                SET status = ?, payload_json = ?, updated_by = ?, status_note = ?,
                    status_updated_at = ?, last_action = ?
                WHERE alert_id = ?
                """,
                (
                    status.value,
                    _encode_payload(current),
                    normalized_actor,
                    None if note is None else note.strip(),
                    timestamp,
                    action,
                    normalized_id,
                ),
            )
            _insert_event(
                connection,
                alert_id=normalized_id,
                event_type=action,
                timestamp=timestamp,
                actor=normalized_actor,
                note=None if note is None else note.strip(),
                batch_id=None,
                payload=current,
            )
            connection.commit()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to update SQLite alert store: {expanded_path}") from error

    return get_alert(expanded_path, normalized_id)


def prune_alert_log(
    path: Path,
    *,
    older_than_days: int,
    status: AlertStatus = AlertStatus.RESOLVED,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Remove old alerts from SQLite or compact a legacy JSONL log."""

    expanded_path = path.expanduser()
    if not is_sqlite_store(expanded_path):
        return legacy.prune_alert_log(
            expanded_path,
            older_than_days=older_than_days,
            status=status,
            now=now,
        )
    if not 1 <= older_than_days <= 365_000:
        raise AlertStoreError("Retention days must be between 1 and 365000.")
    if not expanded_path.exists():
        return 0, 0

    cutoff = (now or datetime.now(UTC)) - timedelta(days=older_than_days)
    initialize_store(expanded_path)
    try:
        with _connect(expanded_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            before = int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            connection.execute(
                "DELETE FROM alerts WHERE status = ? AND last_seen < ?",
                (status.value, cutoff.astimezone(UTC).isoformat()),
            )
            after = int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            connection.commit()
    except sqlite3.Error as error:
        raise AlertStoreError(f"Unable to prune SQLite alert store: {expanded_path}") from error

    return before - after, after


def migrate_jsonl_to_sqlite(
    source: Path,
    destination: Path,
    *,
    merge: bool = False,
) -> int:
    """Import current states from a v0.6+ JSONL lifecycle log into SQLite."""

    source_path = source.expanduser()
    destination_path = destination.expanduser()
    if is_sqlite_store(source_path):
        raise AlertStoreError("Migration source must be a JSONL alert log.")
    if not is_sqlite_store(destination_path):
        raise AlertStoreError("Migration destination must be a SQLite alert store.")

    alerts = legacy.load_alerts(source_path)
    initialize_store(destination_path)

    try:
        with _connect(destination_path) as connection:
            existing_count = int(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            if existing_count and not merge:
                raise AlertStoreError(
                    "Destination already contains alerts. Use merge=True to import additional data."
                )
            connection.execute("BEGIN IMMEDIATE")
            imported = 0
            for alert in alerts:
                _import_snapshot(connection, alert)
                imported += 1
            connection.commit()
    except sqlite3.Error as error:
        raise AlertStoreError(
            f"Unable to migrate JSONL alert log into SQLite: {destination_path}"
        ) from error

    return imported


def store_info(path: Path) -> dict[str, Any]:
    """Return non-sensitive storage diagnostics."""

    expanded_path = path.expanduser()
    backend = "sqlite" if is_sqlite_store(expanded_path) else "jsonl"
    result: dict[str, Any] = {
        "path": str(expanded_path),
        "backend": backend,
        "exists": expanded_path.exists(),
        "size_bytes": expanded_path.stat().st_size if expanded_path.exists() else 0,
        "alert_count": 0,
        "schema_version": None,
    }

    if backend == "sqlite":
        if expanded_path.exists():
            initialize_store(expanded_path)
            try:
                with _connect(expanded_path) as connection:
                    result["schema_version"] = _schema_version(connection)
                    result["alert_count"] = int(
                        connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                    )
            except sqlite3.Error as error:
                raise AlertStoreError(
                    f"Unable to inspect SQLite alert store: {expanded_path}"
                ) from error
    else:
        result["alert_count"] = len(legacy.load_alerts(expanded_path))

    return result


def verify_store(path: Path) -> dict[str, Any]:
    """Validate the selected store and return a diagnostic result."""

    expanded_path = path.expanduser()
    information = store_info(expanded_path)
    information["valid"] = True

    if is_sqlite_store(expanded_path) and expanded_path.exists():
        try:
            with _connect(expanded_path) as connection:
                integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        except sqlite3.Error as error:
            raise AlertStoreError(
                f"Unable to verify SQLite alert store: {expanded_path}"
            ) from error
        information["integrity_check"] = integrity
        information["valid"] = integrity == "ok"
    else:
        legacy.load_alerts(expanded_path)
        information["integrity_check"] = "jsonl_replay_ok"

    return information


def backup_store(source: Path, destination: Path) -> Path:
    """Create a consistent private backup of an alert store."""

    source_path = source.expanduser()
    destination_path = destination.expanduser()
    if not source_path.exists():
        raise AlertStoreError(f"Alert store does not exist: {source_path}")

    if destination_path.exists() and destination_path.is_dir():
        suffix = source_path.suffix or ".jsonl"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination_path = destination_path / f"aidac-alerts-{stamp}{suffix}"

    _ensure_private_directory(destination_path.parent)
    temporary = destination_path.with_suffix(destination_path.suffix + ".tmp")

    try:
        if is_sqlite_store(source_path):
            initialize_store(source_path)
            with closing(sqlite3.connect(source_path)) as source_connection:
                with closing(sqlite3.connect(temporary)) as destination_connection:
                    source_connection.backup(destination_connection)
                    destination_connection.commit()
        else:
            shutil.copyfile(source_path, temporary)
        temporary.chmod(0o600)
        temporary.replace(destination_path)
        destination_path.chmod(0o600)
    except (OSError, sqlite3.Error) as error:
        temporary.unlink(missing_ok=True)
        raise AlertStoreError(f"Unable to back up alert store: {source_path}") from error

    return destination_path


def restore_store(
    backup: Path,
    destination: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Validate and restore a private alert-store backup."""

    backup_path = backup.expanduser()
    destination_path = destination.expanduser()
    if not backup_path.exists():
        raise AlertStoreError(f"Backup does not exist: {backup_path}")
    if backup_path.resolve() == destination_path.resolve():
        raise AlertStoreError("Backup and destination must be different files.")
    if destination_path.exists() and not overwrite:
        raise AlertStoreError("Destination already exists. Explicit overwrite is required.")

    verify_store(backup_path)
    _ensure_private_directory(destination_path.parent)
    temporary = destination_path.with_suffix(destination_path.suffix + ".restore.tmp")

    try:
        shutil.copyfile(backup_path, temporary)
        temporary.chmod(0o600)
        temporary.replace(destination_path)
        destination_path.chmod(0o600)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise AlertStoreError(f"Unable to restore alert store: {destination_path}") from error

    verify_store(destination_path)
    return destination_path


def _apply_schema_v1(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK(status IN ('new', 'acknowledged', 'resolved')),
            occurrence_count INTEGER NOT NULL CHECK(occurrence_count > 0),
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT '',
            risk_score REAL NOT NULL DEFAULT 0.0,
            database_name TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            client_ip TEXT NOT NULL DEFAULT '',
            classification TEXT NOT NULL DEFAULT '',
            source_system TEXT NOT NULL DEFAULT '',
            query_text TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL,
            updated_by TEXT,
            status_note TEXT,
            status_updated_at TEXT,
            last_action TEXT
        );

        CREATE TABLE IF NOT EXISTS alert_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            batch_id TEXT,
            actor TEXT,
            note TEXT,
            payload_json TEXT NOT NULL,
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_status_last_seen
            ON alerts(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity_risk
            ON alerts(severity, risk_score DESC);
        CREATE INDEX IF NOT EXISTS idx_alert_events_alert_id
            ON alert_events(alert_id, event_id);
        """
    )


def _schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    if row is None or row[0] is None:
        return 0
    return int(row[0])


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5.0)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def _upsert_occurrence(connection: sqlite3.Connection, occurrence: dict[str, Any]) -> None:
    alert_id = str(occurrence["alert_id"])
    row = connection.execute(
        "SELECT payload_json FROM alerts WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()

    if row is None:
        current = dict(occurrence)
        event_type = "created"
    else:
        existing = _decode_payload(str(row[0]), Path("<sqlite>"))
        current_status = _parse_status(existing.get("status"))
        current = dict(existing)
        current.update(occurrence)
        current["occurrence_count"] = _positive_integer(existing.get("occurrence_count"), 1) + 1
        current["first_seen"] = min(
            _parse_datetime(existing.get("first_seen")),
            _parse_datetime(occurrence.get("first_seen")),
        ).isoformat()
        current["last_seen"] = max(
            _parse_datetime(existing.get("last_seen")),
            _parse_datetime(occurrence.get("last_seen")),
        ).isoformat()
        if current_status is AlertStatus.RESOLVED:
            current["status"] = AlertStatus.NEW.value
            current["updated_by"] = "system"
            current["status_note"] = "A new matching database event reopened the resolved alert."
            current["status_updated_at"] = _utc_timestamp()
            current["last_action"] = "reopened"
            event_type = "reopened"
        else:
            current["status"] = current_status.value
            for key in ("updated_by", "status_note", "status_updated_at", "last_action"):
                if key in existing:
                    current[key] = existing[key]
            event_type = "occurrence"

    _write_current_alert(connection, current)
    _insert_event(
        connection,
        alert_id=alert_id,
        event_type=event_type,
        timestamp=str(
            occurrence.get("last_seen", occurrence.get("generated_at", _utc_timestamp()))
        ),
        actor="system" if event_type == "reopened" else None,
        note=current.get("status_note") if event_type == "reopened" else None,
        batch_id=str(occurrence.get("batch_id", "")) or None,
        payload=occurrence,
    )


def _write_current_alert(connection: sqlite3.Connection, alert: dict[str, Any]) -> None:
    connection.execute(
        """
        INSERT INTO alerts (
            alert_id, fingerprint, status, occurrence_count, first_seen, last_seen,
            severity, risk_score, database_name, username, client_ip, classification,
            source_system, query_text, payload_json, updated_by, status_note,
            status_updated_at, last_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alert_id) DO UPDATE SET
            fingerprint = excluded.fingerprint,
            status = excluded.status,
            occurrence_count = excluded.occurrence_count,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            severity = excluded.severity,
            risk_score = excluded.risk_score,
            database_name = excluded.database_name,
            username = excluded.username,
            client_ip = excluded.client_ip,
            classification = excluded.classification,
            source_system = excluded.source_system,
            query_text = excluded.query_text,
            payload_json = excluded.payload_json,
            updated_by = excluded.updated_by,
            status_note = excluded.status_note,
            status_updated_at = excluded.status_updated_at,
            last_action = excluded.last_action
        """,
        (
            str(alert.get("alert_id", "")),
            str(alert.get("fingerprint", "")),
            _parse_status(alert.get("status")).value,
            _positive_integer(alert.get("occurrence_count"), 1),
            _text_timestamp(alert.get("first_seen"), _utc_timestamp()),
            _text_timestamp(alert.get("last_seen"), _utc_timestamp()),
            str(alert.get("severity", "")),
            _risk_score(alert.get("risk_score")),
            str(alert.get("database", "")),
            str(alert.get("username", "")),
            str(alert.get("client_ip", "")),
            str(alert.get("classification", "")),
            str(alert.get("source_system", "")),
            str(alert.get("query", "")),
            _encode_payload(alert),
            _optional_text(alert.get("updated_by")),
            _optional_text(alert.get("status_note")),
            _optional_text(alert.get("status_updated_at")),
            _optional_text(alert.get("last_action")),
        ),
    )


def _insert_event(
    connection: sqlite3.Connection,
    *,
    alert_id: str,
    event_type: str,
    timestamp: str,
    actor: str | None,
    note: str | None,
    batch_id: str | None,
    payload: dict[str, Any],
) -> None:
    connection.execute(
        """
        INSERT INTO alert_events(
            alert_id, event_type, timestamp, batch_id, actor, note, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            event_type,
            _text_timestamp(timestamp, _utc_timestamp()),
            batch_id,
            actor,
            note,
            _encode_payload(payload),
        ),
    )


def _import_snapshot(connection: sqlite3.Connection, alert: dict[str, Any]) -> None:
    normalized = dict(alert)
    if "fingerprint" not in normalized:
        normalized["fingerprint"] = alert_fingerprint(normalized)
    if "alert_id" not in normalized:
        normalized["alert_id"] = alert_identifier(normalized)
    _write_current_alert(connection, normalized)
    _insert_event(
        connection,
        alert_id=str(normalized["alert_id"]),
        event_type="migrated",
        timestamp=str(normalized.get("last_seen", _utc_timestamp())),
        actor="system",
        note="Imported from legacy JSONL lifecycle log.",
        batch_id=_optional_text(normalized.get("batch_id")),
        payload=normalized,
    )


def _filter_in_memory(
    alerts: list[dict[str, Any]],
    *,
    status: AlertStatus | None,
    severity: str | None,
    minimum_risk: float,
    search: str | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    needle = None if search is None else search.casefold()

    for alert in alerts:
        if status is not None and alert.get("status") != status.value:
            continue
        if (
            severity is not None
            and str(alert.get("severity", "")).casefold() != severity.casefold()
        ):
            continue
        if _risk_score(alert.get("risk_score")) < minimum_risk:
            continue
        if needle is not None:
            haystack = " ".join(
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
            if needle not in haystack:
                continue
        filtered.append(alert)
    return filtered


def _validate_query_parameters(*, minimum_risk: float, limit: int, offset: int) -> None:
    if not 0.0 <= minimum_risk <= 1.0:
        raise AlertStoreError("Minimum risk must be between 0.0 and 1.0.")
    if not 1 <= limit <= 100_000:
        raise AlertStoreError("Alert list limit must be between 1 and 100000.")
    if offset < 0:
        raise AlertStoreError("Alert list offset cannot be negative.")


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _decode_payload(value: str, path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as error:
        raise AlertStoreError(f"Invalid alert payload in store: {path}") from error
    if not isinstance(payload, dict):
        raise AlertStoreError(f"Alert payload in store must be a JSON object: {path}")
    return payload


def _encode_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


def _risk_score(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))
    try:
        return max(0.0, min(float(str(value)), 1.0))
    except ValueError:
        return 0.0


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


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


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as error:
        raise AlertStoreError(f"Unable to prepare private directory: {path}") from error


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()
