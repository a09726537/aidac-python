"""Optional PostgreSQL alert lifecycle storage for AI-DAC."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg import Connection, sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from aidac import legacy_alert_store as legacy

AlertStoreError = legacy.AlertStoreError
AlertStatus = legacy.AlertStatus
alert_fingerprint = legacy.alert_fingerprint
alert_identifier = legacy.alert_identifier
enrich_alert_record = legacy.enrich_alert_record

CURRENT_SCHEMA_VERSION = 1
_SCHEMA_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_BACKUP_FORMAT = "aidac-postgresql-alert-backup-v1"


def validate_schema(schema: str) -> str:
    """Validate and normalize the PostgreSQL schema name."""

    normalized = schema.strip()
    if not _SCHEMA_PATTERN.fullmatch(normalized):
        raise AlertStoreError(
            "PostgreSQL alert-store schema must start with a letter or underscore and "
            "contain only letters, digits, and underscores."
        )
    return normalized


def initialize_store(dsn: str, *, schema: str) -> None:
    """Create or migrate the PostgreSQL alert-store schema."""

    normalized_schema = validate_schema(schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                cursor.execute(
                    sql.SQL(
                        """
                        CREATE TABLE IF NOT EXISTS {}.schema_migrations (
                            version INTEGER PRIMARY KEY,
                            applied_at TIMESTAMPTZ NOT NULL
                        )
                        """
                    ).format(sql.Identifier(normalized_schema))
                )
                cursor.execute(
                    sql.SQL(
                        "SELECT COALESCE(MAX(version), 0) AS version FROM {}.schema_migrations"
                    ).format(sql.Identifier(normalized_schema))
                )
                row = cursor.fetchone()
                current_version = 0 if row is None else int(row["version"])
                if current_version > CURRENT_SCHEMA_VERSION:
                    raise AlertStoreError(
                        "PostgreSQL alert-store schema is newer than this AI-DAC installation."
                    )
                if current_version < 1:
                    _apply_schema_v1(cursor, normalized_schema)
                    cursor.execute(
                        sql.SQL(
                            "INSERT INTO {}.schema_migrations(version, applied_at) VALUES (%s, %s)"
                        ).format(sql.Identifier(normalized_schema)),
                        (1, datetime.now(UTC)),
                    )
            connection.commit()
    except AlertStoreError:
        raise
    except psycopg.Error as error:
        raise AlertStoreError(
            "Unable to initialize PostgreSQL alert store. Check the DSN, schema, and privileges."
        ) from error


def persist_alert_batch(
    dsn: str,
    *,
    schema: str,
    batch: dict[str, Any],
) -> list[dict[str, Any]]:
    """Persist one alert batch and return current deduplicated states."""

    raw_alerts = batch.get("alerts", [])
    if not isinstance(raw_alerts, list):
        raise AlertStoreError("Alert batch does not contain a valid alerts list.")
    batch_id = str(batch.get("batch_id", "")).strip()
    generated_at = _text_timestamp(batch.get("generated_at"), _utc_timestamp())
    if not batch_id:
        raise AlertStoreError("Alert batch does not contain a batch_id.")

    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                for raw_alert in raw_alerts:
                    if not isinstance(raw_alert, dict):
                        raise AlertStoreError("Alert records must be JSON objects.")
                    occurrence = enrich_alert_record(
                        raw_alert,
                        batch_id=batch_id,
                        generated_at=generated_at,
                    )
                    _upsert_occurrence(cursor, normalized_schema, occurrence)
            connection.commit()
    except AlertStoreError:
        raise
    except psycopg.Error as error:
        raise AlertStoreError("Unable to persist PostgreSQL alert batch.") from error

    return load_alerts(dsn, schema=normalized_schema)


def load_alerts(dsn: str, *, schema: str) -> list[dict[str, Any]]:
    """Load current alert states from PostgreSQL."""

    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL(
                        "SELECT payload_json FROM {}.alerts ORDER BY last_seen DESC, alert_id ASC"
                    ).format(sql.Identifier(normalized_schema))
                )
                rows = cursor.fetchall()
    except psycopg.Error as error:
        raise AlertStoreError("Unable to read PostgreSQL alert store.") from error
    return [_payload(row["payload_json"]) for row in rows]


def query_alerts(
    dsn: str,
    *,
    schema: str,
    status: AlertStatus | None = None,
    severity: str | None = None,
    minimum_risk: float = 0.0,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Search and paginate alerts in PostgreSQL."""

    _validate_query_parameters(minimum_risk=minimum_risk, limit=limit, offset=offset)
    normalized_schema = validate_schema(schema)
    normalized_severity = _normalize_optional_text(severity)
    normalized_search = _normalize_optional_text(search)
    initialize_store(dsn, schema=normalized_schema)

    clauses: list[sql.Composable] = []
    parameters: list[object] = []
    if status is not None:
        clauses.append(sql.SQL("status = %s"))
        parameters.append(status.value)
    if normalized_severity is not None:
        clauses.append(sql.SQL("LOWER(severity) = %s"))
        parameters.append(normalized_severity.casefold())
    if minimum_risk > 0.0:
        clauses.append(sql.SQL("risk_score >= %s"))
        parameters.append(minimum_risk)
    if normalized_search is not None:
        clauses.append(
            sql.SQL(
                "("
                + " OR ".join(
                    [
                        "LOWER(alert_id) LIKE %s",
                        "LOWER(username) LIKE %s",
                        "LOWER(database_name) LIKE %s",
                        "LOWER(client_ip) LIKE %s",
                        "LOWER(classification) LIKE %s",
                        "LOWER(query_text) LIKE %s",
                    ]
                )
                + ")"
            )
        )
        wildcard = f"%{normalized_search.casefold()}%"
        parameters.extend([wildcard] * 6)

    where: sql.Composable = sql.SQL("")
    if clauses:
        where = sql.SQL(" WHERE ") + sql.SQL(" AND ").join(clauses)

    count_query = (
        sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(sql.Identifier(normalized_schema))
        + where
    )
    select_query = (
        sql.SQL("SELECT payload_json FROM {}.alerts").format(sql.Identifier(normalized_schema))
        + where
        + sql.SQL(" ORDER BY last_seen DESC, alert_id ASC LIMIT %s OFFSET %s")
    )

    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(count_query, parameters)
                total_row = cursor.fetchone()
                cursor.execute(select_query, [*parameters, limit, offset])
                rows = cursor.fetchall()
    except psycopg.Error as error:
        raise AlertStoreError("Unable to query PostgreSQL alert store.") from error

    total = 0 if total_row is None else int(total_row["total"])
    return [_payload(row["payload_json"]) for row in rows], total


def get_alert(dsn: str, *, schema: str, alert_id: str) -> dict[str, Any]:
    """Return one alert by identifier."""

    normalized_id = alert_id.strip()
    if not normalized_id:
        raise AlertStoreError("Alert identifier cannot be empty.")
    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SELECT payload_json FROM {}.alerts WHERE alert_id = %s").format(
                        sql.Identifier(normalized_schema)
                    ),
                    (normalized_id,),
                )
                row = cursor.fetchone()
    except psycopg.Error as error:
        raise AlertStoreError("Unable to read PostgreSQL alert store.") from error
    if row is None:
        raise AlertStoreError(f"Alert not found: {normalized_id}")
    return _payload(row["payload_json"])


def update_alert_status(
    dsn: str,
    *,
    schema: str,
    alert_id: str,
    status: AlertStatus,
    actor: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Persist an acknowledged or resolved lifecycle transition."""

    normalized_id = alert_id.strip()
    normalized_actor = actor.strip()
    if not normalized_actor:
        raise AlertStoreError("Alert actor cannot be empty.")
    if status is AlertStatus.NEW:
        raise AlertStoreError("Use automatic event detection to reopen an alert.")
    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)

    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL(
                        "SELECT payload_json FROM {}.alerts WHERE alert_id = %s FOR UPDATE"
                    ).format(sql.Identifier(normalized_schema)),
                    (normalized_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise AlertStoreError(f"Alert not found: {normalized_id}")
                current = _payload(row["payload_json"])
                current_status = _parse_status(current.get("status"))
                if current_status is AlertStatus.RESOLVED:
                    raise AlertStoreError(
                        "A resolved alert cannot be modified until it is reopened."
                    )
                if (
                    status is AlertStatus.ACKNOWLEDGED
                    and current_status is AlertStatus.ACKNOWLEDGED
                ):
                    raise AlertStoreError("Alert is already acknowledged.")

                timestamp = _utc_timestamp()
                normalized_note = None if note is None else note.strip()
                action = "acknowledged" if status is AlertStatus.ACKNOWLEDGED else "resolved"
                current.update(
                    {
                        "status": status.value,
                        "updated_by": normalized_actor,
                        "status_note": normalized_note,
                        "status_updated_at": timestamp,
                        "last_action": action,
                    }
                )
                _write_current_alert(cursor, normalized_schema, current)
                _insert_event(
                    cursor,
                    normalized_schema,
                    alert_id=normalized_id,
                    event_type=action,
                    timestamp=timestamp,
                    actor=normalized_actor,
                    note=normalized_note,
                    batch_id=None,
                    payload=current,
                )
            connection.commit()
    except AlertStoreError:
        raise
    except psycopg.Error as error:
        raise AlertStoreError("Unable to update PostgreSQL alert store.") from error

    return get_alert(dsn, schema=normalized_schema, alert_id=normalized_id)


def prune_alert_log(
    dsn: str,
    *,
    schema: str,
    older_than_days: int,
    status: AlertStatus = AlertStatus.RESOLVED,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Remove old lifecycle alerts from PostgreSQL."""

    if not 1 <= older_than_days <= 365_000:
        raise AlertStoreError("Retention days must be between 1 and 365000.")
    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    cutoff = (now or datetime.now(UTC)) - timedelta(days=older_than_days)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                before_row = cursor.fetchone()
                before = 0 if before_row is None else int(before_row["total"])
                cursor.execute(
                    sql.SQL("DELETE FROM {}.alerts WHERE status = %s AND last_seen < %s").format(
                        sql.Identifier(normalized_schema)
                    ),
                    (status.value, cutoff),
                )
                cursor.execute(
                    sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                after_row = cursor.fetchone()
                after = 0 if after_row is None else int(after_row["total"])
            connection.commit()
    except psycopg.Error as error:
        raise AlertStoreError("Unable to prune PostgreSQL alert store.") from error
    return before - after, after


def import_alerts(
    dsn: str,
    *,
    schema: str,
    alerts: list[dict[str, Any]],
    merge: bool,
) -> int:
    """Import alert snapshots into PostgreSQL."""

    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                row = cursor.fetchone()
                existing_count = 0 if row is None else int(row["total"])
                if existing_count and not merge:
                    raise AlertStoreError(
                        "Destination already contains alerts. "
                        "Use merge=True to import additional data."
                    )
                for alert in alerts:
                    _import_snapshot(cursor, normalized_schema, alert)
            connection.commit()
    except AlertStoreError:
        raise
    except psycopg.Error as error:
        raise AlertStoreError("Unable to import alerts into PostgreSQL.") from error
    return len(alerts)


def store_info(dsn: str, *, schema: str) -> dict[str, Any]:
    """Return non-sensitive PostgreSQL storage diagnostics."""

    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database() AS database, current_user AS username")
                identity = cursor.fetchone() or {}
                cursor.execute(
                    sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                count = cursor.fetchone() or {"total": 0}
                cursor.execute(
                    sql.SQL(
                        "SELECT COALESCE(MAX(version), 0) AS version FROM {}.schema_migrations"
                    ).format(sql.Identifier(normalized_schema))
                )
                version = cursor.fetchone() or {"version": 0}
    except psycopg.Error as error:
        raise AlertStoreError("Unable to inspect PostgreSQL alert store.") from error
    return {
        "path": "environment:AIDAC_ALERT_STORE_DSN",
        "backend": "postgresql",
        "exists": True,
        "size_bytes": None,
        "alert_count": int(count["total"]),
        "schema_version": int(version["version"]),
        "database": str(identity.get("database", "")),
        "username": str(identity.get("username", "")),
        "schema": normalized_schema,
    }


def verify_store(dsn: str, *, schema: str) -> dict[str, Any]:
    """Verify PostgreSQL connectivity and schema state."""

    information = store_info(dsn, schema=schema)
    information.update({"valid": True, "integrity_check": "postgresql_connection_ok"})
    return information


def backup_store(dsn: str, *, schema: str, destination: Path) -> Path:
    """Create an application-level private JSON backup of PostgreSQL alerts."""

    destination_path = destination.expanduser()
    if destination_path.exists() and destination_path.is_dir():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination_path = destination_path / f"aidac-alerts-postgresql-{stamp}.json"
    _ensure_private_directory(destination_path.parent)
    temporary = destination_path.with_suffix(destination_path.suffix + ".tmp")
    payload = {
        "format": _BACKUP_FORMAT,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "created_at": _utc_timestamp(),
        "alerts": load_alerts(dsn, schema=schema),
    }
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(destination_path)
        destination_path.chmod(0o600)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise AlertStoreError("Unable to back up PostgreSQL alert store.") from error
    return destination_path


def restore_store(
    dsn: str,
    *,
    schema: str,
    backup: Path,
    overwrite: bool,
) -> None:
    """Restore an application-level PostgreSQL alert backup."""

    backup_path = backup.expanduser()
    try:
        payload = json.loads(backup_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AlertStoreError("Unable to read PostgreSQL alert backup.") from error
    if not isinstance(payload, dict) or payload.get("format") != _BACKUP_FORMAT:
        raise AlertStoreError("Backup is not an AI-DAC PostgreSQL alert backup.")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or any(not isinstance(item, dict) for item in alerts):
        raise AlertStoreError("PostgreSQL alert backup contains invalid alert data.")

    normalized_schema = validate_schema(schema)
    initialize_store(dsn, schema=normalized_schema)
    try:
        with _connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SELECT COUNT(*) AS total FROM {}.alerts").format(
                        sql.Identifier(normalized_schema)
                    )
                )
                row = cursor.fetchone()
                count = 0 if row is None else int(row["total"])
                if count and not overwrite:
                    raise AlertStoreError(
                        "PostgreSQL alert store is not empty. Explicit overwrite is required."
                    )
                if overwrite:
                    cursor.execute(
                        sql.SQL("TRUNCATE {}.alert_events, {}.alerts RESTART IDENTITY").format(
                            sql.Identifier(normalized_schema),
                            sql.Identifier(normalized_schema),
                        )
                    )
                for alert in alerts:
                    _import_snapshot(cursor, normalized_schema, alert)
            connection.commit()
    except AlertStoreError:
        raise
    except psycopg.Error as error:
        raise AlertStoreError("Unable to restore PostgreSQL alert store.") from error


def _apply_schema_v1(cursor: Any, schema: str) -> None:
    cursor.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {}.alerts (
                alert_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('new', 'acknowledged', 'resolved')),
                occurrence_count INTEGER NOT NULL CHECK(occurrence_count > 0),
                first_seen TIMESTAMPTZ NOT NULL,
                last_seen TIMESTAMPTZ NOT NULL,
                severity TEXT NOT NULL DEFAULT '',
                risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                database_name TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                classification TEXT NOT NULL DEFAULT '',
                source_system TEXT NOT NULL DEFAULT '',
                query_text TEXT NOT NULL DEFAULT '',
                payload_json JSONB NOT NULL,
                updated_by TEXT,
                status_note TEXT,
                status_updated_at TIMESTAMPTZ,
                last_action TEXT
            )
            """
        ).format(sql.Identifier(schema))
    )
    cursor.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {}.alert_events (
                event_id BIGSERIAL PRIMARY KEY,
                alert_id TEXT NOT NULL REFERENCES {}.alerts(alert_id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                batch_id TEXT,
                actor TEXT,
                note TEXT,
                payload_json JSONB NOT NULL
            )
            """
        ).format(sql.Identifier(schema), sql.Identifier(schema))
    )
    cursor.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {} ON {}.alerts(status, last_seen DESC)").format(
            sql.Identifier(f"idx_{schema}_alerts_status_last_seen"),
            sql.Identifier(schema),
        )
    )
    cursor.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {} ON {}.alerts(severity, risk_score DESC)").format(
            sql.Identifier(f"idx_{schema}_alerts_severity_risk"),
            sql.Identifier(schema),
        )
    )
    cursor.execute(
        sql.SQL("CREATE INDEX IF NOT EXISTS {} ON {}.alert_events(alert_id, event_id)").format(
            sql.Identifier(f"idx_{schema}_alert_events_alert_id"),
            sql.Identifier(schema),
        )
    )


def _upsert_occurrence(cursor: Any, schema: str, occurrence: dict[str, Any]) -> None:
    alert_id = str(occurrence["alert_id"])
    cursor.execute(
        sql.SQL("SELECT payload_json FROM {}.alerts WHERE alert_id = %s FOR UPDATE").format(
            sql.Identifier(schema)
        ),
        (alert_id,),
    )
    row = cursor.fetchone()
    if row is None:
        current = dict(occurrence)
        event_type = "created"
    else:
        existing = _payload(row["payload_json"])
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

    _write_current_alert(cursor, schema, current)
    _insert_event(
        cursor,
        schema,
        alert_id=alert_id,
        event_type=event_type,
        timestamp=str(
            occurrence.get(
                "last_seen",
                occurrence.get("generated_at", _utc_timestamp()),
            )
        ),
        actor="system" if event_type == "reopened" else None,
        note=current.get("status_note") if event_type == "reopened" else None,
        batch_id=str(occurrence.get("batch_id", "")) or None,
        payload=occurrence,
    )


def _write_current_alert(cursor: Any, schema: str, alert: dict[str, Any]) -> None:
    cursor.execute(
        sql.SQL(
            """
            INSERT INTO {}.alerts (
                alert_id, fingerprint, status, occurrence_count, first_seen, last_seen,
                severity, risk_score, database_name, username, client_ip, classification,
                source_system, query_text, payload_json, updated_by, status_note,
                status_updated_at, last_action
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT(alert_id) DO UPDATE SET
                fingerprint = EXCLUDED.fingerprint,
                status = EXCLUDED.status,
                occurrence_count = EXCLUDED.occurrence_count,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                severity = EXCLUDED.severity,
                risk_score = EXCLUDED.risk_score,
                database_name = EXCLUDED.database_name,
                username = EXCLUDED.username,
                client_ip = EXCLUDED.client_ip,
                classification = EXCLUDED.classification,
                source_system = EXCLUDED.source_system,
                query_text = EXCLUDED.query_text,
                payload_json = EXCLUDED.payload_json,
                updated_by = EXCLUDED.updated_by,
                status_note = EXCLUDED.status_note,
                status_updated_at = EXCLUDED.status_updated_at,
                last_action = EXCLUDED.last_action
            """
        ).format(sql.Identifier(schema)),
        (
            str(alert.get("alert_id", "")),
            str(alert.get("fingerprint", "")),
            _parse_status(alert.get("status")).value,
            _positive_integer(alert.get("occurrence_count"), 1),
            _parse_datetime(alert.get("first_seen")),
            _parse_datetime(alert.get("last_seen")),
            str(alert.get("severity", "")),
            _risk_score(alert.get("risk_score")),
            str(alert.get("database", "")),
            str(alert.get("username", "")),
            str(alert.get("client_ip", "")),
            str(alert.get("classification", "")),
            str(alert.get("source_system", "")),
            str(alert.get("query", "")),
            Jsonb(alert),
            _optional_text(alert.get("updated_by")),
            _optional_text(alert.get("status_note")),
            _optional_datetime(alert.get("status_updated_at")),
            _optional_text(alert.get("last_action")),
        ),
    )


def _insert_event(
    cursor: Any,
    schema: str,
    *,
    alert_id: str,
    event_type: str,
    timestamp: str,
    actor: str | None,
    note: str | None,
    batch_id: str | None,
    payload: dict[str, Any],
) -> None:
    cursor.execute(
        sql.SQL(
            """
            INSERT INTO {}.alert_events(
                alert_id, event_type, timestamp, batch_id, actor, note, payload_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
        ).format(sql.Identifier(schema)),
        (
            alert_id,
            event_type,
            _parse_datetime(timestamp),
            batch_id,
            actor,
            note,
            Jsonb(payload),
        ),
    )


def _import_snapshot(cursor: Any, schema: str, alert: dict[str, Any]) -> None:
    normalized = dict(alert)
    if "fingerprint" not in normalized:
        normalized["fingerprint"] = alert_fingerprint(normalized)
    if "alert_id" not in normalized:
        normalized["alert_id"] = alert_identifier(normalized)
    _write_current_alert(cursor, schema, normalized)
    _insert_event(
        cursor,
        schema,
        alert_id=str(normalized["alert_id"]),
        event_type="migrated",
        timestamp=str(normalized.get("last_seen", _utc_timestamp())),
        actor="system",
        note="Imported from an AI-DAC lifecycle backup.",
        batch_id=_optional_text(normalized.get("batch_id")),
        payload=normalized,
    )


@contextmanager
def _connect(dsn: str) -> Iterator[Connection[dict[str, Any]]]:
    normalized = dsn.strip()
    if not normalized:
        raise AlertStoreError("AIDAC_ALERT_STORE_DSN cannot be empty.")
    connection = psycopg.connect(normalized, connect_timeout=5, row_factory=dict_row)
    try:
        yield connection
    finally:
        connection.close()


def _payload(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as error:
            raise AlertStoreError("PostgreSQL alert payload contains invalid JSON.") from error
        if isinstance(decoded, dict):
            return decoded
    raise AlertStoreError("PostgreSQL alert payload is not a JSON object.")


def _parse_status(value: object) -> AlertStatus:
    try:
        return AlertStatus(str(value))
    except ValueError as error:
        raise AlertStoreError(f"Invalid alert status: {value}") from error


def _positive_integer(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, (str, float)):
        try:
            parsed = int(value)
        except ValueError:
            return default
    else:
        return default
    return parsed if parsed > 0 else default


def _risk_score(value: object) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float, str)):
        try:
            parsed = float(value)
        except ValueError:
            return 0.0
    else:
        return 0.0
    return min(max(parsed, 0.0), 1.0)


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _text_timestamp(value: object, default: str) -> str:
    if value is None:
        return default
    return _parse_datetime(value).isoformat()


def _optional_datetime(value: object) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    return _parse_datetime(value)


def _parse_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        normalized = str(value).strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as error:
            raise AlertStoreError(f"Invalid alert timestamp: {value}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _validate_query_parameters(*, minimum_risk: float, limit: int, offset: int) -> None:
    if not 0.0 <= minimum_risk <= 1.0:
        raise AlertStoreError("Minimum risk must be between 0.0 and 1.0.")
    if not 1 <= limit <= 100_000:
        raise AlertStoreError("Limit must be between 1 and 100000.")
    if offset < 0:
        raise AlertStoreError("Offset cannot be negative.")


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as error:
        raise AlertStoreError(f"Unable to prepare private directory: {path}") from error


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()
