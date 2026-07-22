"""Structured application logging for AI-DAC services."""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_LOGGER_NAME = "aidac"
_ALLOWED_FORMATS = {"text", "json"}


class JSONLogFormatter(logging.Formatter):
    """Format one logging record as a compact JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.casefold(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in (
            "event",
            "method",
            "path",
            "status_code",
            "duration_seconds",
            "role",
            "token_id",
            "alert_id",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def configure_logging(
    *,
    log_format: str = "text",
    log_file: Path | None = None,
    level: str = "info",
) -> logging.Logger:
    """Configure the AI-DAC application logger."""

    normalized_format = log_format.strip().casefold()
    if normalized_format not in _ALLOWED_FORMATS:
        raise ValueError("Log format must be text or json.")
    normalized_level = level.strip().upper()
    numeric_level = logging.getLevelNamesMapping().get(normalized_level)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(numeric_level)
    logger.propagate = False
    logger.handlers.clear()

    formatter: logging.Formatter
    if normalized_format == "json":
        formatter = JSONLogFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

    if log_file is None:
        handler: logging.Handler = logging.StreamHandler()
    else:
        expanded = log_file.expanduser()
        expanded.parent.mkdir(parents=True, exist_ok=True)
        expanded.parent.chmod(0o700)
        descriptor = os.open(expanded, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        stream = os.fdopen(descriptor, "a", encoding="utf-8")
        handler = logging.StreamHandler(stream)
        expanded.chmod(0o600)

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def get_logger() -> logging.Logger:
    """Return the AI-DAC application logger."""

    return logging.getLogger(_LOGGER_NAME)
