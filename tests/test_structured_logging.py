from __future__ import annotations

import json
import stat
from pathlib import Path

from aidac.structured_logging import configure_logging


def test_json_logging_writes_private_structured_record(tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "aidac.jsonl"
    logger = configure_logging(log_format="json", log_file=log_file, level="info")
    logger.info(
        "request complete",
        extra={"event": "http_request", "status_code": 200, "path": "/health/live"},
    )
    for handler in logger.handlers:
        handler.flush()

    payload = json.loads(log_file.read_text(encoding="utf-8"))
    assert payload["event"] == "http_request"
    assert payload["status_code"] == 200
    assert payload["path"] == "/health/live"
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
