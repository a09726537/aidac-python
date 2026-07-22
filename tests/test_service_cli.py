from __future__ import annotations

from pathlib import Path

from aidac.service_cli import render_systemd_unit


def test_render_systemd_unit_is_hardened_and_uses_json_logging(tmp_path: Path) -> None:
    unit = render_systemd_unit(
        executable=tmp_path / ".venv/bin/aidac",
        env_file=tmp_path / ".config/aidac/aidac.env",
        state_dir=tmp_path / ".local/state/aidac",
        share_dir=tmp_path / ".local/share/aidac",
        host="127.0.0.1",
        port=8000,
        dashboard=True,
    )
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "UMask=0077" in unit
    assert "--dashboard" in unit
    assert "--log-format json" in unit
    assert "Restart=on-failure" in unit
