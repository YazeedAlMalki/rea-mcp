"""``rea-mcp-register``: merge the ``rea`` entry into a client config without losing anything."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from rea_mcp.register import RegisterError, main, register

ENTRY = {"command": "C:\\rea\\.venv\\Scripts\\python.exe", "args": ["-m", "rea_mcp"], "env": {"REA_LEDGER_DIR": "C:\\rea\\ledger"}}


def host_config(tmp_path: Path, entry: object = ENTRY) -> Path:
    path = tmp_path / "mcp.host.json"
    path.write_text(json.dumps({"mcpServers": {"rea": entry}}), encoding="utf-8")
    return path


def test_adds_rea_and_keeps_everything_else(tmp_path: Path) -> None:
    config = tmp_path / "claude_desktop_config.json"
    original = {"preferences": {"theme": "dark"}, "mcpServers": {"other": {"command": "x"}}}
    config.write_text(json.dumps(original), encoding="utf-8")
    config.chmod(0o640)
    summary = register(host_config(tmp_path), config)
    after = json.loads(config.read_text(encoding="utf-8"))
    assert after["preferences"] == original["preferences"]
    assert after["mcpServers"] == {"other": {"command": "x"}, "rea": ENTRY}
    assert "other" in summary
    backup = tmp_path / "claude_desktop_config.json.bak"
    assert json.loads(backup.read_text(encoding="utf-8")) == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o640


def test_creates_the_config_when_there_is_none(tmp_path: Path) -> None:
    config = tmp_path / "sub" / "mcp.json"
    register(host_config(tmp_path), config)
    assert json.loads(config.read_text(encoding="utf-8")) == {"mcpServers": {"rea": ENTRY}}
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert not list(config.parent.glob("*.bak*"))


def test_second_run_changes_nothing_and_makes_no_backup(tmp_path: Path) -> None:
    config = tmp_path / "c.json"
    config.write_text("{}", encoding="utf-8")
    register(host_config(tmp_path), config)
    before = config.read_bytes()
    assert "already registered" in register(host_config(tmp_path), config)
    assert config.read_bytes() == before
    assert sorted(p.name for p in tmp_path.glob("c.json.bak*")) == ["c.json.bak"]


def test_backups_are_never_overwritten(tmp_path: Path) -> None:
    config = tmp_path / "c.json"
    (tmp_path / "c.json.bak").write_text("precious", encoding="utf-8")
    config.write_text("{}", encoding="utf-8")
    register(host_config(tmp_path), config)
    assert (tmp_path / "c.json.bak").read_text(encoding="utf-8") == "precious"
    assert (tmp_path / "c.json.bak.1").read_text(encoding="utf-8") == "{}"


def test_a_different_existing_rea_is_not_overwritten_without_replace(tmp_path: Path) -> None:
    config = tmp_path / "c.json"
    config.write_text(json.dumps({"mcpServers": {"rea": {"command": "mine"}}}), encoding="utf-8")
    before = config.read_bytes()
    with pytest.raises(RegisterError, match="--replace"):
        register(host_config(tmp_path), config)
    assert config.read_bytes() == before
    assert not list(tmp_path.glob("c.json.bak*"))
    register(host_config(tmp_path), config, replace=True)
    assert json.loads(config.read_text(encoding="utf-8"))["mcpServers"]["rea"] == ENTRY


def test_a_utf8_bom_from_windows_powershell_is_accepted(tmp_path: Path) -> None:
    config = tmp_path / "c.json"
    config.write_bytes(b"\xef\xbb\xbf" + json.dumps({"mcpServers": {"a": {}}}).encode())
    register(host_config(tmp_path), config)
    assert set(json.loads(config.read_text(encoding="utf-8"))["mcpServers"]) == {"a", "rea"}


@pytest.mark.parametrize("text", ["not json", "[]", '{"mcpServers": []}'])
def test_unusable_client_config_is_refused_and_untouched(tmp_path: Path, text: str) -> None:
    config = tmp_path / "c.json"
    config.write_text(text, encoding="utf-8")
    with pytest.raises(RegisterError):
        register(host_config(tmp_path), config)
    assert config.read_text(encoding="utf-8") == text
    assert not list(tmp_path.glob("c.json.bak*"))


def test_host_config_without_rea_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "mcp.host.json"
    empty.write_text('{"mcpServers": {}}', encoding="utf-8")
    with pytest.raises(RegisterError, match="rea-mcp-bootstrap"):
        register(empty, tmp_path / "c.json")


def test_no_temporary_files_are_left_behind(tmp_path: Path) -> None:
    config = tmp_path / "c.json"
    config.write_text("{}", encoding="utf-8")
    register(host_config(tmp_path), config)
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".")) == []


def test_command_line_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "c.json"
    assert main(["--host-config", str(host_config(tmp_path)), "--config", str(config)]) == 0
    assert "registered 'rea'" in capsys.readouterr().out
    config.write_text("nope", encoding="utf-8")
    assert main(["--host-config", str(host_config(tmp_path)), "--config", str(config)]) == 1
    assert "not valid JSON" in capsys.readouterr().err
    assert os.path.exists(config)
