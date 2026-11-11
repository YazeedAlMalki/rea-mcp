"""``rea-mcp-register``: add the ``rea`` server from ``mcp.host.json`` to an MCP client's config file.

    rea-mcp-register --host-config ~/workspace/rea-data/mcp.host.json --config <client config file>

Works on any file that keeps servers under a top-level ``mcpServers`` object (Claude Desktop's
``claude_desktop_config.json``, a project ``.mcp.json``, Cursor's ``mcp.json``). It only adds or updates
the ``rea`` entry: every other server and setting is kept as it was. The old file is copied to
``<file>.bak`` first (``.bak.1``, ``.bak.2``... if that exists), and the new file replaces it atomically
with the same permissions. An existing, different ``rea`` entry is left alone unless ``--replace`` is given.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

SERVER_NAME = "rea"


class RegisterError(Exception):
    """A reason the config cannot be changed safely."""


def _load_object(path: Path, what: str) -> dict[str, object]:
    try:
        loaded: object = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise RegisterError(f"{what} {path}: cannot read ({exc.strerror})") from exc
    except ValueError as exc:
        raise RegisterError(f"{what} {path}: not valid JSON ({exc})") from exc
    if not isinstance(loaded, dict):
        raise RegisterError(f"{what} {path}: expected a JSON object")
    return {str(k): v for k, v in loaded.items()}


def rea_entry(host_config: Path) -> object:
    servers = _load_object(host_config, "host config").get("mcpServers")
    if not isinstance(servers, dict) or SERVER_NAME not in servers:
        raise RegisterError(f"host config {host_config}: no mcpServers.{SERVER_NAME} entry (run rea-mcp-bootstrap)")
    return servers[SERVER_NAME]


def _backup(path: Path) -> Path:
    candidate = path.with_name(path.name + ".bak")
    number = 0
    while candidate.exists():
        number += 1
        candidate = path.with_name(f"{path.name}.bak.{number}")
    shutil.copy2(path, candidate)
    return candidate


def register(host_config: Path, config: Path, *, replace: bool = False) -> str:
    """Merge the entry into ``config`` (created if missing). Returns a one-line summary."""
    entry = rea_entry(host_config)
    existing = config.exists()
    current = _load_object(config, "client config") if existing else {}
    servers_value = current.get("mcpServers", {})
    if not isinstance(servers_value, dict):
        raise RegisterError(f"client config {config}: mcpServers is not an object")
    servers = {str(k): v for k, v in servers_value.items()}
    if servers.get(SERVER_NAME) == entry:
        return f"{config}: already registered, nothing changed ({len(servers)} server(s))"
    if SERVER_NAME in servers and not replace:
        raise RegisterError(f"{config}: a different '{SERVER_NAME}' entry exists; use --replace to overwrite it")
    backup = _backup(config) if existing else None
    merged = {**current, "mcpServers": {**servers, SERVER_NAME: entry}}
    config.parent.mkdir(parents=True, exist_ok=True)
    mode = config.stat().st_mode & 0o777 if existing else 0o600
    descriptor, temporary_name = tempfile.mkstemp(dir=config.parent, prefix=".rea-register.")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(merged, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, config)
    finally:
        temporary.unlink(missing_ok=True)
    kept = ", ".join(sorted(name for name in servers if name != SERVER_NAME)) or "none"
    saved = f"backup {backup}" if backup is not None else "new file"
    return f"{config}: registered '{SERVER_NAME}' ({saved}); other servers kept: {kept}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rea-mcp-register", description=__doc__.splitlines()[0])
    parser.add_argument("--host-config", type=Path, required=True, help="the mcp.host.json written by rea-mcp-bootstrap")
    parser.add_argument("--config", type=Path, required=True, help="the MCP client's config file to update")
    parser.add_argument("--replace", action="store_true", help="overwrite a different existing 'rea' entry")
    args = parser.parse_args(argv)
    try:
        print(register(args.host_config.expanduser(), args.config.expanduser(), replace=args.replace))
    except RegisterError as exc:
        print(f"rea-mcp-register: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
