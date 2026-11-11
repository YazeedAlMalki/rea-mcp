"""The ``mcp.host.json`` file: written by ``rea-mcp-bootstrap``, read by ``rea-mcp-doctor``.

It is the common ``{"mcpServers": {name: {command, args, env}}}`` shape that Claude Code, Cursor and
most MCP hosts import. It holds paths and loopback URLs only, never secrets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from pydantic import Field, ValidationError

from rea_mcp.core.models import StrictModel

HOST_CONFIG_NAME: Final = "mcp.host.json"
SERVER_KEY: Final = "rea"
MAX_HOST_CONFIG_BYTES: Final = 64 * 1024


class HostConfigError(ValueError):
    """The file is missing, unreadable, or not a valid host config."""


class HostServer(StrictModel):
    command: str = Field(min_length=1)
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)


class HostConfig(StrictModel):
    mcpServers: dict[str, HostServer]  # noqa: N815  (the wire name used by MCP hosts)


def render(server: HostServer) -> str:
    document = HostConfig(mcpServers={SERVER_KEY: server})
    return document.model_dump_json(indent=2) + "\n"


def load(path: Path) -> HostServer:
    """Return the ``rea`` entry. Strict: unknown fields, other server names and oversized files are errors."""
    try:
        if path.stat().st_size > MAX_HOST_CONFIG_BYTES:
            raise HostConfigError(f"{path}: larger than {MAX_HOST_CONFIG_BYTES} bytes")
        raw = path.read_bytes()
    except OSError as exc:
        raise HostConfigError(f"{path}: cannot be read ({type(exc).__name__})") from exc
    try:
        document = HostConfig.model_validate_json(raw)
    except ValidationError as exc:
        where = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors()[:3])
        raise HostConfigError(f"{path}: not a valid host config ({where})") from exc
    server = document.mcpServers.get(SERVER_KEY)
    if server is None:
        raise HostConfigError(f"{path}: no {SERVER_KEY!r} server entry")
    return server
