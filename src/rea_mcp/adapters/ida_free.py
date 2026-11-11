"""IDA Free adapter (``0xshlomil/ida-free-mcp``, native plugin, MCP over HTTP at ``:13337/mcp``).

The README lists 37 tool names in 7 groups but no argument names, so this profile uses the same
schema-resolved README names as the IDA Pro fallback layer, minus everything IDA Free does not
have (``idb_*`` sessions: it serves the one open database), plus the batch writers whose
``{"items": [...]}`` schemas the operator supplied: ``rename`` (symbols and locals),
``set_comments`` and ``set_type`` (also used for function prototypes). Not mapped, deliberately:

* ``declare_type``, ``define_func``, ``define_code``, ``undefine``, ``declare_stack``,
  ``delete_stack``, local-variable types: argument shapes still unknown; ``describe_tools()``
  prints them from the live server.
* ``patch``, ``patch_asm``, ``put_int``: privileged, no wire mapping exists.
* ``decompile`` goes through the IDA GUI pseudocode widget (no Hex-Rays SDK in this plugin), so it
  needs the pseudocode window available; a failure surfaces as a normal backend error.
"""

from __future__ import annotations

from typing import Final

from rea_mcp.adapters.base import (
    LoopbackHttp,
    McpHttpClient,
    McpToolBackend,
    Profile,
)
from rea_mcp.adapters.ida_pro import BATCH_VARIANTS, IDA_PRO_URL, README_VARIANTS, merged_profile
from rea_mcp.core.models import BackendKind

IDA_FREE_PROFILE: Final[Profile] = merged_profile(README_VARIANTS, BATCH_VARIANTS)


class IdaFreeBackend(McpToolBackend):
    """Call ``await backend.start()`` once at server start-up so ``supports()`` is truthful."""

    def __init__(self, client: McpHttpClient) -> None:
        super().__init__(BackendKind.IDA_FREE, client, IDA_FREE_PROFILE)

    @classmethod
    def connect_to(cls, url: str = IDA_PRO_URL) -> IdaFreeBackend:
        return cls(McpHttpClient(LoopbackHttp(url)))
