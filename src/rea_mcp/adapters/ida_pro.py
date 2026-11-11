"""IDA Pro adapter (``mrexodia/ida-pro-mcp``, MCP over HTTP at ``127.0.0.1:13337/mcp``).

Wire names come from two sources, tried in this order for every capability and checked against
the live ``tools/list`` schema at start-up:

1. ``SPEC_VARIANTS``: the operator-supplied contract (``decompile_function``, ``list_functions``,
   ``get_xrefs_to``, ``rename_function`` ...), which the Phase 2 brief declares binding.
2. ``README_VARIANTS``: the tool names in the project's current README (``decompile``, ``disasm``,
   ``list_funcs``, ``imports``, ``find_bytes``, ``callgraph``, ``idb_open`` ...). The README gives
   names but not argument names, so each argument lists candidate names and is resolved against the
   live schema. Anything that cannot be matched is reported by ``diagnostics()`` and stays
   unsupported.

Never reachable from this adapter, by construction and by deny-list: ``py_eval``, ``dbg_*``,
``patch``/``patch_asm``/``put_int``, ``idb_save`` and ``idb_close(save=True)``. The router already
refuses those capabilities without the operator override; this adapter has no wire mapping for them.
"""

from __future__ import annotations

from typing import Final

from rea_mcp.adapters.base import (
    BatchSpec,
    ItemField,
    LoopbackHttp,
    McpHttpClient,
    McpToolBackend,
    Profile,
    ProfileKey,
    Split,
    ToolVariant,
    WireArg,
)
from rea_mcp.core.models import BackendKind, Capability

IDA_PRO_URL: Final = "http://127.0.0.1:13337"


def _a(semantic: str, *wire: str, optional: bool = False) -> WireArg:
    return WireArg(semantic, wire or (semantic,), optional)


_PAGE: Final = (_a("offset"), _a("limit", "count", "limit"))
_ADDR: Final = ("addr", "address", "ea")
_ADDRS: Final = ("addrs", "addr", "address")

SPEC_VARIANTS: Final[dict[ProfileKey, ToolVariant]] = {
    (Capability.DECOMPILE, "address"): ToolVariant("decompile_function", (_a("address"),)),
    (Capability.DISASM, ""): ToolVariant("disassemble_function", (_a("address", "start_address"),)),
    (Capability.LIST_FUNCTIONS, ""): ToolVariant("list_functions", _PAGE, Split.JSON_ARRAY, paged=True),
    (Capability.LIST_STRINGS, ""): ToolVariant(
        "list_strings", (*_PAGE, _a("filter", optional=True)), Split.JSON_ARRAY, paged=True
    ),
    (Capability.LIST_IMPORTS, ""): ToolVariant("list_imports", _PAGE, Split.JSON_ARRAY, paged=True),
    (Capability.XREFS_TO, ""): ToolVariant("get_xrefs_to", (_a("address"),), Split.JSON_ARRAY),
    (Capability.RENAME_SYMBOL, ""): ToolVariant(
        "rename_function", (_a("address", "function_address"), _a("new_name"))
    ),
    (Capability.RENAME_VARIABLE, ""): ToolVariant(
        "rename_local_variable", (_a("function_address"), _a("old_name"), _a("new_name"))
    ),
    (Capability.SET_FUNCTION_PROTOTYPE, ""): ToolVariant(
        "set_function_prototype", (_a("address", "function_address"), _a("declaration", "prototype"))
    ),
    (Capability.SET_VARIABLE_TYPE, ""): ToolVariant(
        "set_local_variable_type",
        (_a("address", "function_address"), _a("variable_name"), _a("declaration", "new_type")),
    ),
    (Capability.SET_COMMENT, "decompiler"): ToolVariant(
        "set_decompiler_comment", (_a("address"), _a("comment"))
    ),
    (Capability.SET_COMMENT, "disasm"): ToolVariant(
        "set_disassembly_comment", (_a("address"), _a("comment"))
    ),
}

# Headless-only session tools (README-verified names; arguments are schema-resolved).
SESSION_VARIANTS: Final[dict[ProfileKey, ToolVariant]] = {
    (Capability.LIST_DATABASES, ""): ToolVariant("idb_list", (), Split.JSON_ARRAY),
    (Capability.OPEN_DATABASE, ""): ToolVariant(
        "idb_open", (_a("input_path"), _a("run_auto_analysis", optional=True))
    ),
    (Capability.CLOSE_DATABASE, ""): ToolVariant("idb_close", (_a("save"),)),
}

README_VARIANTS: Final[dict[ProfileKey, ToolVariant]] = {
    (Capability.DECOMPILE, "address"): ToolVariant("decompile", (_a("address", *_ADDR),)),
    (Capability.DISASM, ""): ToolVariant("disasm", (_a("address", *_ADDR),)),
    (Capability.XREFS_TO, ""): ToolVariant("xrefs_to", (_a("address", *_ADDRS),), Split.JSON_ARRAY),
    (Capability.CALLEES, ""): ToolVariant("callees", (_a("address", *_ADDRS),), Split.JSON_ARRAY),
    (Capability.BASIC_BLOCKS, ""): ToolVariant("basic_blocks", (_a("address", *_ADDRS),), Split.JSON_ARRAY),
    (Capability.STACK_FRAME, ""): ToolVariant("stack_frame", (_a("address", *_ADDRS),), Split.JSON_ARRAY),
    (Capability.LIST_FUNCTIONS, ""): ToolVariant("list_funcs", _PAGE, Split.JSON_ARRAY, paged=True),
    (Capability.LIST_GLOBALS, ""): ToolVariant("list_globals", _PAGE, Split.JSON_ARRAY, paged=True),
    (Capability.LIST_IMPORTS, ""): ToolVariant("imports", _PAGE, Split.JSON_ARRAY, paged=True),
    (Capability.FIND_REGEX, ""): ToolVariant(
        "find_regex", (_a("pattern", "pattern", "regex", "query"), *_PAGE), Split.JSON_ARRAY, paged=True
    ),
    (Capability.FIND_BYTES, ""): ToolVariant(
        "find_bytes", (_a("pattern", "patterns", "pattern"), *_PAGE), Split.JSON_ARRAY, paged=True
    ),
    (Capability.GET_BYTES, ""): ToolVariant(
        "get_bytes", (_a("address", *_ADDR), _a("size", "size", "length", "count"))
    ),
    (Capability.CALLGRAPH, ""): ToolVariant(
        "callgraph", (_a("roots"), _a("max_depth")), Split.JSON_ARRAY
    ),
    (Capability.READ_STRUCT, ""): ToolVariant(
        "read_struct", (_a("name", "name", "names"), _a("address", *_ADDR, optional=True)), Split.JSON_ARRAY
    ),
}


def _f(semantic: str, wire: str, *translate: tuple[str, str]) -> ItemField:
    return ItemField(semantic, wire, translate)


_KINDS: Final = (("decompiler", "decompiler"), ("disasm", "disassembly"))

# Batch writers (``0xshlomil/ida-free-mcp`` and newer ``ida-pro-mcp``): ``{"items": [{...}]}``.
BATCH_VARIANTS: Final[dict[ProfileKey, ToolVariant]] = {
    (Capability.RENAME_SYMBOL, ""): ToolVariant(
        "rename", batch=BatchSpec("items", (_f("address", "addr"), _f("new_name", "name")))
    ),
    (Capability.RENAME_VARIABLE, ""): ToolVariant(
        "rename",
        batch=BatchSpec("items", (_f("function_address", "addr"), _f("old_name", "old"), _f("new_name", "new"))),
    ),
    (Capability.SET_COMMENT, "decompiler"): ToolVariant(
        "set_comments",
        batch=BatchSpec("items", (_f("address", "addr"), _f("comment", "comment"), _f("@sub", "kind", *_KINDS))),
    ),
    (Capability.SET_COMMENT, "disasm"): ToolVariant(
        "set_comments",
        batch=BatchSpec("items", (_f("address", "addr"), _f("comment", "comment"), _f("@sub", "kind", *_KINDS))),
    ),
    (Capability.SET_TYPE, ""): ToolVariant(
        "set_type", batch=BatchSpec("items", (_f("address", "addr"), _f("declaration", "ty")))
    ),
    (Capability.SET_FUNCTION_PROTOTYPE, ""): ToolVariant(
        "set_type", batch=BatchSpec("items", (_f("address", "addr"), _f("declaration", "ty")))
    ),
}


def merged_profile(*layers: dict[ProfileKey, ToolVariant]) -> Profile:
    """Earlier layers win; later layers are fallbacks for the same capability."""
    merged: dict[ProfileKey, tuple[ToolVariant, ...]] = {}
    for layer in layers:
        for key, variant in layer.items():
            merged[key] = (*merged.get(key, ()), variant)
    return merged


IDA_PRO_PROFILE: Final[Profile] = merged_profile(
    SPEC_VARIANTS, README_VARIANTS, BATCH_VARIANTS, SESSION_VARIANTS
)


class IdaProBackend(McpToolBackend):
    """Call ``await backend.start()`` once at server start-up so ``supports()`` is truthful."""

    def __init__(self, client: McpHttpClient) -> None:
        super().__init__(BackendKind.IDA_PRO, client, IDA_PRO_PROFILE)

    @classmethod
    def connect_to(cls, url: str = IDA_PRO_URL) -> IdaProBackend:
        """Loopback-only (raises ``SecurityDenied`` for anything else); GUI plugin or ``idalib-mcp``."""
        return cls(McpHttpClient(LoopbackHttp(url)))
