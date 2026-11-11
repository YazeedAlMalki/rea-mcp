"""GhidraMCP 2.0 wire dialect (``LaurieWired/GhidraMCP`` tag ``2.0``).

GhidraMCP 2.0 is a rewrite of the plugin, not an update of 1.x: it serves snake_case routes
(``/functions``, not ``/methods``) and wraps every reply in a JSON envelope
(``{"success": true, "data": ...}`` or ``{"success": false, "error": {"code", "message"}}``).

Every route, parameter and reply shape below was read from the plugin's own source at that tag
(``BackendHttpServer.registerRoutes``, ``core/Model.java``, ``core/Page.java``, ``http/Json.java``),
not from the 1.x bridge. The dialect is selected by ``GET /health``, which only 2.x answers.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from pydantic import JsonValue, TypeAdapter, ValidationError

from rea_mcp.adapters.base import json_item, safe_label
from rea_mcp.core.models import BackendItem, Capability
from rea_mcp.core.router import BackendError

UNKNOWN_ENDPOINT: Final = "UNKNOWN_ENDPOINT"
SUPPORTED_MAJOR: Final = "2"
TRUNCATED_NOTE: Final = "\n/* [rea-mcp] GhidraMCP truncated this decompilation */"
_JSON: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


@dataclass(frozen=True, slots=True)
class Health:
    version: str
    ghidra_version: str
    mode: str
    program: str | None  # None: the plugin is up but no program is open in a CodeBrowser

    def describe(self) -> str:
        program = self.program if self.program is not None else "no program open"
        return f"GhidraMCP {self.version} on Ghidra {self.ghidra_version} ({self.mode}); program: {program}"


@dataclass(frozen=True, slots=True)
class Envelope:
    success: bool
    data: JsonValue
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class V2Route:
    method: Literal["GET", "POST"]
    path: str
    params: tuple[tuple[str, str], ...]  # (semantic, wire)
    paged: bool = False


def _text(value: JsonValue) -> str:
    return value if isinstance(value, str) else ""


def parse_envelope(text: str) -> Envelope | None:
    """The reply as an envelope, or ``None`` when it is not one (so nothing is mistaken for GhidraMCP 2.0)."""
    try:
        value = _JSON.validate_json(text)
    except ValidationError:
        return None
    if not isinstance(value, dict):
        return None
    success = value.get("success")
    if not isinstance(success, bool):
        return None
    if success:
        return Envelope(True, value["data"], "", "") if "data" in value else None
    error = value.get("error")
    if not isinstance(error, dict):
        return None
    return Envelope(False, None, _text(error.get("code")), _text(error.get("message")))


def parse_health(text: str) -> Health | None:
    """``None`` when the reply is not a 2.x health envelope; ``BackendError`` for a 2.x we do not speak."""
    envelope = parse_envelope(text)
    if envelope is None or not envelope.success or not isinstance(envelope.data, dict):
        return None
    version = envelope.data.get("version")
    if not isinstance(version, str):
        return None
    if version.split(".", 1)[0] != SUPPORTED_MAJOR:
        raise BackendError(f"GhidraMCP reports version {version[:20]!r}; this adapter speaks 1.x and 2.x only")
    program = envelope.data.get("program")
    name = _text(program.get("name")) if isinstance(program, dict) else ""
    return Health(
        version=version[:20],
        ghidra_version=_text(envelope.data.get("ghidra_version"))[:20] or "?",
        mode=_text(envelope.data.get("mode"))[:20] or "?",
        program=name[:120] if name else None,
    )


def _compact(value: JsonValue) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _element(element: JsonValue, index: int) -> BackendItem:
    if isinstance(element, dict):
        instruction = element.get("instruction")
        address = element.get("address")
        if isinstance(instruction, str) and isinstance(address, str):  # a disassembly line
            raw = _text(element.get("bytes"))
            comment = _text(element.get("comment"))
            line = f"{address}  {raw}  {instruction}" + (f"  ; {comment}" if comment else "")
            return BackendItem(label=safe_label(address), text=line)
    return json_item(element, index, "artifact")


def render_data(data: JsonValue, default_label: str) -> list[BackendItem]:
    """``Page`` -> one item per element; ``Decompilation`` -> its code; anything else -> compact JSON."""
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [_element(e, i) for i, e in enumerate(items)]
        code = data.get("code")
        if isinstance(code, str):
            function = data.get("function")
            name = _text(function.get("name")) if isinstance(function, dict) else ""
            text = code + (TRUNCATED_NOTE if data.get("truncated") is True else "")
            return [BackendItem(label=safe_label(name or default_label), text=text or "(empty)")]
    return [BackendItem(label=safe_label(default_label), text=_compact(data))]


def truncation_note(data: JsonValue) -> BackendItem | None:
    """A page the plugin cut short for a capability that cannot be paged: say so instead of hiding it."""
    if not isinstance(data, dict) or data.get("has_more") is not True:
        return None
    items = data.get("items")
    if not isinstance(items, list):
        return None
    total = data.get("total")
    of = f" of {total}" if isinstance(total, int) and not isinstance(total, bool) else ""
    text = f"[rea-mcp] GhidraMCP returned {len(items)}{of} entries; more exist and this capability cannot page"
    return BackendItem(label="truncated", text=text, channel="host")


_PAGE: Final = (("offset", "offset"), ("limit", "limit"))
_FILTER: Final = (("filter", "filter"),)
_ADDR: Final = (("address", "address"),)


def _get(path: str, params: tuple[tuple[str, str], ...], *, paged: bool = False) -> V2Route:
    return V2Route("GET", path, params, paged)


def _post(path: str, params: tuple[tuple[str, str], ...]) -> V2Route:
    return V2Route("POST", path, params)


V2_ROUTES: Final[Mapping[tuple[Capability, str], tuple[V2Route, ...]]] = {
    (Capability.LIST_FUNCTIONS, ""): (_get("/functions", _PAGE + _FILTER, paged=True),),
    (Capability.LIST_IMPORTS, ""): (_get("/imports", _PAGE, paged=True),),
    (Capability.LIST_EXPORTS, ""): (_get("/exports", _PAGE, paged=True),),
    (Capability.LIST_STRINGS, ""): (_get("/strings", _PAGE + _FILTER, paged=True),),
    (Capability.LIST_SEGMENTS, ""): (_get("/segments", _PAGE, paged=True),),
    (Capability.LIST_NAMESPACES, ""): (_get("/namespaces", _PAGE, paged=True),),
    (Capability.LIST_GLOBALS, ""): (_get("/data", _PAGE, paged=True),),
    (Capability.SEARCH_FUNCTIONS, ""): (_get("/functions", (("pattern", "filter"),) + _PAGE, paged=True),),
    (Capability.DECOMPILE, "name"): (_get("/decompile", (("name", "name"),)),),
    (Capability.DECOMPILE, "address"): (_get("/decompile_function", _ADDR),),
    (Capability.DISASM, ""): (_get("/disassemble_function", _ADDR),),
    (Capability.FUNCTION_INFO, ""): (_get("/function", _ADDR),),
    (Capability.XREFS_TO, ""): (_get("/xrefs_to", _ADDR + _PAGE, paged=True),),
    (Capability.XREFS_FROM, ""): (_get("/xrefs_from", _ADDR + _PAGE, paged=True),),
    (Capability.RENAME_SYMBOL, ""): (  # a function first, then a data label: nothing changes on a failed try
        _post("/rename_function_by_address", (("address", "function_address"), ("new_name", "new_name"))),
        _post("/rename_data", (("address", "address"), ("new_name", "new_name"))),
    ),
    (Capability.RENAME_VARIABLE, ""): (
        _post("/rename_variable", (("function_address", "function_address"), ("old_name", "old_name"), ("new_name", "new_name"))),
    ),
    (Capability.SET_COMMENT, "decompiler"): (
        _post("/set_decompiler_comment", (("address", "address"), ("comment", "comment"))),
    ),
    (Capability.SET_COMMENT, "disasm"): (
        _post("/set_disassembly_comment", (("address", "address"), ("comment", "comment"))),
    ),
    (Capability.SET_FUNCTION_PROTOTYPE, ""): (
        _post("/set_function_prototype", (("address", "function_address"), ("declaration", "prototype"))),
    ),
    (Capability.SET_VARIABLE_TYPE, ""): (
        _post(
            "/set_local_variable_type",
            (("address", "function_address"), ("variable_name", "variable_name"), ("declaration", "new_type")),
        ),
    ),
}


def v2_supports(capability: Capability) -> bool:
    return any(key[0] is capability for key in V2_ROUTES)
