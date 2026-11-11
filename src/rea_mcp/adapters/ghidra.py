"""Ghidra adapter (``LaurieWired/GhidraMCP`` Java plugin, plain HTTP REST at ``127.0.0.1:8080``).

Two wire dialects exist and the adapter picks one per connection with ``GET /health``:

* **2.0** (``/health`` answers a JSON envelope): the routes and reply shapes in ``ghidra_v2``,
  read from the plugin's own source. Replies are JSON, errors are typed (``code``/``message``).
* **legacy** (anything else): the 1.x plain-text routes below.

Legacy details. Every route carries a provenance:

* ``SPEC``: the operator-supplied contract in the Phase 2 brief (declared binding): ``/methods``,
  ``/decompile?name=``, ``/Imports``, ``/Exports``, ``/strings``, ``/segments``, ``/renameData``,
  ``/renameVariable``, ``/setDecompilerComment``, ``/setDisassemblyComment``,
  ``/setFunctionPrototype``, ``/setLocalVariableType`` (camelCase parameters).
* ``OBSERVED``: routes seen in the project's Python bridge during Phase 1 research
  (``decompile_function``, ``disassemble_function``, ``xrefs_to``, ``get_function_by_address``,
  snake_case mutators ...). Not verified against the current Java plugin; the bridge file may be stale.

The two sets disagree in places (capitalisation, camelCase vs snake_case, name-based vs
address-based decompile). The adapter does not guess: routes for a capability are tried in order, a
404 (or, for mutators, a plain-text failure reply) moves on to the next one, and a 404 is
remembered. ``allow_observed_routes=False`` restricts the adapter to the brief's routes.

Ghidra replies in plain text, so list endpoints are split by line and mutators are judged by a
text heuristic (``looks_like_failure``); both are best-effort and covered by tests, not by the plugin.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

from rea_mcp.adapters.base import (
    Addr,
    HttpReply,
    LoopbackHttp,
    Sem,
    Split,
    hex_address,
    semantic_args,
    split_items,
    subkey,
)
from rea_mcp.adapters.ghidra_v2 import (
    UNKNOWN_ENDPOINT,
    V2_ROUTES,
    Health,
    V2Route,
    parse_envelope,
    parse_health,
    render_data,
    truncation_note,
    v2_supports,
)
from rea_mcp.core.models import (
    BackendKind,
    BackendResult,
    Capability,
    FindBytesArgs,
    PagedListArgs,
    RenameVariableArgs,
    SearchArgs,
    SecurityTier,
)
from rea_mcp.core.paging import GenerationCounter, window
from rea_mcp.core.router import BackendCall, BackendError, UnsupportedOperationError
from rea_mcp.core.security import tier_of

GHIDRA_URL: Final = "http://127.0.0.1:8080"
_FAILURE_PREFIXES: Final = (
    "failed", "error", "could not", "unable", "invalid", "no function", "function not found",
    "not found", "no such", "cannot",
)
_FUNCTION_NAME: Final = (
    re.compile(r"(?im)^\s*function:\s*(\S+)"),
    re.compile(r"(?m)^(\S+)\s+at\s+\S+"),
)


class Provenance(StrEnum):
    SPEC = "operator_spec"
    OBSERVED = "bridge_observed"


class Dialect(StrEnum):
    LEGACY = "legacy"
    V2 = "2.0"


@dataclass(frozen=True, slots=True)
class Route:
    method: Literal["GET", "POST"]
    path: str
    params: tuple[tuple[str, str], ...]  # (semantic, wire)
    provenance: Provenance
    split: Split = Split.WHOLE
    paged: bool = False


RouteKey = tuple[Capability, str]
_S: Final = Provenance.SPEC
_O: Final = Provenance.OBSERVED
_PAGE: Final = (("offset", "offset"), ("limit", "limit"))
_FILTER: Final = (("filter", "filter"),)
_ADDR_ONLY: Final = (("address", "address"),)


def _get(path: str, params: tuple[tuple[str, str], ...], prov: Provenance, *, paged: bool = False) -> Route:
    return Route("GET", path, params, prov, Split.LINES if paged else Split.WHOLE, paged)


def _post(path: str, params: tuple[tuple[str, str], ...], prov: Provenance) -> Route:
    return Route("POST", path, params, prov)


ROUTES: Final[Mapping[RouteKey, tuple[Route, ...]]] = {
    (Capability.LIST_FUNCTIONS, ""): (_get("/methods", _PAGE, _S, paged=True),),
    (Capability.LIST_IMPORTS, ""): (
        _get("/Imports", _PAGE, _S, paged=True), _get("/imports", _PAGE, _O, paged=True),
    ),
    (Capability.LIST_EXPORTS, ""): (
        _get("/Exports", _PAGE, _S, paged=True), _get("/exports", _PAGE, _O, paged=True),
    ),
    (Capability.LIST_STRINGS, ""): (_get("/strings", _PAGE + _FILTER, _S, paged=True),),
    (Capability.LIST_SEGMENTS, ""): (_get("/segments", _PAGE, _S, paged=True),),
    (Capability.LIST_NAMESPACES, ""): (_get("/namespaces", _PAGE, _O, paged=True),),
    (Capability.LIST_GLOBALS, ""): (_get("/data", _PAGE, _O, paged=True),),
    (Capability.SEARCH_FUNCTIONS, ""): (
        _get("/searchFunctions", (("pattern", "query"), *_PAGE), _O, paged=True),
    ),
    (Capability.DECOMPILE, "name"): (_get("/decompile", (("name", "name"),), _S),),
    (Capability.DECOMPILE, "address"): (_get("/decompile_function", _ADDR_ONLY, _O),),
    (Capability.DISASM, ""): (_get("/disassemble_function", _ADDR_ONLY, _O),),
    (Capability.FUNCTION_INFO, ""): (_get("/get_function_by_address", _ADDR_ONLY, _O),),
    (Capability.XREFS_TO, ""): (_get("/xrefs_to", _ADDR_ONLY + _PAGE, _O, paged=True),),
    (Capability.XREFS_FROM, ""): (_get("/xrefs_from", _ADDR_ONLY + _PAGE, _O, paged=True),),
    (Capability.RENAME_SYMBOL, ""): (
        _post("/renameData", (("address", "address"), ("new_name", "newName")), _S),
        _post("/rename_function_by_address", (("address", "function_address"), ("new_name", "new_name")), _O),
    ),
    (Capability.RENAME_VARIABLE, ""): (
        _post(
            "/renameVariable",
            (("function_name", "functionName"), ("old_name", "oldName"), ("new_name", "newName")),
            _S,
        ),
    ),
    (Capability.SET_COMMENT, "decompiler"): (
        _post("/setDecompilerComment", (("address", "address"), ("comment", "comment")), _S),
        _post("/set_decompiler_comment", (("address", "address"), ("comment", "comment")), _O),
    ),
    (Capability.SET_COMMENT, "disasm"): (
        _post("/setDisassemblyComment", (("address", "address"), ("comment", "comment")), _S),
        _post("/set_disassembly_comment", (("address", "address"), ("comment", "comment")), _O),
    ),
    (Capability.SET_FUNCTION_PROTOTYPE, ""): (
        _post("/setFunctionPrototype", (("address", "functionAddress"), ("declaration", "prototype")), _S),
        _post("/set_function_prototype", (("address", "function_address"), ("declaration", "prototype")), _O),
    ),
    (Capability.SET_VARIABLE_TYPE, ""): (
        _post(
            "/setLocalVariableType",
            (("address", "functionAddress"), ("variable_name", "variableName"), ("declaration", "newType")),
            _S,
        ),
        _post(
            "/set_local_variable_type",
            (("address", "function_address"), ("variable_name", "variable_name"), ("declaration", "new_type")),
            _O,
        ),
    ),
}


_FAILURE_MARKER: Final = re.compile(
    r"(?i)\b(?:failed|failure|error|could not|unable to|not found|no function|invalid|cannot)\b"
)


def looks_like_failure(text: str, *, mutating: bool = False) -> bool:
    """Ghidra answers 200 with prose. Reads: failure only if the reply *starts* like one (decompiled
    code may legitimately mention 'error'). Mutators: any failure word in the first line."""
    head = text.strip()
    if not head or head.lower().startswith(_FAILURE_PREFIXES):
        return True
    return mutating and _FAILURE_MARKER.search(head.splitlines()[0][:200]) is not None


_SIGNATURE_NAME: Final = re.compile(r"([A-Za-z_][\w$@?:.~]*)\s*\(")
_NOT_A_NAME: Final = frozenset({"if", "while", "for", "switch", "return", "sizeof"})


def _signature_name(pseudocode: str) -> str | None:
    """Function name from the first code line of decompiler output (comments skipped)."""
    for line in pseudocode.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        for match in _SIGNATURE_NAME.finditer(stripped):
            if match.group(1) not in _NOT_A_NAME:
                return match.group(1)
        return None
    return None


def wire_value(value: Sem) -> str:
    if isinstance(value, Addr):
        return hex_address(value.value)
    if isinstance(value, tuple):
        return ",".join(hex_address(a.value) for a in value)
    return str(value).lower() if isinstance(value, bool) else str(value)


class GhidraBackend:
    def __init__(self, http: LoopbackHttp, *, allow_observed_routes: bool = True) -> None:
        self._http = http
        self._routes: dict[RouteKey, tuple[Route, ...]] = {
            key: tuple(r for r in routes if allow_observed_routes or r.provenance is Provenance.SPEC)
            for key, routes in ROUTES.items()
        }
        self._dead: dict[RouteKey, set[str]] = {}  # 404'd paths, skipped on later calls
        self._gen = GenerationCounter()
        self._allow_observed = allow_observed_routes
        self._dialect: Dialect | None = None  # unknown until the first successful /health round trip
        self._health: Health | None = None

    @property
    def dialect(self) -> Dialect | None:
        return self._dialect

    @property
    def health(self) -> Health | None:
        return self._health

    def describe(self) -> str:
        if self._dialect is Dialect.V2 and self._health is not None:
            return self._health.describe()
        if self._dialect is Dialect.LEGACY:
            return "GhidraMCP 1.x plain-text routes (no /health)"
        return "GhidraMCP (dialect not detected)"

    async def detect(self) -> Dialect:
        """Pick the wire dialect once. A failed round trip (unreachable, timed out) is never cached."""
        if self._dialect is not None:
            return self._dialect
        reply = await self._http.request("GET", "/health")
        health = parse_health(reply.text) if reply.status == 200 else None
        if health is None:
            self._dialect = Dialect.LEGACY
        else:
            self._health, self._dialect = health, Dialect.V2
        return self._dialect

    @classmethod
    def connect_to(cls, url: str = GHIDRA_URL, *, allow_observed_routes: bool = True) -> GhidraBackend:
        return cls(LoopbackHttp(url), allow_observed_routes=allow_observed_routes)

    @property
    def kind(self) -> BackendKind:
        return BackendKind.GHIDRA

    async def aclose(self) -> None:
        await self._http.aclose()

    def supports(self, capability: Capability) -> bool:
        """Static route table of the detected dialect; before detection, either dialect (a superset)."""
        if self._dialect is Dialect.V2:
            return v2_supports(capability)
        has_route = any(key[0] is capability and routes for key, routes in self._routes.items())
        if capability is Capability.RENAME_VARIABLE:
            has_route = has_route and bool(self._routes.get((Capability.FUNCTION_INFO, "")))
        return has_route or (self._dialect is None and v2_supports(capability))

    async def execute(self, call: BackendCall) -> BackendResult:
        if await self.detect() is Dialect.V2:
            return await self._execute_v2(call)
        return await self._execute_legacy(call)

    async def _execute_v2(self, call: BackendCall) -> BackendResult:
        key = (call.capability, subkey(call.args))
        routes = V2_ROUTES.get(key, ())
        if not routes:
            raise UnsupportedOperationError(f"ghidra cannot {call.capability.value} with these arguments")
        sem = dict(semantic_args(call.args, call.offset, call.resolved_path))
        mutating = tier_of(call.capability) is not SecurityTier.READ_ONLY
        last = "no usable route"
        for route in routes:
            if any(name not in dict(route.params) for name in sem):
                last = f"{route.path} cannot honor all arguments"
                continue
            reply = await self._send_v2(route, sem)
            envelope = parse_envelope(reply.text)
            if envelope is None:  # a 2.x /health was seen, so a non-envelope reply is a fault, not an answer
                raise BackendError(f"ghidra bridge sent a reply that is not a JSON envelope (HTTP {reply.status})")
            if not envelope.success:
                last = "route not found (404)" if envelope.code == UNKNOWN_ENDPOINT else (
                    f"{envelope.code or 'ERROR'}: {envelope.message}"[:200]
                )
                if mutating and len(routes) > 1:
                    continue  # nothing changed; try the next route
                raise BackendError(last)
            if reply.status >= 400:
                raise BackendError(f"ghidra bridge returned HTTP {reply.status}")
            if mutating:
                self._gen.bump()
            items = render_data(envelope.data, call.capability.value)
            if route.paged and isinstance(call.args, (PagedListArgs, SearchArgs, FindBytesArgs)):
                return window(items, call.args.limit, call.offset, self._gen.value)
            note = truncation_note(envelope.data)
            if note is not None:
                items.append(note)
            return BackendResult(items=tuple(items), next_offset=None, generation=self._gen.value)
        raise BackendError(last)

    async def _send_v2(self, route: V2Route, sem: Mapping[str, Sem]) -> HttpReply:
        wire = {dict(route.params)[name]: wire_value(value) for name, value in sem.items()}
        if route.method == "GET":
            return await self._http.request("GET", route.path, params=wire)
        return await self._http.request("POST", route.path, form=wire)

    async def _execute_legacy(self, call: BackendCall) -> BackendResult:
        key = (call.capability, subkey(call.args))
        routes = self._routes.get(key, ())
        if not routes:
            raise UnsupportedOperationError(f"ghidra cannot {call.capability.value} with these arguments")
        sem = dict(semantic_args(call.args, call.offset, call.resolved_path))
        if isinstance(call.args, RenameVariableArgs):  # the spec route is name-based
            sem["function_name"] = await self._function_name(call.args.function_address)
            del sem["function_address"]
        mutating = tier_of(call.capability) is not SecurityTier.READ_ONLY
        last = "no usable route"
        for route in routes:
            if route.path in self._dead.get(key, set()):
                continue
            if any(name not in dict(route.params) for name in sem):
                last = f"{route.path} cannot honor all arguments"
                continue
            reply = await self._send(route, sem)
            if reply.status == 404:
                self._dead.setdefault(key, set()).add(route.path)
                last = "route not found (404)"
                continue
            if reply.status >= 400:
                raise BackendError(f"ghidra bridge returned HTTP {reply.status}")
            text = reply.text.strip()
            if route.split is Split.WHOLE and looks_like_failure(text, mutating=mutating):
                last = text[:200] or "empty reply"
                if mutating:
                    continue  # nothing changed; try the next route
                raise BackendError(last)
            if mutating:
                self._gen.bump()
            items = split_items(text, route.split, call.capability.value)
            if route.paged and isinstance(call.args, (PagedListArgs, SearchArgs, FindBytesArgs)):
                return window(items, call.args.limit, call.offset, self._gen.value)
            return BackendResult(items=tuple(items), next_offset=None, generation=self._gen.value)
        raise BackendError(last)

    async def _send(self, route: Route, sem: Mapping[str, Sem]) -> HttpReply:
        wire = {dict(route.params)[name]: wire_value(value) for name, value in sem.items()}
        if route.method == "GET":
            return await self._http.request("GET", route.path, params=wire)
        return await self._http.request("POST", route.path, form=wire)

    async def _function_name(self, address: int) -> str:
        """``/get_function_by_address``, else the signature line of the decompiled function."""
        for route in self._routes.get((Capability.FUNCTION_INFO, ""), ()):
            reply = await self._send(route, {"address": Addr(address)})
            if reply.status == 404:
                continue
            for pattern in _FUNCTION_NAME:
                match = pattern.search(reply.text)
                if match is not None and not looks_like_failure(match.group(1)):
                    return match.group(1)
        if self._allow_observed:
            for path in ("/decompile_function", "/decompile"):
                reply = await self._send(
                    Route("GET", path, _ADDR_ONLY, Provenance.OBSERVED), {"address": Addr(address)}
                )
                if reply.status >= 400 or looks_like_failure(reply.text):
                    continue
                name = _signature_name(reply.text)
                if name is not None:
                    return name
        raise BackendError("could not resolve a function name for that address")
