"""Shared adapter plumbing (Phase 2).

* ``LoopbackHttp``: the only network primitive adapters may use. Literal-loopback targets only
  (``127.0.0.1`` / ``::1``: no DNS, no ``localhost``), redirects disabled (nac), ambient proxy
  settings ignored (``trust_env=False``, otherwise ``HTTP(S)_PROXY`` could carry loopback
  traffic off-box), strict connect/read/total timeouts, bounded response size, and a header
  deny-list so a caller can never override ``Host``/``Authorization``/``x-api-key``.
* ``McpHttpClient``: minimal MCP Streamable-HTTP client (JSON-RPC 2.0 over ``POST /mcp``;
  JSON or single-event SSE replies). The legacy ``GET /sse`` + ``POST /message`` transport is
  not implemented.
* ``McpToolBackend``: profile-driven backend. A profile maps each router capability to
  candidate (tool, argument-name) variants; at start-up they are checked against the live
  ``tools/list`` schema, so a wrong guess becomes "unsupported" (fail closed), never a bad call.
  Tools outside the profile are unreachable, and a deny-list rejects ``py_eval``, ``dbg_*``,
  patch/put tools and ``idb_save`` even if a profile names them by mistake.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, ValidationError

from rea_mcp.core.models import (
    MAX_SAFE_INTEGER,
    AddBookmarkArgs,
    AddressArgs,
    AnyArgs,
    BackendItem,
    BackendKind,
    BackendResult,
    CallgraphArgs,
    Capability,
    CloseDatabaseArgs,
    DeclareStackVarArgs,
    DeclareTypeArgs,
    DecompileArgs,
    DefineCodeArgs,
    DefineFunctionArgs,
    DeleteStackVarArgs,
    FindBytesArgs,
    GetBytesArgs,
    ListDatabasesArgs,
    OpenDatabaseArgs,
    PagedListArgs,
    ReadStructArgs,
    RenameSymbolArgs,
    RenameVariableArgs,
    SearchArgs,
    SecurityTier,
    SetCommentArgs,
    SetTypeArgs,
    UndefineArgs,
)
from rea_mcp.core.paging import GenerationCounter, window
from rea_mcp.core.router import BackendCall, BackendError, UnsupportedOperationError
from rea_mcp.core.security import sanitize_headers, tier_of, assert_loopback_url

# Windows takes about 2 s to refuse a connection to a closed loopback port (it retries the SYN), so the
# limit must stay above that or "nothing is listening" is reported as a timeout. Linux and macOS refuse at once.
CONNECT_TIMEOUT_S: Final = 4.0
READ_TIMEOUT_S: Final = 30.0
TOTAL_TIMEOUT_S: Final = 35.0
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
MCP_PROTOCOL_VERSION: Final = "2025-06-18"
_PATH_OK: Final = re.compile(r"^/[A-Za-z0-9_./-]{0,200}$")
_SESSION_ID_OK: Final = re.compile(r"^[\x21-\x7e]{1,256}$")
_FORBIDDEN_TOOL: Final = re.compile(r"^(?:py_eval|eval.*|exec.*|patch.*|put_int|dbg_.*|idb_save|.*_write)$")
_JSON: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


def hex_address(value: int) -> str:
    """Strict hex form used on every wire: ``0x`` + lowercase hex."""
    return f"0x{value:x}"


def safe_label(text: str) -> str:
    return text.replace("\x00", "").encode("utf-8", errors="backslashreplace").decode("utf-8")[:120] or "-"


# --------------------------------------------------------------------------- #
# Hardened loopback HTTP
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class HttpReply:
    status: int
    text: str
    content_type: str
    headers: Mapping[str, str]  # lower-cased names


UNREACHABLE: Final = "cannot reach the local backend bridge"
TIMED_OUT: Final = "backend call timed out"


class LoopbackHttp:
    def __init__(
        self,
        base_url: str,
        *,
        read_timeout_s: float = READ_TIMEOUT_S,
        total_timeout_s: float = TOTAL_TIMEOUT_S,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._base = assert_loopback_url(base_url).rstrip("/")  # raises SecurityDenied
        self._total = total_timeout_s
        self._max = max_response_bytes
        self._client = httpx.AsyncClient(
            base_url=self._base,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            timeout=httpx.Timeout(connect=CONNECT_TIMEOUT_S, read=read_timeout_s, write=5.0, pool=2.0),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            headers=sanitize_headers(default_headers or {}),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        form: Mapping[str, str] | None = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> HttpReply:
        if not _PATH_OK.fullmatch(path) or ".." in path or "//" in path:  # "//host" would replace the host
            raise BackendError("invalid request path")
        extra = sanitize_headers(headers or {})
        try:
            async with asyncio.timeout(self._total):
                async with self._client.stream(
                    method, path, params=params, data=form, content=body, headers=extra
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise BackendError("backend attempted a redirect (refused)")
                    buffer = bytearray()
                    async for chunk in response.aiter_bytes():
                        buffer += chunk
                        if len(buffer) > self._max:
                            raise BackendError("backend response exceeded the size limit")
                    return HttpReply(
                        status=response.status_code,
                        text=bytes(buffer).decode("utf-8", errors="backslashreplace"),
                        content_type=response.headers.get("content-type", ""),
                        headers={k.lower(): v for k, v in response.headers.items()},
                    )
        except TimeoutError as exc:
            raise BackendError("backend call exceeded the total deadline", retryable=True) from exc
        except httpx.ConnectError as exc:
            raise BackendError(UNREACHABLE, retryable=True) from exc
        except httpx.TimeoutException as exc:
            raise BackendError(TIMED_OUT, retryable=True) from exc
        except httpx.HTTPError as exc:
            raise BackendError(f"http failure: {type(exc).__name__}") from exc


# --------------------------------------------------------------------------- #
# MCP JSON-RPC client
# --------------------------------------------------------------------------- #


class _Inbound(BaseModel):
    """External data: typed and checked, but unknown fields are ignored (servers evolve)."""

    model_config = ConfigDict(extra="ignore", frozen=True)


class RpcError(_Inbound):
    code: int
    message: str


class RpcEnvelope(_Inbound):
    id: int | str | None = None
    result: dict[str, JsonValue] | None = None
    error: RpcError | None = None


class InputSchema(_Inbound):
    properties: dict[str, JsonValue] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)


class ToolDescriptor(_Inbound):
    name: str
    inputSchema: InputSchema = Field(default_factory=InputSchema)


class ToolsPage(_Inbound):
    tools: list[ToolDescriptor] = Field(default_factory=list)
    nextCursor: str | None = None


class ContentBlock(_Inbound):
    type: str
    text: str | None = None


class ToolCallResult(_Inbound):
    content: list[ContentBlock] = Field(default_factory=list)
    isError: bool = False


class InitializeResult(_Inbound):
    protocolVersion: str = MCP_PROTOCOL_VERSION


def _decode_rpc(reply: HttpReply, request_id: int) -> RpcEnvelope:
    if reply.status >= 400:
        raise BackendError(f"bridge returned HTTP {reply.status}")
    if "text/event-stream" in reply.content_type:
        payloads = [line[5:].strip() for line in reply.text.splitlines() if line.startswith("data:")]
    else:
        payloads = [reply.text]
    for payload in payloads:
        try:
            envelope = RpcEnvelope.model_validate_json(payload)
        except ValidationError:
            continue
        if envelope.id == request_id:
            return envelope
    raise BackendError("bridge sent no matching JSON-RPC response")


class McpHttpClient:
    def __init__(self, http: LoopbackHttp, endpoint: str = "/mcp") -> None:
        self._http = http
        self._endpoint = endpoint
        self._ids = itertools.count(1)
        self._session: str | None = None
        self._protocol = MCP_PROTOCOL_VERSION
        self._lock = asyncio.Lock()
        self.tools: dict[str, ToolDescriptor] = {}
        self.ready = False

    async def connect(self) -> None:
        async with self._lock:
            self._session = None
            self.tools = {}
            result = await self._rpc(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "rea-mcp", "version": "0.1.0"},
                },
            )
            init = InitializeResult.model_validate(result)
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", init.protocolVersion):
                self._protocol = init.protocolVersion
            await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_body=False)
            cursor: str | None = None
            for _ in range(10):
                page = ToolsPage.model_validate(
                    await self._rpc("tools/list", {} if cursor is None else {"cursor": cursor})
                )
                self.tools.update({t.name: t for t in page.tools})
                cursor = page.nextCursor
                if cursor is None:
                    break
            self.ready = True

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call_tool(self, name: str, arguments: Mapping[str, JsonValue]) -> str:
        if _FORBIDDEN_TOOL.fullmatch(name):
            raise BackendError(f"tool {name!r} is permanently blocked by the adapter")
        result = await self._rpc("tools/call", {"name": name, "arguments": dict(arguments)})
        parsed = ToolCallResult.model_validate(result)
        text = "\n".join(b.text for b in parsed.content if b.type == "text" and b.text is not None)
        if parsed.isError:
            raise BackendError(text[:240] or f"tool {name!r} reported an error")
        return text

    async def _rpc(self, method: str, params: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        request_id = next(self._ids)
        reply = await self._post(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)},
            expect_body=True,
        )
        envelope = _decode_rpc(reply, request_id)
        if envelope.error is not None:
            raise BackendError(f"bridge error {envelope.error.code}: {envelope.error.message[:160]}")
        return envelope.result if envelope.result is not None else {}

    async def _post(self, message: Mapping[str, JsonValue], *, expect_body: bool) -> HttpReply:
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        if self._session is not None:
            headers["mcp-session-id"] = self._session
            headers["mcp-protocol-version"] = self._protocol
        reply = await self._http.request(
            "POST", self._endpoint, body=json.dumps(message).encode("utf-8"), headers=headers
        )
        session = reply.headers.get("mcp-session-id")
        if session is not None and _SESSION_ID_OK.fullmatch(session):
            self._session = session
        if not expect_body and reply.status >= 400:
            raise BackendError(f"bridge returned HTTP {reply.status}")
        return reply


# --------------------------------------------------------------------------- #
# Result text -> items
# --------------------------------------------------------------------------- #


class Split(StrEnum):
    WHOLE = "whole"  # one item (pseudocode, a single confirmation)
    LINES = "lines"  # one item per non-empty line
    JSON_ARRAY = "json_array"  # one item per array element; falls back to LINES


_LABEL_KEYS: Final = ("name", "address", "addr", "func", "function", "string", "value")


def split_items(
    text: str, split: Split, default_label: str, channel: Literal["artifact", "host"] = "artifact"
) -> list[BackendItem]:
    if split is Split.WHOLE:
        return [BackendItem(label=safe_label(default_label), text=text or "(empty)", channel=channel)]
    if split is Split.JSON_ARRAY:
        elements = _elements(_parse_json(text))
        if elements is not None:
            return [json_item(e, i, channel) for i, e in enumerate(elements)]
    return [
        BackendItem(label=safe_label(line), text=line, channel=channel)
        for line in text.splitlines()
        if line.strip()
    ]


def _parse_json(text: str) -> JsonValue:
    try:
        return _JSON.validate_json(text)
    except ValidationError:
        return None


def _elements(value: JsonValue) -> list[JsonValue] | None:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for inner in value.values():
            if isinstance(inner, list):
                return inner
    return None


def json_item(element: JsonValue, index: int, channel: Literal["artifact", "host"]) -> BackendItem:
    if isinstance(element, str):
        return BackendItem(label=safe_label(element), text=element, channel=channel)
    label = f"#{index}"
    if isinstance(element, dict):
        for key in _LABEL_KEYS:
            candidate = element.get(key)
            if isinstance(candidate, (str, int)) and not isinstance(candidate, bool):
                label = str(candidate)
                break
    return BackendItem(
        label=safe_label(label),
        text=json.dumps(element, separators=(",", ":"), ensure_ascii=False),
        channel=channel,
    )


def embedded_error(text: str) -> str | None:
    """IDA-style tools report per-item failures as ``{"error": "..."}`` inside a success."""
    parsed = _parse_json(text)
    candidates: list[JsonValue] = parsed if isinstance(parsed, list) else [parsed]
    for entry in candidates:
        if isinstance(entry, dict):
            error = entry.get("error")
            if isinstance(error, str) and error:
                return error[:200]
    return None


# --------------------------------------------------------------------------- #
# Semantic arguments -> wire arguments (schema-typed)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Addr:
    value: int


Sem = int | str | bool | Addr | tuple[Addr, ...]


def semantic_args(args: AnyArgs, offset: int, resolved_path: Path | None) -> dict[str, Sem]:
    """Backend-neutral argument names; profiles translate them to each server's names."""
    if isinstance(args, DecompileArgs):
        out: dict[str, Sem] = {}
        if args.address is not None:
            out["address"] = Addr(args.address)
        if args.name is not None:
            out["name"] = args.name
        return out
    if isinstance(args, (AddressArgs, DefineCodeArgs)):
        return {"address": Addr(args.address)}
    if isinstance(args, PagedListArgs):
        paged: dict[str, Sem] = {"offset": offset, "limit": args.limit + 1}
        if args.filter is not None:
            paged["filter"] = args.filter
        return paged
    if isinstance(args, (SearchArgs, FindBytesArgs)):
        return {"pattern": args.pattern, "offset": offset, "limit": args.limit + 1}
    if isinstance(args, GetBytesArgs):
        return {"address": Addr(args.address), "size": args.size}
    if isinstance(args, CallgraphArgs):
        return {"roots": tuple(Addr(r) for r in args.roots), "max_depth": args.max_depth}
    if isinstance(args, ReadStructArgs):
        struct: dict[str, Sem] = {"name": args.name}
        if args.address is not None:
            struct["address"] = Addr(args.address)
        return struct
    if isinstance(args, ListDatabasesArgs):
        return {}
    if isinstance(args, OpenDatabaseArgs):
        if resolved_path is None:
            raise BackendError("open_database needs a resolved input path")
        return {"input_path": str(resolved_path), "run_auto_analysis": args.run_auto_analysis}
    if isinstance(args, CloseDatabaseArgs):
        return {"save": False}
    if isinstance(args, RenameSymbolArgs):
        return {"address": Addr(args.address), "new_name": args.new_name}
    if isinstance(args, RenameVariableArgs):
        return {
            "function_address": Addr(args.function_address),
            "old_name": args.old_name,
            "new_name": args.new_name,
        }
    if isinstance(args, SetCommentArgs):
        return {"address": Addr(args.address), "comment": args.comment}
    if isinstance(args, SetTypeArgs):
        typed: dict[str, Sem] = {"address": Addr(args.address), "declaration": args.declaration}
        if args.variable_name is not None:
            typed["variable_name"] = args.variable_name
        return typed
    if isinstance(args, DeclareTypeArgs):
        return {"declaration": args.declaration}
    if isinstance(args, AddBookmarkArgs):
        return {"address": Addr(args.address), "note": args.note}
    if isinstance(args, DefineFunctionArgs):
        func: dict[str, Sem] = {"start": Addr(args.start)}
        if args.end is not None:
            func["end"] = Addr(args.end)
        return func
    if isinstance(args, UndefineArgs):
        return {"address": Addr(args.address), "size": args.size}
    if isinstance(args, DeclareStackVarArgs):
        return {
            "function_address": Addr(args.function_address),
            "frame_offset": args.frame_offset,
            "name": args.name,
            "declaration": args.declaration,
        }
    if isinstance(args, DeleteStackVarArgs):
        return {"function_address": Addr(args.function_address), "name": args.name}
    raise BackendError(f"{args.capability} has no wire encoding")


def subkey(args: AnyArgs) -> str:
    """Profile sub-key for capabilities that map to different tools by argument."""
    if isinstance(args, SetCommentArgs):
        return args.kind
    if isinstance(args, DecompileArgs):
        return "name" if args.name is not None else "address"
    return ""


def schema_type(schema: InputSchema, name: str) -> str | None:
    prop = schema.properties.get(name)
    if isinstance(prop, dict):
        declared = prop.get("type")
        if isinstance(declared, str):
            return declared
        if isinstance(declared, list):
            for entry in declared:
                if isinstance(entry, str) and entry != "null":
                    return entry
    return None


def to_wire(value: Sem, declared: str | None) -> JsonValue:
    if isinstance(value, Addr):
        if declared == "integer":
            if value.value > MAX_SAFE_INTEGER:
                raise BackendError("address is too large for a numeric argument")
            return value.value
        if declared == "array":
            return [hex_address(value.value)]
        return hex_address(value.value)
    if isinstance(value, tuple):
        hexes: list[JsonValue] = [hex_address(a.value) for a in value]
        return ",".join(hex_address(a.value) for a in value) if declared == "string" else hexes
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value) if declared == "string" else value
    return [value] if declared == "array" else value


# --------------------------------------------------------------------------- #
# Profiles and the generic MCP-tool backend
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class WireArg:
    semantic: str
    wire: tuple[str, ...]  # candidate server-side names; first one in the live schema wins
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ItemField:
    """One key of a batch item. ``semantic == "@sub"`` takes the profile sub-key (e.g. comment kind)."""

    semantic: str
    wire: str
    translate: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class BatchSpec:
    """Writers that take ``{"items": [{...}]}``. Item keys are fixed by the documented schema
    (the live schema only proves the array argument exists), and one item is sent per call."""

    key: str
    fields: tuple[ItemField, ...]


@dataclass(frozen=True, slots=True)
class ToolVariant:
    tool: str
    args: tuple[WireArg, ...] = ()
    split: Split = Split.WHOLE
    paged: bool = False
    batch: BatchSpec | None = None


ProfileKey = tuple[Capability, str]
Profile = Mapping[ProfileKey, tuple[ToolVariant, ...]]


@dataclass(frozen=True, slots=True)
class ResolvedTool:
    variant: ToolVariant
    wires: Mapping[str, tuple[str, str | None]]  # semantic -> (wire name, schema type)
    schema: InputSchema


def resolve_variant(variant: ToolVariant, tool: ToolDescriptor | None) -> ResolvedTool | str:
    if tool is None:
        return f"{variant.tool}: not exposed by the server"
    props = tool.inputSchema.properties
    wires: dict[str, tuple[str, str | None]] = {}
    if variant.batch is not None:
        if variant.batch.key not in props:
            return f"{variant.tool}: no {variant.batch.key!r} array argument (server has {sorted(props)})"
        extra = [r for r in tool.inputSchema.required if r not in {variant.batch.key, "database"}]
        if extra:
            return f"{variant.tool}: required arguments {extra} are not mapped"
        return ResolvedTool(variant, wires, tool.inputSchema)
    for arg in variant.args:
        found = next((n for n in arg.wire if n in props), None)
        if found is None:
            if arg.optional:
                continue
            return f"{variant.tool}: none of {list(arg.wire)} in server arguments {sorted(props)}"
        wires[arg.semantic] = (found, schema_type(tool.inputSchema, found))
    covered = {w for w, _ in wires.values()} | {"database"}
    missing = [r for r in tool.inputSchema.required if r not in covered]
    if missing:
        return f"{variant.tool}: required arguments {missing} are not mapped"
    return ResolvedTool(variant, wires, tool.inputSchema)


def _batch_arguments(batch: BatchSpec, tool: str, sem: Mapping[str, Sem], sub: str) -> dict[str, JsonValue]:
    item: dict[str, JsonValue] = {}
    for field in batch.fields:
        raw: Sem | None = sub if field.semantic == "@sub" else sem.get(field.semantic)
        if raw is None:
            raise BackendError(f"{tool} needs the {field.semantic!r} argument")
        if isinstance(raw, str) and field.translate:
            raw = dict(field.translate).get(raw, raw)
        item[field.wire] = to_wire(raw, "string")
    unknown = set(sem) - {f.semantic for f in batch.fields}
    if unknown:
        raise BackendError(f"{tool} cannot honor the {sorted(unknown)} arguments")
    items: list[JsonValue] = [item]
    return {batch.key: items}


def build_arguments(
    resolved: ResolvedTool, sem: Mapping[str, Sem], database: str | None, sub: str = ""
) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {}
    if resolved.variant.batch is not None:
        out = _batch_arguments(resolved.variant.batch, resolved.variant.tool, sem, sub)
    for name, value in ([] if resolved.variant.batch is not None else sem.items()):
        target = resolved.wires.get(name)
        if target is None:
            raise BackendError(f"{resolved.variant.tool} cannot honor the {name!r} argument")
        out[target[0]] = to_wire(value, target[1])
    if "database" in resolved.schema.properties:
        if database is not None:
            out["database"] = database
        elif "database" in resolved.schema.required:
            raise BackendError("this call needs a database id")
    return out


_HOST_CHANNEL: Final = frozenset(
    {Capability.LIST_DATABASES, Capability.OPEN_DATABASE, Capability.CLOSE_DATABASE}
)


class McpToolBackend:
    """Profile-driven adapter over an MCP-over-HTTP disassembler plugin."""

    def __init__(self, kind: BackendKind, client: McpHttpClient, profile: Profile) -> None:
        for variants in profile.values():
            for variant in variants:
                if _FORBIDDEN_TOOL.fullmatch(variant.tool):
                    raise ValueError(f"profile names a blocked tool: {variant.tool}")
        self._kind = kind
        self._client = client
        self._profile = profile
        self._resolved: dict[ProfileKey, ResolvedTool] = {}
        self._problems: list[str] = []
        self._gen = GenerationCounter()
        self._start_lock = asyncio.Lock()

    @property
    def kind(self) -> BackendKind:
        return self._kind

    async def start(self) -> None:
        """Handshake, read the live tool list, and resolve every profile entry against it."""
        async with self._start_lock:
            if self._client.ready:
                return
            await self._client.connect()
            self._resolved.clear()
            self._problems.clear()
            for key, variants in self._profile.items():
                reasons: list[str] = []
                for variant in variants:
                    outcome = resolve_variant(variant, self._client.tools.get(variant.tool))
                    if isinstance(outcome, str):
                        reasons.append(outcome)
                        continue
                    self._resolved[key] = outcome
                    break
                else:
                    self._problems.append(f"{key[0].value}/{key[1] or '-'}: " + " | ".join(reasons))

    async def aclose(self) -> None:
        await self._client.aclose()

    def supports(self, capability: Capability) -> bool:
        return any(key[0] is capability for key in self._resolved)

    def diagnostics(self) -> tuple[str, ...]:
        """Why each unsupported capability is unsupported (for operators, not for the model)."""
        return tuple(self._problems)

    def describe_tools(self) -> str:
        """Live ``tool(arg, arg*)`` listing (``*`` = required): paste it to extend a profile."""
        lines = []
        for name in sorted(self._client.tools):
            schema = self._client.tools[name].inputSchema
            lines.append(
                f"{name}({', '.join(p + ('*' if p in schema.required else '') for p in sorted(schema.properties))})"
            )
        return "\n".join(lines)

    async def execute(self, call: BackendCall) -> BackendResult:
        await self.start()
        resolved = self._resolved.get((call.capability, subkey(call.args)))
        if resolved is None:
            raise UnsupportedOperationError(
                f"{self._kind.value} cannot {call.capability.value} with these arguments"
            )
        sem = semantic_args(call.args, call.offset, call.resolved_path)
        arguments = build_arguments(resolved, sem, call.database, subkey(call.args))
        text = await self._client.call_tool(resolved.variant.tool, arguments)
        failure = embedded_error(text)
        if failure is not None:
            raise BackendError(failure)
        if tier_of(call.capability) is not SecurityTier.READ_ONLY:
            self._gen.bump()
        channel: Literal["artifact", "host"] = "host" if call.capability in _HOST_CHANNEL else "artifact"
        items = split_items(text, resolved.variant.split, call.capability.value, channel)
        if resolved.variant.paged and isinstance(call.args, (PagedListArgs, SearchArgs, FindBytesArgs)):
            return window(items, call.args.limit, call.offset, self._gen.value)
        return BackendResult(items=tuple(items), next_offset=None, generation=self._gen.value)
