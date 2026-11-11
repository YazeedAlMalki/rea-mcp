"""Asynchronous zero-trust capability router with token-budgeted, deduplicated output.

Request path (every step fails closed and returns a typed ``ToolResponse``):

    raw JSON -> strict parse -> facade/tier match -> path checks -> cursor/receipt checks
        -> Authorizer (tier policy + audit) -> bounded concurrency -> backend call
        -> redact -> BLAKE3 fragment hashes -> dedup -> token budget -> receipt/cursor

Backends (IDA Pro / IDA Free / Ghidra adapters, Phase 2) implement
``DisassemblerBackend``. ``script_eval`` is never forwarded to a backend: it can
only reach an ``IsolatedScriptRunner`` (rootless Podman, see adapters/podman_runner.py);
with none configured it is refused even when the operator override is set.

The evidence engine (Phase 3, ``rea_mcp.evidence.engine``) registers like any other backend
(kind ``evidence``); it adds no top-level tool. The router keeps a per-session record of every
fragment it delivered so ledger evidence can be verified against what the server really sent.
"""

import asyncio
import hmac
import os
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, Protocol, runtime_checkable

from blake3 import blake3
from pydantic import ValidationError

from rea_mcp.core.models import (
    AddressArgs,
    AnyArgs,
    DecompileArgs,
    DecompileTarget,
    EVIDENCE_CAPABILITIES,
    LEDGER_READS,
    PAGED_ARGS,
    ScanHotspotsArgs,
    SourceOutlineArgs,
    SourceReadArgs,
    GetBytesArgs,
    ScriptInputBytes,
    BackendItem,
    BackendKind,
    BackendResult,
    Blake3Hex,
    Capability,
    CapabilityEntry,
    CapabilityListing,
    ErrorCategory,
    ErrorInfo,
    Fragment,
    MAX_TOKEN_BUDGET,
    FragmentRef,
    MutateRequest,
    OmissionSummary,
    OpenDatabaseArgs,
    PrivilegedRequest,
    QueryRequest,
    ResponseControl,
    ResponseMeta,
    SaveDatabaseArgs,
    ScriptEvalArgs,
    SecurityTier,
    ToolResponse,
    content_hash,
)
from rea_mcp.core.security import (
    Authorizer,
    AuthTicket,
    RedactionPipeline,
    SecurityDenied,
    SessionGrants,
    resolve_under_roots,
    tier_of,
)

ToolName = Literal["rea_query", "rea_mutate", "rea_privileged", "rea_capabilities"]
_TOOL_TIER: Final[dict[str, SecurityTier]] = {
    "rea_query": SecurityTier.READ_ONLY,
    "rea_mutate": SecurityTier.MUTATE_SAFE,
    "rea_privileged": SecurityTier.PRIVILEGED_DANGEROUS,
}

DEFAULT_MAX_CONCURRENCY: Final = 16  # same ceiling as leantoken's active-call limit
DEFAULT_CALL_TIMEOUT_S: Final = 30.0
DEFAULT_QUEUE_TIMEOUT_S: Final = 5.0
RECEIPT_TTL_S: Final = 24 * 3600.0  # sliding, like leantoken
MAX_RECEIPT_HASHES: Final = 4_096
MAX_RECEIPTS_PER_SESSION: Final = 64
MAX_SESSIONS: Final = 256
_SESSION_ID: Final = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RESERVED_SCRIPT_NAME: Final = "script.py"
MAX_SCRIPT_INPUT_BYTES: Final = 1_048_576
_BYTES_PER_TOKEN: Final = 3  # conservative for code/hex; no tokenizer dependency
MAX_SENT_FRAGMENTS: Final = 8_192  # per session: the index that makes fragment evidence verifiable
# Results that describe the ledger itself, or are only candidates for review, are never citable.
_NOT_EVIDENCE: Final = LEDGER_READS | {Capability.SCAN_HOTSPOTS}
_UNCITABLE_RECEIPT_KEYS: Final = frozenset({"ledger", "scan"})


def estimate_tokens(text: str) -> int:
    """Upper-biased token estimate (UTF-8 bytes / 3, rounded up)."""
    return (len(text.encode("utf-8")) + _BYTES_PER_TOKEN - 1) // _BYTES_PER_TOKEN


# --------------------------------------------------------------------------- #
# Backend contracts
# --------------------------------------------------------------------------- #


class BackendError(Exception):
    """Adapters raise this for expected failures (bridge down, IDA error, ...)."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.retryable = retryable


class _Refusal(Exception):
    """Internal control flow: becomes an error ``ToolResponse``."""

    def __init__(self, category: ErrorCategory, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.retryable = retryable


class UnsupportedOperationError(BackendError):
    """The backend has the capability but not for these arguments (maps to unsupported_capability)."""


class RefusedError(BackendError):
    """An in-process backend (the evidence engine) refusing with a specific, stable category."""

    def __init__(self, category: ErrorCategory, message: str, *, retryable: bool = False) -> None:
        super().__init__(message, retryable=retryable)
        self.category = category


@runtime_checkable
class StartableBackend(Protocol):
    """Optional: adapters that must handshake/discover tools before ``supports()`` is truthful."""

    async def start(self) -> None: ...


class SandboxUnavailableError(BackendError):
    """The isolated runner cannot start (no podman, image missing, ...)."""


@dataclass(frozen=True, slots=True)
class ScriptFile:
    """A read-only input mounted at ``/input/<name>`` inside the sandbox."""

    name: str
    data: bytes


@dataclass(frozen=True, slots=True)
class SentFragment:
    """A fragment this session was actually sent (the server's own record, not the client's)."""

    digest: str
    label: str
    capability: Capability
    generation: int


@dataclass(frozen=True, slots=True)
class ReceiptInfo:
    receipt_id: str
    digest: str  # BLAKE3 over the sorted fragment hashes the receipt covers right now
    fragments: int
    generation: int
    fresh: bool  # False once the data behind it changed


class EvidenceLookup(Protocol):
    """Read-only view of one session's delivery record, for verifying evidence references."""

    def fragment(self, digest: str) -> SentFragment | None: ...

    def receipt(self, receipt_id: str) -> ReceiptInfo | None: ...


@dataclass(frozen=True, slots=True)
class SourcePayload:
    """Pseudocode the router fetched from a disassembler backend for a ``decompile`` target."""

    label: str
    text: str


@dataclass(frozen=True, slots=True)
class BackendCall:
    database: str | None
    capability: Capability
    args: AnyArgs
    offset: int  # decoded from the signed cursor; 0 on the first page
    resolved_path: Path | None  # already checked against REA_ALLOWED_ROOTS
    session_id: str = ""
    payload: SourcePayload | None = None
    lookup: EvidenceLookup | None = None


class DisassemblerBackend(Protocol):
    """Polymorphic adapter surface.

    Paging contract: for list/search capabilities return at most ``args.limit``
    items starting at ``offset``, one item per offset unit, in a stable order, and
    set ``next_offset`` only if more remain. ``generation`` must change whenever
    the database content a read could observe changes (any successful mutation).
    """

    @property
    def kind(self) -> BackendKind: ...

    def supports(self, capability: Capability) -> bool: ...

    async def execute(self, call: BackendCall) -> BackendResult: ...


class IsolatedScriptRunner(Protocol):
    """Runs ``code`` with no network, no host mounts except ``files`` (read-only), and no
    access to any disassembler. ``files`` were fetched by the router, never by the script."""

    async def run(self, code: str, files: Sequence[ScriptFile], timeout_s: float) -> BackendResult: ...


# --------------------------------------------------------------------------- #
# Signed, generation-bound cursors
# --------------------------------------------------------------------------- #


class CursorError(Exception):
    pass


class CursorCodec:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("cursor key must be 32 bytes")
        self._key = key

    def _mac(self, body: str) -> str:
        return blake3(body.encode("ascii"), key=self._key).hexdigest()[:32]

    def encode(self, *, generation: int, offset: int, scope: str) -> str:
        body = f"{generation}.{offset}.{scope}"
        return f"{body}.{self._mac(body)}"

    def decode(self, token: str) -> tuple[int, int, str]:
        parts = token.split(".")
        if len(parts) != 4:
            raise CursorError("malformed cursor")
        generation_s, offset_s, scope, mac = parts
        body = f"{generation_s}.{offset_s}.{scope}"
        if not hmac.compare_digest(mac, self._mac(body)):
            raise CursorError("cursor signature mismatch")
        if not (generation_s.isdigit() and offset_s.isdigit()):
            raise CursorError("malformed cursor")
        return int(generation_s), int(offset_s), scope


# --------------------------------------------------------------------------- #
# Per-session state
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _Receipt:
    rid: str
    key: str
    generation: int
    expires_at: float
    hashes: OrderedDict[str, None] = field(default_factory=OrderedDict)


@dataclass(slots=True)
class _Session:
    grants: SessionGrants
    receipts: OrderedDict[str, _Receipt] = field(default_factory=OrderedDict)
    sent: OrderedDict[str, SentFragment] = field(default_factory=OrderedDict)


@dataclass(frozen=True, slots=True)
class _Prepared:
    capability: Capability
    tier: SecurityTier
    backend: DisassemblerBackend | None
    key: str
    offset: int
    scope: str
    resolved_path: Path | None
    known: frozenset[str]
    receipt: _Receipt | None
    epoch_key: str
    script_backends: dict[Capability, DisassemblerBackend]
    aux: DisassemblerBackend | None = None  # decompiler for a ``decompile`` evidence target


# --------------------------------------------------------------------------- #
# Router
# --------------------------------------------------------------------------- #


class _SessionLookup:
    """Evidence verification view over one session; live data, never a copy."""

    def __init__(
        self, session: _Session, state: dict[str, tuple[int, int]], clock: Callable[[], float]
    ) -> None:
        self._session = session
        self._state = state
        self._clock = clock

    def fragment(self, digest: str) -> SentFragment | None:
        return self._session.sent.get(digest)

    def receipt(self, receipt_id: str) -> ReceiptInfo | None:
        receipt = self._session.receipts.get(receipt_id)
        if receipt is None or receipt.expires_at < self._clock():
            return None
        label = receipt.key.split("|", 1)[0]
        if label in _UNCITABLE_RECEIPT_KEYS:
            return None
        current = self._state.get(label)
        digest = blake3("\n".join(sorted(receipt.hashes)).encode()).hexdigest()
        return ReceiptInfo(
            receipt_id=receipt.rid, digest=digest, fragments=len(receipt.hashes),
            generation=receipt.generation,
            fresh=current is not None and receipt.generation == current[1],
        )


def _epoch_label(capability: Capability) -> str:
    """Evidence capabilities get independent epochs so a ledger write never stales a source read."""
    if capability is Capability.SCAN_HOTSPOTS:
        return "scan"
    if capability in {Capability.SOURCE_OUTLINE, Capability.SOURCE_READ}:
        return "source"
    return "ledger"


def _error(category: ErrorCategory, message: str, *, retryable: bool = False) -> ToolResponse:
    return ToolResponse(
        status="error",
        error=ErrorInfo(category=category, message=message[:256], retryable=retryable),
    )


class CapabilityRouter:
    def __init__(
        self,
        *,
        backends: Sequence[DisassemblerBackend],
        authorizer: Authorizer,
        redaction: RedactionPipeline,
        script_runner: IsolatedScriptRunner | None = None,
        cursor_key: bytes | None = None,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        call_timeout_s: float = DEFAULT_CALL_TIMEOUT_S,
        queue_timeout_s: float = DEFAULT_QUEUE_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._backends = {b.kind: b for b in backends}
        self._authorizer = authorizer
        self._redaction = redaction
        self._runner = script_runner
        self._cursors = CursorCodec(cursor_key if cursor_key is not None else os.urandom(32))
        self._slots = asyncio.Semaphore(max_concurrency)
        self._call_timeout = call_timeout_s
        self._queue_timeout = queue_timeout_s
        self._clock = clock
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._state: dict[str, tuple[int, int]] = {}  # epoch_key -> (backend generation, epoch)
        self._write_locks: dict[BackendKind, asyncio.Lock] = {}

    # ---- public entry points ------------------------------------------------

    async def call(self, tool: ToolName, session_id: str, raw: str | bytes) -> ToolResponse | CapabilityListing:
        """Boundary: strict-parse ``raw`` JSON for ``tool`` and dispatch."""
        if not _SESSION_ID.fullmatch(session_id):
            return _error(ErrorCategory.INVALID_REQUEST, "invalid session id")
        if tool == "rea_capabilities":
            await self._ensure_started()
            return self.capabilities()
        try:
            if tool == "rea_query":
                return await self.handle(session_id, QueryRequest.model_validate_json(raw))
            if tool == "rea_mutate":
                return await self.handle(session_id, MutateRequest.model_validate_json(raw))
            return await self.handle(session_id, PrivilegedRequest.model_validate_json(raw), tool="rea_privileged")
        except ValidationError as exc:  # report locations only; never echo input values
            where = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['type']}" for e in exc.errors()[:3]
            )
            return _error(ErrorCategory.INVALID_REQUEST, f"schema violation: {where}")

    def capabilities(self) -> CapabilityListing:
        policy = self._authorizer.policy
        entries: list[CapabilityEntry] = []
        for capability in Capability:
            tier = tier_of(capability)
            routable = (
                self._runner is not None
                if capability is Capability.SCRIPT_EVAL
                else any(b.supports(capability) for b in self._backends.values())
            )
            enabled = routable and policy.is_enabled(capability)
            if tier is SecurityTier.READ_ONLY:
                reason = "read-only default" if routable else "no backend supports this"
            elif tier is SecurityTier.MUTATE_SAFE:
                reason = "requires per-session approval" if routable else "no backend supports this"
            elif not policy.is_enabled(capability):
                reason = "hard-disabled; operator override and allow-list required"
            else:
                reason = "operator-enabled; audited" if routable else "no backend or sandbox available"
            entries.append(CapabilityEntry(capability=capability, tier=tier, enabled=enabled, reason=reason))
        return CapabilityListing(entries=tuple(entries))

    async def handle(
        self,
        session_id: str,
        request: QueryRequest | MutateRequest | PrivilegedRequest,
        *,
        tool: Literal["rea_query", "rea_mutate", "rea_privileged"] | None = None,
    ) -> ToolResponse:
        expected_tool = tool or (
            "rea_query" if isinstance(request, QueryRequest)
            else "rea_mutate" if isinstance(request, MutateRequest)
            else "rea_privileged"
        )
        args = request.args
        capability = Capability(args.capability)
        tier = tier_of(capability)
        if _TOOL_TIER[expected_tool] is not tier:  # defense in depth beyond the schema union
            return _error(ErrorCategory.DENIED_TIER, f"{capability.value} is not served by {expected_tool}")
        session = self._session(session_id)
        await self._ensure_started()

        ticket: AuthTicket | None = None
        try:
            if tier is SecurityTier.PRIVILEGED_DANGEROUS:
                # Policy first, so every privileged attempt (even an unsupported one) is audited.
                ticket = await self._authorizer.authorize(session.grants, capability, args)
            prepared = self._prepare(session, capability, tier, request)
            if ticket is None:  # mutate asks its human only for operations that can actually run
                ticket = await self._authorizer.authorize(session.grants, capability, args)
        except SecurityDenied as denied:
            if ticket is not None:
                await self._authorizer.complete(session.grants, ticket, denied.category.value)
            return _error(denied.category, denied.message)
        except _Refusal as refusal:
            if ticket is not None:
                await self._authorizer.complete(session.grants, ticket, refusal.category.value)
            return _error(refusal.category, refusal.message, retryable=refusal.retryable)

        try:
            result = await self._dispatch(prepared, session, session_id, request.database, args)
        except _Refusal as refusal:
            await self._authorizer.complete(session.grants, ticket, refusal.category.value)
            return _error(refusal.category, refusal.message, retryable=refusal.retryable)
        await self._authorizer.complete(session.grants, ticket, "ok")
        return self._package(session, prepared, request.control, result)

    async def start(self) -> None:
        """Handshake with every adapter that needs it. Failures leave that adapter unsupported
        (never raise); the next request retries."""
        for backend in self._backends.values():
            if isinstance(backend, StartableBackend):
                try:
                    async with asyncio.timeout(self._call_timeout):
                        await backend.start()
                except (BackendError, TimeoutError):
                    continue

    async def _ensure_started(self) -> None:
        await self.start()

    # ---- preparation --------------------------------------------------------

    def _session(self, session_id: str) -> _Session:
        session = self._sessions.get(session_id)
        if session is None:
            session = _Session(grants=SessionGrants(session_id))
            self._sessions[session_id] = session
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        self._sessions.move_to_end(session_id)
        return session

    def _prepare(
        self,
        session: _Session,
        capability: Capability,
        tier: SecurityTier,
        request: QueryRequest | MutateRequest | PrivilegedRequest,
    ) -> _Prepared:
        args = request.args
        backend: DisassemblerBackend | None = None
        aux: DisassemblerBackend | None = None
        if capability is Capability.SCRIPT_EVAL:
            kind_label = "sandbox"
        elif capability in EVIDENCE_CAPABILITIES:
            backend = self._select_backend(capability, BackendKind.EVIDENCE)
            kind_label = _epoch_label(capability)
            if isinstance(args, (SourceOutlineArgs, SourceReadArgs, ScanHotspotsArgs)) and isinstance(
                args.target, DecompileTarget
            ):
                wanted = request.backend if request.backend is not BackendKind.EVIDENCE else None
                aux = self._select_backend(Capability.DECOMPILE, wanted)
        else:
            backend = self._select_backend(capability, request.backend)
            kind_label = backend.kind.value
        key = f"{kind_label}|{request.database or ''}"
        script_backends: dict[Capability, DisassemblerBackend] = {}
        if isinstance(args, ScriptEvalArgs):
            for item in args.inputs:
                needed = (
                    Capability.GET_BYTES if isinstance(item, ScriptInputBytes)
                    else Capability.DISASM if item.source == "disasm"
                    else Capability.DECOMPILE
                )
                if needed not in script_backends:
                    script_backends[needed] = self._select_backend(needed, request.backend)

        resolved: Path | None = None
        roots = self._authorizer.policy.allowed_roots
        if isinstance(args, OpenDatabaseArgs):
            resolved = resolve_under_roots(args.input_path, roots)
            if not resolved.is_file():
                raise SecurityDenied(ErrorCategory.DENIED_PATH, "input path is not a regular file")
        elif isinstance(args, SaveDatabaseArgs) and args.path is not None:
            resolved = resolve_under_roots(args.path, roots)

        offset, scope = 0, ""
        if isinstance(args, PAGED_ARGS):
            scope = blake3(
                f"{key}|{capability.value}|{args.model_copy(update={'cursor': None}).model_dump_json()}".encode()
            ).hexdigest()[:32]
            if args.cursor is not None:
                offset = self._check_cursor(args.cursor, key, scope)

        known, receipt = self._known_hashes(session, request.control, key, tier)
        return _Prepared(
            capability, tier, backend, key, offset, scope, resolved, known, receipt,
            kind_label, script_backends, aux,
        )

    def _select_backend(self, capability: Capability, wanted: BackendKind | None) -> DisassemblerBackend:
        if wanted is not None:
            backend = self._backends.get(wanted)
            if backend is None:
                raise _Refusal(ErrorCategory.BACKEND_UNAVAILABLE, f"backend {wanted.value} is not registered")
            if not backend.supports(capability):
                raise _Refusal(ErrorCategory.UNSUPPORTED_CAPABILITY, f"{wanted.value} cannot {capability.value}")
            return backend
        for backend in self._backends.values():
            if backend.supports(capability):
                return backend
        raise _Refusal(ErrorCategory.UNSUPPORTED_CAPABILITY, f"no backend supports {capability.value}")

    def _check_cursor(self, token: str, key: str, scope: str) -> int:
        try:
            generation, offset, token_scope = self._cursors.decode(token)
        except CursorError as exc:
            raise _Refusal(ErrorCategory.STALE_CURSOR, str(exc)) from exc
        if token_scope != scope:
            raise _Refusal(ErrorCategory.STALE_CURSOR, "cursor belongs to a different query")
        current = self._state.get(key.split("|", 1)[0])
        if current is None or generation != current[1]:
            raise _Refusal(ErrorCategory.STALE_CURSOR, "database changed since the cursor was issued")
        return offset

    def _known_hashes(
        self, session: _Session, control: ResponseControl, key: str, tier: SecurityTier
    ) -> tuple[frozenset[str], _Receipt | None]:
        if tier is not SecurityTier.READ_ONLY:
            return frozenset(), None  # no dedup for writes: their output is the confirmation
        known = set(control.known_hashes)
        receipt: _Receipt | None = None
        if control.receipt_id is not None:
            receipt = session.receipts.get(control.receipt_id)
            now = self._clock()
            if receipt is None or receipt.expires_at < now or receipt.key != key:
                raise _Refusal(ErrorCategory.UNKNOWN_RECEIPT, "receipt is unknown, expired, or for another database")
            current = self._state.get(key.split("|", 1)[0])
            if current is None or receipt.generation != current[1]:
                raise _Refusal(ErrorCategory.STALE_RECEIPT, "database changed since the receipt was issued", retryable=True)
            known |= receipt.hashes.keys()
        return frozenset(known), receipt

    # ---- execution ----------------------------------------------------------

    async def _dispatch(
        self, p: _Prepared, session: _Session, session_id: str, database: str | None, args: AnyArgs
    ) -> BackendResult:
        try:
            async with asyncio.timeout(self._queue_timeout):
                await self._slots.acquire()
        except TimeoutError as exc:
            raise _Refusal(ErrorCategory.CAPACITY_EXHAUSTED, "too many active calls", retryable=True) from exc
        try:
            if isinstance(args, ScriptEvalArgs):
                if self._runner is None:
                    raise _Refusal(ErrorCategory.SANDBOX_UNAVAILABLE, "no isolated script runner is configured")
                files = await self._resolve_inputs(p, database, args)
                return await self._bounded(self._runner.run(args.code, files, self._call_timeout))
            backend = p.backend
            if backend is None:  # unreachable: only SCRIPT_EVAL has no backend
                raise _Refusal(ErrorCategory.UNSUPPORTED_CAPABILITY, "no backend selected")
            payload: SourcePayload | None = None
            lookup: EvidenceLookup | None = None
            if p.capability in EVIDENCE_CAPABILITIES:
                payload = await self._fetch_pseudocode(p, database, args)
                lookup = _SessionLookup(session, self._state, self._clock)
            call = BackendCall(
                database, p.capability, args, p.offset, p.resolved_path,
                session_id=session_id, payload=payload, lookup=lookup,
            )
            if p.tier is SecurityTier.READ_ONLY:
                return await self._bounded(backend.execute(call))
            lock = self._write_locks.setdefault(backend.kind, asyncio.Lock())
            async with lock:  # one writer per backend: IDA/Ghidra mutate on a single thread
                return await self._bounded(backend.execute(call))
        finally:
            self._slots.release()

    async def _fetch_pseudocode(
        self, p: _Prepared, database: str | None, args: AnyArgs
    ) -> SourcePayload | None:
        """For a ``decompile`` evidence target: the router, not the engine, talks to the backend."""
        if p.aux is None or not isinstance(args, (SourceOutlineArgs, SourceReadArgs, ScanHotspotsArgs)):
            return None
        target = args.target
        if not isinstance(target, DecompileTarget):
            return None
        result = await self._bounded(p.aux.execute(BackendCall(
            database, Capability.DECOMPILE,
            DecompileArgs(capability="decompile", address=target.address), 0, None,
        )))
        text = "\n".join(item.text for item in result.items)
        return SourcePayload(f"decompile@0x{target.address:x}", text)

    async def _resolve_inputs(
        self, p: _Prepared, database: str | None, args: ScriptEvalArgs
    ) -> tuple[ScriptFile, ...]:
        """Router-side reads for the sandbox: the script never talks to a backend itself."""
        files: list[ScriptFile] = []
        seen: set[str] = set()
        total = 0
        for item in args.inputs:
            if item.name in seen or item.name == RESERVED_SCRIPT_NAME:
                raise _Refusal(ErrorCategory.INVALID_REQUEST, "duplicate or reserved input name")
            seen.add(item.name)
            if isinstance(item, ScriptInputBytes):
                capability = Capability.GET_BYTES
                call_args: AnyArgs = GetBytesArgs(capability="get_bytes", address=item.address, size=item.size)
            elif item.source == "disasm":
                capability = Capability.DISASM
                call_args = AddressArgs(capability="disasm", address=item.address)
            else:
                capability = Capability.DECOMPILE
                call_args = DecompileArgs(capability="decompile", address=item.address)
            result = await self._bounded(
                p.script_backends[capability].execute(BackendCall(database, capability, call_args, 0, None))
            )
            text = "\n".join(i.text for i in result.items)
            if isinstance(item, ScriptInputBytes):
                try:
                    data = bytes.fromhex("".join(text.split()))
                except ValueError as exc:
                    raise _Refusal(ErrorCategory.BACKEND_ERROR, "backend returned non-hex bytes") from exc
                if len(data) != item.size:
                    raise _Refusal(ErrorCategory.BACKEND_ERROR, "backend returned a short byte read")
            else:
                data = text.encode("utf-8", errors="backslashreplace")
            total += len(data)
            if total > MAX_SCRIPT_INPUT_BYTES:
                raise _Refusal(ErrorCategory.INVALID_REQUEST, "script inputs exceed the total size limit")
            files.append(ScriptFile(item.name, data))
        return tuple(files)

    async def _bounded(self, coro: Coroutine[object, object, BackendResult]) -> BackendResult:
        try:
            async with asyncio.timeout(self._call_timeout):
                return await coro
        except TimeoutError as exc:
            raise _Refusal(ErrorCategory.TIMEOUT, "backend call timed out", retryable=True) from exc
        except RefusedError as exc:
            raise _Refusal(
                exc.category, self._redaction.scrub_transport(exc.message), retryable=exc.retryable
            ) from exc
        except SecurityDenied as denied:
            raise _Refusal(denied.category, denied.message) from denied
        except UnsupportedOperationError as exc:
            raise _Refusal(ErrorCategory.UNSUPPORTED_CAPABILITY, self._redaction.scrub_transport(exc.message)) from exc
        except SandboxUnavailableError as exc:
            raise _Refusal(
                ErrorCategory.SANDBOX_UNAVAILABLE, self._redaction.scrub_transport(exc.message)
            ) from exc
        except BackendError as exc:
            raise _Refusal(
                ErrorCategory.BACKEND_ERROR, self._redaction.scrub_transport(exc.message),
                retryable=exc.retryable,
            ) from exc
        except (OSError, ValidationError, ValueError) as exc:
            raise _Refusal(
                ErrorCategory.BACKEND_ERROR, f"backend failed: {type(exc).__name__}", retryable=True
            ) from exc

    # ---- response packaging -------------------------------------------------

    def _package(
        self, session: _Session, p: _Prepared, control: ResponseControl, result: BackendResult
    ) -> ToolResponse:
        generation, changed = self._advance_epoch(p, result.generation)
        if changed and p.offset > 0:
            return _error(ErrorCategory.STALE_CURSOR, "database changed while paging; restart the query")
        if changed and p.receipt is not None:
            return _error(
                ErrorCategory.STALE_RECEIPT, "database changed since the receipt was issued", retryable=True
            )
        budget = control.token_budget
        backend_kind = p.backend.kind if p.backend is not None else None

        processed: list[tuple[str, str, str, int, tuple[str, ...]]] = []
        for item in result.items:
            label, text, candidates = self._scrub_item(item)
            processed.append((label, text, content_hash(text), estimate_tokens(label + text), candidates))

        receipt = self._receipt_for(session, p, generation)
        expected = control.expected_hash
        if expected is not None and len(processed) == 1 and processed[0][2] == expected:
            self._remember(session, receipt, [expected])
            self._record_sent(session, p, generation, [(expected, processed[0][0])])
            return ToolResponse(
                status="not_modified",
                meta=self._meta(p, backend_kind, receipt, generation, budget, 0, False, (expected,), None, None),
            )

        fragments: list[Fragment] = []
        refs: list[FragmentRef] = []
        hashes: list[str] = []
        delivered: list[tuple[str, str]] = []
        seen: set[str] = set()
        used = consumed = omitted = omitted_tokens = first_overflow = 0
        truncated = False
        for label, text, digest, tokens, candidates in processed:
            if truncated:
                omitted += 1
                omitted_tokens += tokens
            elif digest in p.known or digest in seen:
                refs.append(FragmentRef(hash=digest, label=label, tokens_saved=tokens))
                hashes.append(digest)
                delivered.append((digest, label))
                consumed += 1
            elif used + tokens > budget:
                truncated = True
                omitted += 1
                omitted_tokens += tokens
                first_overflow = first_overflow or tokens
            else:
                fragments.append(
                    Fragment(hash=digest, label=label, text=text, tokens=tokens, secret_candidates=candidates)
                )
                seen.add(digest)
                hashes.append(digest)
                delivered.append((digest, label))
                used += tokens
                consumed += 1
        if truncated and not fragments and not refs:
            return _error(
                ErrorCategory.BUDGET_TOO_SMALL,
                f"first result needs ~{first_overflow} tokens, budget is {budget} "
                f"(max {MAX_TOKEN_BUDGET}); raise token_budget or narrow the query",
            )

        next_cursor: str | None = None
        if p.scope:
            next_offset = p.offset + consumed if truncated else result.next_offset
            if next_offset is not None:
                next_cursor = self._cursors.encode(
                    generation=generation, offset=next_offset, scope=p.scope
                )
        self._remember(session, receipt, hashes)
        self._record_sent(session, p, generation, delivered)
        omission = (
            OmissionSummary(omitted_fragments=omitted, omitted_tokens_estimate=omitted_tokens, reason="token_budget")
            if truncated
            else None
        )
        return ToolResponse(
            status="ok",
            fragments=tuple(fragments),
            known=tuple(refs),
            meta=self._meta(
                p, backend_kind, receipt, generation, budget, used, truncated,
                tuple(hashes), next_cursor, omission,
            ),
        )

    def _advance_epoch(self, p: _Prepared, backend_generation: int) -> tuple[int, bool]:
        """Router-owned generation: bumps on every state-changing call and whenever the
        backend reports a new generation, so cursors/receipts can never survive a mutation
        even if an adapter forgets to count it. Scoped per backend, not per database."""
        prev = self._state.get(p.epoch_key)
        mutated = p.tier is not SecurityTier.READ_ONLY and p.capability is not Capability.SCRIPT_EVAL
        if prev is None:
            epoch, changed = (1 if mutated else 0), mutated
        else:
            changed = mutated or prev[0] != backend_generation
            epoch = prev[1] + (1 if changed else 0)
        self._state[p.epoch_key] = (backend_generation, epoch)
        return epoch, changed

    def _scrub_item(self, item: BackendItem) -> tuple[str, str, tuple[str, ...]]:
        if item.channel == "host":
            label = self._redaction.scrub_host_channel(item.label).text
            scrubbed = self._redaction.scrub_host_channel(item.text)
        else:
            label = self._redaction.scrub_artifact(item.label).text
            scrubbed = self._redaction.scrub_artifact(item.text)
        return _clean(label)[:256], _clean(scrubbed.text), scrubbed.candidates

    @staticmethod
    def _meta(
        p: _Prepared,
        backend_kind: BackendKind | None,
        receipt: _Receipt | None,
        generation: int,
        budget: int,
        used: int,
        truncated: bool,
        hashes: tuple[Blake3Hex, ...],
        next_cursor: str | None,
        omission: OmissionSummary | None,
    ) -> ResponseMeta:
        return ResponseMeta(
            capability=p.capability,
            backend=backend_kind,
            receipt_id=receipt.rid if receipt is not None else None,
            generation=generation,
            token_budget=budget,
            tokens_used=used,
            truncated=truncated,
            result_complete=not truncated and next_cursor is None,
            fragment_hashes=hashes,
            next_cursor=next_cursor,
            omission=omission,
        )

    def _receipt_for(self, session: _Session, p: _Prepared, generation: int) -> _Receipt | None:
        if p.tier is not SecurityTier.READ_ONLY:
            return None
        receipt = p.receipt or _Receipt(secrets.token_urlsafe(16), p.key, generation, 0.0)
        receipt.generation = generation
        receipt.expires_at = self._clock() + RECEIPT_TTL_S  # sliding lifetime
        return receipt

    @staticmethod
    def _record_sent(
        session: _Session, p: _Prepared, generation: int, delivered: Sequence[tuple[str, str]]
    ) -> None:
        """Remember what this session was shown, so fragment evidence can be verified later.
        Only plain reads count: not ledger views, not scanner candidates, not writes."""
        if p.tier is not SecurityTier.READ_ONLY or p.capability in _NOT_EVIDENCE:
            return
        for digest, label in delivered:
            session.sent[digest] = SentFragment(digest, label, p.capability, generation)
            session.sent.move_to_end(digest)
        while len(session.sent) > MAX_SENT_FRAGMENTS:
            session.sent.popitem(last=False)

    @staticmethod
    def _remember(session: _Session, receipt: _Receipt | None, hashes: Sequence[str]) -> None:
        if receipt is None:
            return
        for digest in hashes:
            receipt.hashes[digest] = None
            receipt.hashes.move_to_end(digest)
        while len(receipt.hashes) > MAX_RECEIPT_HASHES:
            receipt.hashes.popitem(last=False)
        session.receipts[receipt.rid] = receipt
        session.receipts.move_to_end(receipt.rid)
        while len(session.receipts) > MAX_RECEIPTS_PER_SESSION:
            session.receipts.popitem(last=False)


def _clean(text: str) -> str:
    """Make backend text valid UTF-8 without silently dropping evidence.

    Lone surrogates become visible ``\\udc80``-style escapes and NUL becomes ``\\x00``.
    """
    return text.encode("utf-8", errors="backslashreplace").decode("utf-8").replace("\x00", "\\x00")
