"""MCP server entrypoint: wires the router, evidence engine, adapters and registry into ``mcp.server.Server``.

Surface (nothing else is exposed):

* tools: ``rea_query``, ``rea_mutate``, ``rea_privileged``, ``rea_capabilities``. Input schemas are
  generated from the strict Pydantic request models, and every call is parsed again by those models
  inside the router, so the published schema and the enforced one cannot drift apart.
* resources / resource templates: the read-only ``rea://`` catalog.
* prompts: the built-in playbooks.

Configuration comes only from the operator's environment and is validated before the server answers a
single request (``load_config``): a bad setting stops startup with a message on stderr, never a
half-working server. stdout belongs to the protocol, so all diagnostics go to stderr.

Human consent for disassembler edits is asked through MCP elicitation with a fixed message that no tool
input can influence. If the client cannot elicit, the answer is "no".
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
import re
import secrets
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

import mcp_types as types
from mcp.server import Server, ServerRequestContext
from mcp.server.session import ServerSession
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from rea_mcp.adapters.ghidra import GhidraBackend
from rea_mcp.adapters.ida_free import IdaFreeBackend
from rea_mcp.adapters.ida_pro import IdaProBackend
from rea_mcp.adapters.podman_runner import PodmanScriptRunner
from rea_mcp.core.models import (
    Capability,
    CapabilityListing,
    ErrorCategory,
    MutateRequest,
    PrivilegedRequest,
    QueryRequest,
    ToolResponse,
)
from rea_mcp.core.router import CapabilityRouter, DisassemblerBackend, IsolatedScriptRunner, ToolName
from rea_mcp.core.security import (
    ALLOW_ENV,
    AUDIT_ENV,
    AUTO_GRANT_ENV,
    KEYFILE_ENV,
    LEDGER_DIR_ENV,
    LEDGER_FOREIGN_ENV,
    OVERRIDE_ENV,
    REDACT_ARTIFACTS_ENV,
    ROOTS_ENV,
    AuditLog,
    Authorizer,
    ConsentProvider,
    RedactionPipeline,
    SecurityDenied,
    SecurityPolicy,
    assert_loopback_url,
)
from rea_mcp.evidence.engine import EvidenceEngine
from rea_mcp.registry.catalog import KNOWLEDGE_DIR_ENV, Catalog, KnowledgeConfigError, RegistryError
from rea_mcp.registry.prompts import PLAYBOOKS, PROMPT_ARGUMENTS, PromptError, get_playbook, render_prompt

SERVER_NAME: Final = "rea-mcp"
SERVER_VERSION: Final = "1.2.1"
IDA_PRO_URL_ENV: Final = "REA_IDA_PRO_URL"
IDA_FREE_URL_ENV: Final = "REA_IDA_FREE_URL"
GHIDRA_URL_ENV: Final = "REA_GHIDRA_URL"
SESSION_ID_ENV: Final = "REA_SESSION_ID"
DEFAULT_LEDGER_SESSION: Final = "default"
_SESSION_ID: Final = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

KNOWN_ENV: Final = frozenset({
    ROOTS_ENV, IDA_PRO_URL_ENV, IDA_FREE_URL_ENV, GHIDRA_URL_ENV, LEDGER_DIR_ENV, LEDGER_FOREIGN_ENV,
    KNOWLEDGE_DIR_ENV, REDACT_ARTIFACTS_ENV, AUDIT_ENV, AUTO_GRANT_ENV, SESSION_ID_ENV,
    OVERRIDE_ENV, ALLOW_ENV, KEYFILE_ENV,
})

RESOURCE_NOT_FOUND: Final = -32002
CONSENT_TIMEOUT_S: Final = 120.0
MAX_REQUEST_CHARS: Final = 2 * 1024 * 1024

TOOL_NAMES: Final[tuple[ToolName, ...]] = ("rea_query", "rea_mutate", "rea_privileged", "rea_capabilities")

INSTRUCTIONS: Final = (
    "Reverse-engineering facade over IDA Pro, IDA Free and Ghidra, plus a read-only source and evidence "
    "engine. Four tools: rea_capabilities (call first), rea_query (read-only), rea_mutate (ledger notes; "
    "database edits need the user's per-session approval), rea_privileged (disabled by default). "
    "Pass control.receipt_id and control.known_hashes to avoid re-reading fragments you already hold, and "
    "record findings in the evidence ledger as ConfirmedFact, Hypothesis or UnanalyzedGap. Playbooks are "
    "available as prompts and at rea://prompts/{name}; reference material is under rea://cases/ and rea://search/."
)

_TOOL_TEXT: Final[Mapping[str, str]] = {
    "rea_query": (
        "Read-only analysis: decompile, disasm, xrefs, listings, search, byte reads, source reads, hotspot "
        "scans and evidence-ledger views. Set args.capability; use control.receipt_id / known_hashes / "
        "token_budget and follow meta.next_cursor to stay token-lean. "
        'Example: {"args": {"capability": "list_functions", "limit": 20}}. '
        "args is a JSON object (not a string); control is optional, so omit it rather than sending null."
    ),
    "rea_mutate": (
        "Notes and edits. Evidence-ledger writes (ledger_*, import_sarif) need no approval and are checked "
        "against evidence the server issued. Database edits (rename, comment, type, structural) need the "
        "user's per-session approval."
    ),
    "rea_privileged": (
        "Patching, memory writes, saving the database, sandboxed scripts and debugger control. Hard-disabled "
        "unless the operator enabled each capability; every attempt is audited. Use only when the user asked."
    ),
    "rea_capabilities": (
        "List every capability with its tier and whether it is enabled in this session. Takes no arguments."
    ),
}


_OBJECT_FIELDS: Final = ("args", "control")


def coerce_arguments(arguments: Mapping[str, object]) -> dict[str, object]:
    """Repair the two envelope slips that tool-calling clients make with nested-object schemas.

    * ``args`` / ``control`` sent as a JSON *string* holding an object (``'{"capability": ...}'``);
    * ``control`` sent as ``null`` instead of being left out.

    This is syntax only: the repaired request goes through the same strict validation, tier checks
    and size limit as any other, so nothing is accepted that an object-shaped request would not be.
    Anything that is not a string holding a JSON object is left untouched and fails validation.
    """
    fixed = dict(arguments)
    for key in _OBJECT_FIELDS:
        value = fixed.get(key)
        if isinstance(value, str) and len(value) <= MAX_REQUEST_CHARS:
            try:
                parsed: object = json.loads(value)
            except (ValueError, RecursionError):
                continue
            if isinstance(parsed, dict):
                fixed[key] = parsed
    if "control" in fixed and fixed["control"] is None:
        del fixed["control"]
    return fixed


@runtime_checkable
class Closeable(Protocol):
    async def aclose(self) -> None: ...


class ConfigError(ValueError):
    """The operator's environment is unusable; the server refuses to start."""


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ServerConfig:
    policy: SecurityPolicy
    ida_pro_url: str | None
    ida_free_url: str | None
    ghidra_url: str | None
    knowledge_dir: Path | None
    audit_log: Path | None
    session_id: str | None  # stable id => the durable ledger resumes across restarts
    warnings: tuple[str, ...]


def _loopback(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name, "").strip()
    if not value:
        return None
    try:
        return assert_loopback_url(value)
    except SecurityDenied as exc:
        raise ConfigError(f"{name}: {exc.message}") from exc


def load_config(env: Mapping[str, str]) -> ServerConfig:
    """Validate every ``REA_*`` setting. Raises ``ConfigError``; never returns a partial config."""
    try:
        policy = SecurityPolicy.from_environ(env)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    warnings: list[str] = []

    for root in policy.allowed_roots:
        if not root.is_dir():
            raise ConfigError(f"{ROOTS_ENV}: {str(root)!r} is not an existing directory")
    if not policy.allowed_roots:
        warnings.append(f"{ROOTS_ENV} is empty: source, scan and SARIF capabilities will refuse every path")

    audit = Path(env[AUDIT_ENV]) if env.get(AUDIT_ENV) else None
    if policy.privileged_override and not policy.privileged_allow:
        raise ConfigError(f"{OVERRIDE_ENV} is set but {ALLOW_ENV} names no capability")
    if policy.privileged_override and audit is None:
        raise ConfigError(f"{OVERRIDE_ENV} requires {AUDIT_ENV} (privileged calls are audited before they run)")
    if policy.privileged_allow and not policy.privileged_override:
        warnings.append(f"{ALLOW_ENV} is set but {OVERRIDE_ENV} is not: privileged capabilities stay disabled")
    if policy.keyfile is not None and not policy.keyfile.is_file():
        warnings.append(f"{KEYFILE_ENV} does not exist now: privileged calls are refused until it does")
    if policy.mutate_auto_grant:
        warnings.append(f"{AUTO_GRANT_ENV}=1: database edits are approved without asking the user")
    if policy.ledger_allow_foreign_workspace:
        warnings.append(f"{LEDGER_FOREIGN_ENV}=1: ledger journals from other workspaces will be loaded")
    if policy.ledger_dir is not None and policy.ledger_dir.exists() and not policy.ledger_dir.is_dir():
        raise ConfigError(f"{LEDGER_DIR_ENV}: exists and is not a directory")

    session_id = env.get(SESSION_ID_ENV) or None
    if session_id is not None and not _SESSION_ID.fullmatch(session_id):
        raise ConfigError(f"{SESSION_ID_ENV}: use 1-64 letters, digits, '_' or '-'")
    if session_id is None and policy.ledger_dir is not None:
        session_id = DEFAULT_LEDGER_SESSION  # stdio serves one connection; the journal is bound to the workspace
    knowledge = Path(env[KNOWLEDGE_DIR_ENV]) if env.get(KNOWLEDGE_DIR_ENV) else None
    warnings += [
        f"unrecognized setting {name} (ignored)"
        for name in sorted(env)
        if name.startswith("REA_") and name not in KNOWN_ENV
    ]
    return ServerConfig(
        policy=policy,
        ida_pro_url=_loopback(env, IDA_PRO_URL_ENV),
        ida_free_url=_loopback(env, IDA_FREE_URL_ENV),
        ghidra_url=_loopback(env, GHIDRA_URL_ENV),
        knowledge_dir=knowledge,
        audit_log=audit,
        session_id=session_id,
        warnings=tuple(warnings),
    )


# --------------------------------------------------------------------------- #
# Consent through MCP elicitation
# --------------------------------------------------------------------------- #

CONSENT_KEY: Final = "rea-consent"


@dataclass(slots=True)
class _ConsentState:
    """What consent can do for the request being served (set per tool call, never shared)."""

    session: ServerSession
    preset: bool | None  # the human's answer, when this request is the retry of an input-required round
    needs_input: bool = False  # the connection cannot be asked directly; answer via input-required instead


_CONSENT: contextvars.ContextVar[_ConsentState | None] = contextvars.ContextVar("rea_consent", default=None)

_CONSENT_MESSAGE: Final = (
    "Allow this session to modify the reverse-engineering database (rename symbols and variables, set "
    "comments and types, structural edits)? Notes in the evidence ledger never need approval."
)
_CONSENT_SCHEMA: Final[dict[str, object]] = {
    "type": "object",
    "properties": {"approve": {"type": "boolean", "title": "Allow database edits for this session", "default": False}},
    "required": ["approve"],
}


def _approved(result: types.ElicitResult) -> bool:
    return result.action == "accept" and result.content is not None and result.content.get("approve") is True


class ElicitationConsent:
    """Asks the human through the client. Fails closed: no capability, error, timeout or decline => no.

    Handshake-era connections (2025-11-25 and earlier) are asked directly over the back-channel. On
    2026-07-28 connections there is no back-channel, so the call is answered with an input-required
    result carrying the same fixed question, and the client's retry brings the human's answer back.
    """

    async def approve_session_mutations(self, session_id: str) -> bool:
        state = _CONSENT.get()
        if state is None:
            return False
        if state.preset is not None:
            return state.preset
        capabilities = state.session.client_capabilities
        if capabilities is None or capabilities.elicitation is None:
            return False
        if not state.session.can_send_request:
            state.needs_input = True
            return False
        try:
            async with asyncio.timeout(CONSENT_TIMEOUT_S):
                result = await state.session.elicit_form(_CONSENT_MESSAGE, _CONSENT_SCHEMA)
        except (MCPError, TimeoutError, OSError):
            return False
        return _approved(result)


def _consent_request() -> types.ElicitRequest:
    return types.ElicitRequest(
        params=types.ElicitRequestFormParams(message=_CONSENT_MESSAGE, requested_schema=dict(_CONSENT_SCHEMA))
    )


def _preset_answer(params: types.CallToolRequestParams) -> bool | None:
    answer = (params.input_responses or {}).get(CONSENT_KEY)
    return _approved(answer) if isinstance(answer, types.ElicitResult) else None


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #


def tool_definitions() -> tuple[types.Tool, ...]:
    """The four tools, with input schemas generated from the strict request models."""
    empty: dict[str, object] = {"type": "object", "properties": {}, "additionalProperties": False}
    schemas: Mapping[str, Mapping[str, object]] = {
        "rea_query": QueryRequest.model_json_schema(mode="validation"),
        "rea_mutate": MutateRequest.model_json_schema(mode="validation"),
        "rea_privileged": PrivilegedRequest.model_json_schema(mode="validation"),
        "rea_capabilities": empty,
    }
    hints: Mapping[str, types.ToolAnnotations] = {
        "rea_query": types.ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False),
        "rea_mutate": types.ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
        "rea_privileged": types.ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False),
        "rea_capabilities": types.ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False),
    }
    return tuple(
        types.Tool(
            name=name,
            description=_TOOL_TEXT[name],
            input_schema=dict(schemas[name]),
            annotations=hints[name],
        )
        for name in TOOL_NAMES
    )


def _text_result(text: str, *, error: bool) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=error)


def _error_result(message: str) -> types.CallToolResult:
    body = {"status": "error", "error": {"category": "invalid_request", "message": message, "retryable": False}}
    return _text_result(json.dumps(body, separators=(",", ":")), error=True)


class ReaApp:
    def __init__(
        self,
        config: ServerConfig,
        env: Mapping[str, str],
        *,
        extra_backends: Sequence[DisassemblerBackend] = (),
    ) -> None:
        self.config = config
        policy = config.policy
        redaction = RedactionPipeline.from_policy(policy, dict(env))
        backends: list[DisassemblerBackend] = [EvidenceEngine(policy)]
        try:
            if config.ida_pro_url is not None:
                backends.append(IdaProBackend.connect_to(config.ida_pro_url))
            if config.ida_free_url is not None:
                backends.append(IdaFreeBackend.connect_to(config.ida_free_url))
            if config.ghidra_url is not None:
                backends.append(GhidraBackend.connect_to(config.ghidra_url))
        except SecurityDenied as exc:  # unreachable after load_config; kept so construction itself fails closed
            raise ConfigError(exc.message) from exc
        backends.extend(extra_backends)
        self._backends: tuple[DisassemblerBackend, ...] = tuple(backends)  # embedding/test seam: already-constructed, caller-vetted backends
        runner: IsolatedScriptRunner | None = None
        if policy.privileged_override and Capability.SCRIPT_EVAL in policy.privileged_allow:
            runner = PodmanScriptRunner(environ=env)
        self.consent: ConsentProvider = ElicitationConsent()
        self.router = CapabilityRouter(
            backends=backends,
            authorizer=Authorizer(policy, AuditLog(config.audit_log), self.consent),
            redaction=redaction,
            script_runner=runner,
        )
        try:
            self.catalog = Catalog.build(config.knowledge_dir, policy.allowed_roots, redaction.scrub_transport)
        except KnowledgeConfigError as exc:
            raise ConfigError(str(exc)) from exc
        self._process_session = config.session_id or f"mcp-{secrets.token_hex(12)}"
        self.server: Server[None] = self._build_server()

    # ---- sessions ----------------------------------------------------------------

    def session_id(self) -> str:
        """The router session for every request.

        mcp 2.x builds a fresh ``ServerSession`` per request, so it cannot be a key. This server speaks
        stdio only, and a stdio process has exactly one client, so the process is the session: an
        operator-chosen stable id (``REA_SESSION_ID``, which makes the durable ledger resumable) or a
        random one per process. Serving several clients from one process would need a per-connection
        key from the transport, which is why no HTTP transport is wired.
        """
        return self._process_session

    # ---- handlers ----------------------------------------------------------------

    async def _list_tools(
        self, ctx: ServerRequestContext[None, object], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=list(tool_definitions()))

    async def _call_tool(
        self, ctx: ServerRequestContext[None, object], params: types.CallToolRequestParams
    ) -> types.CallToolResult | types.InputRequiredResult:
        name = params.name
        if name not in TOOL_NAMES:
            raise MCPError(types.INVALID_PARAMS, "unknown tool")
        arguments = params.arguments or {}
        if name == "rea_capabilities" and arguments:
            return _error_result("rea_capabilities takes no arguments")
        if name != "rea_capabilities":
            arguments = coerce_arguments(arguments)
        try:
            raw = json.dumps(arguments, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError):
            return _error_result("arguments are not valid JSON")
        if len(raw) > MAX_REQUEST_CHARS:
            return _error_result("request is too large")
        tool: ToolName = "rea_query" if name == "rea_query" else (
            "rea_mutate" if name == "rea_mutate" else "rea_privileged" if name == "rea_privileged" else "rea_capabilities"
        )
        state = _ConsentState(ctx.session, _preset_answer(params))
        token = _CONSENT.set(state)
        try:
            outcome = await self.router.call(tool, self.session_id(), raw)
        except Exception as exc:  # last line of defense: report the class, never the message or any input
            print(f"rea-mcp: internal error in {name}: {type(exc).__name__}", file=sys.stderr)
            return _text_result(
                '{"status":"error","error":{"category":"backend_error","message":"internal error","retryable":false}}',
                error=True,
            )
        finally:
            _CONSENT.reset(token)
        if isinstance(outcome, CapabilityListing):
            return _text_result(outcome.model_dump_json(), error=False)
        assert isinstance(outcome, ToolResponse)
        if state.needs_input and outcome.error is not None and outcome.error.category is ErrorCategory.DENIED_CONSENT:
            return types.InputRequiredResult(input_requests={CONSENT_KEY: _consent_request()})
        return _text_result(outcome.model_dump_json(exclude_defaults=True), error=outcome.status == "error")

    async def _list_resources(
        self, ctx: ServerRequestContext[None, object], params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        return types.ListResourcesResult(resources=[
            types.Resource(name=r.name, title=r.title, uri=r.uri, description=r.description, mime_type=r.mime_type)
            for r in self.catalog.static_resources()
        ])

    async def _list_templates(
        self, ctx: ServerRequestContext[None, object], params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        return types.ListResourceTemplatesResult(resource_templates=[
            types.ResourceTemplate(
                name=t.name, title=t.title, uri_template=t.uri_template, description=t.description,
                mime_type=t.mime_type,
            )
            for t in self.catalog.templates()
        ])

    async def _read_resource(
        self, ctx: ServerRequestContext[None, object], params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        try:
            content = self.catalog.read(params.uri)
        except RegistryError as exc:
            code = RESOURCE_NOT_FOUND if exc.kind == "not_found" else (
                types.INVALID_PARAMS if exc.kind == "invalid" else types.INTERNAL_ERROR
            )
            raise MCPError(code, str(exc)) from exc
        return types.ReadResourceResult(contents=[
            types.TextResourceContents(uri=content.uri, mime_type=content.mime_type, text=content.text)
        ])

    async def _list_prompts(
        self, ctx: ServerRequestContext[None, object], params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        arguments = [
            types.PromptArgument(name=a.name, description=a.description, required=a.required)
            for a in PROMPT_ARGUMENTS
        ]
        return types.ListPromptsResult(prompts=[
            types.Prompt(name=p.name, title=p.title, description=p.description, arguments=list(arguments))
            for p in PLAYBOOKS
        ])

    async def _get_prompt(
        self, ctx: ServerRequestContext[None, object], params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        try:
            playbook = get_playbook(params.name)
            text = render_prompt(params.name, params.arguments)
        except PromptError as exc:
            raise MCPError(types.INVALID_PARAMS, str(exc)) from exc
        return types.GetPromptResult(
            description=playbook.description,
            messages=[types.PromptMessage(role="user", content=types.TextContent(text=text))],
        )

    @asynccontextmanager
    async def _lifespan(self, server: Server[None]) -> AsyncIterator[None]:
        try:
            yield None
        finally:  # release the loopback HTTP clients of any backend that holds one
            for backend in self._backends:
                if isinstance(backend, Closeable):
                    await backend.aclose()

    def _build_server(self) -> Server[None]:
        return Server(
            SERVER_NAME,
            version=SERVER_VERSION,
            instructions=INSTRUCTIONS,
            lifespan=self._lifespan,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
            on_list_resources=self._list_resources,
            on_list_resource_templates=self._list_templates,
            on_read_resource=self._read_resource,
            on_list_prompts=self._list_prompts,
            on_get_prompt=self._get_prompt,
        )


def build_app(env: Mapping[str, str], *, extra_backends: Sequence[DisassemblerBackend] = ()) -> ReaApp:
    """Validate ``env`` and construct everything. Raises ``ConfigError``."""
    return ReaApp(load_config(env), env, extra_backends=extra_backends)


async def serve(app: ReaApp) -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.server.run(read_stream, write_stream, app.server.create_initialization_options())


def main() -> int:
    try:
        app = build_app(dict(os.environ))
    except ConfigError as exc:
        print(f"rea-mcp: configuration error: {exc}", file=sys.stderr)
        return 2
    for warning in app.config.warnings:
        print(f"rea-mcp: warning: {warning}", file=sys.stderr)
    asyncio.run(serve(app))
    return 0
