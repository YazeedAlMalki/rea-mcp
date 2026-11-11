"""Phase 2: loopback hardening, IDA (MCP/JSON-RPC) and Ghidra (REST) wire mocks, Podman runner,
router integration (structural edits, epochs, split redaction, script inputs)."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import JsonValue, TypeAdapter, ValidationError

from rea_mcp.adapters.base import (
    LoopbackHttp,
    McpHttpClient,
    McpToolBackend,
    ToolVariant,
)
from rea_mcp.adapters.ghidra import GhidraBackend
from rea_mcp.adapters.ida_free import IdaFreeBackend
from rea_mcp.adapters.ida_pro import IdaProBackend
from rea_mcp.adapters.podman_runner import (
    PodmanScriptRunner,
    ProcessOutput,
    build_podman_argv,
    SandboxLimits,
)
from rea_mcp.core.models import (
    BackendItem,
    BackendKind,
    BackendResult,
    Capability,
    DecompileArgs,
    ErrorCategory,
    MutateRequest,
    QueryRequest,
    ToolResponse,
)
from rea_mcp.core.router import (
    BackendCall,
    BackendError,
    CapabilityRouter,
    DisassemblerBackend,
    IsolatedScriptRunner,
    SandboxUnavailableError,
    ScriptFile,
    ToolName,
)
from rea_mcp.core.security import (
    AuditLog,
    Authorizer,
    DenyAllConsent,
    RedactionPipeline,
    SecurityDenied,
    SecurityPolicy,
)

JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
SESSION = "sess-0002"


def jobj(raw: bytes | str) -> dict[str, JsonValue]:
    value = JSON.validate_json(raw)
    assert isinstance(value, dict)
    return value


def jint(value: JsonValue) -> int:
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


# --------------------------------------------------------------------------- #
# Fake MCP server (JSON-RPC 2.0 over HTTP) behind httpx.MockTransport
# --------------------------------------------------------------------------- #


class FakeMcp:
    def __init__(
        self,
        tools: Mapping[str, Mapping[str, str]],
        *,
        required: Mapping[str, Sequence[str]] | None = None,
        sse: bool = False,
    ) -> None:
        self.tools = tools
        self.required = required or {}
        self.sse = sse
        self.replies: dict[str, str] = {}
        self.handlers: dict[str, Callable[[dict[str, JsonValue]], str]] = {}
        self.error_tools: set[str] = set()
        self.calls: list[tuple[str, dict[str, JsonValue]]] = []
        self.methods: list[str] = []
        self.sessions: list[str | None] = []
        self.client_headers: list[Mapping[str, str]] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        message = jobj(request.content)
        method = str(message.get("method"))
        self.methods.append(method)
        self.sessions.append(request.headers.get("mcp-session-id"))
        self.client_headers.append(dict(request.headers))
        if method == "notifications/initialized":
            return httpx.Response(202)
        params_raw = message.get("params")
        params = params_raw if isinstance(params_raw, dict) else {}
        headers: dict[str, str] = {}
        result: dict[str, JsonValue]
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {}}
            headers["mcp-session-id"] = "sess-abc"
        elif method == "tools/list":
            listing: list[JsonValue] = []
            for name, props in self.tools.items():
                schema_props: dict[str, JsonValue] = {p: {"type": t} for p, t in props.items()}
                required: list[JsonValue] = [r for r in self.required.get(name, [])]
                listing.append(
                    {"name": name, "inputSchema": {"type": "object", "properties": schema_props, "required": required}}
                )
            result = {"tools": listing}
        elif method == "tools/call":
            name = str(params.get("name"))
            raw_args = params.get("arguments")
            arguments = raw_args if isinstance(raw_args, dict) else {}
            self.calls.append((name, arguments))
            handler = self.handlers.get(name)
            text = handler(arguments) if handler is not None else self.replies.get(name, "ok")
            result = {"content": [{"type": "text", "text": text}], "isError": name in self.error_tools}
        else:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32601, "message": "nope"}})
        body = json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
        if self.sse:
            return httpx.Response(
                200, headers={**headers, "content-type": "text/event-stream"}, text=f"event: message\ndata: {body}\n\n"
            )
        return httpx.Response(200, headers={**headers, "content-type": "application/json"}, text=body)


def mcp_client(fake: FakeMcp) -> McpHttpClient:
    return McpHttpClient(LoopbackHttp("http://127.0.0.1:13337", transport=fake.transport()))


SPEC_TOOLS: dict[str, dict[str, str]] = {
    "decompile_function": {"address": "string"},
    "disassemble_function": {"start_address": "string"},
    "list_functions": {"offset": "integer", "count": "integer"},
    "list_strings": {"offset": "integer", "count": "integer", "filter": "string"},
    "list_imports": {"offset": "integer", "count": "integer"},
    "get_xrefs_to": {"address": "string"},
    "rename_function": {"function_address": "string", "new_name": "string"},
    "rename_local_variable": {"function_address": "string", "old_name": "string", "new_name": "string"},
    "set_function_prototype": {"function_address": "string", "prototype": "string"},
    "set_local_variable_type": {"function_address": "string", "variable_name": "string", "new_type": "string"},
    "set_decompiler_comment": {"address": "string", "comment": "string"},
    "set_disassembly_comment": {"address": "string", "comment": "string"},
    # present on the server, must stay unreachable:
    "py_eval": {"code": "string"},
    "dbg_start": {},
    "dbg_write": {"regions": "array"},
    "patch": {"patches": "array"},
    "patch_asm": {"address": "string", "asm": "string"},
    "put_int": {"items": "array"},
    "idb_save": {"path": "string"},
}
README_TOOLS: dict[str, dict[str, str]] = {
    "decompile": {"addr": "string"},
    "disasm": {"addr": "string"},
    "imports": {"offset": "integer", "count": "integer"},
    "find_bytes": {"patterns": "array", "limit": "integer", "offset": "integer"},
    "callgraph": {"roots": "array", "max_depth": "integer"},
    "get_bytes": {"addr": "string", "size": "integer"},
    "py_eval": {"code": "string"},
}


# --------------------------------------------------------------------------- #
# Router harness
# --------------------------------------------------------------------------- #


def build_router(
    backends: Sequence[DisassemblerBackend],
    tmp_path: Path,
    env: Mapping[str, str] | None = None,
    runner: IsolatedScriptRunner | None = None,
    durable: bool = True,
) -> CapabilityRouter:
    values = dict(env or {})
    policy = SecurityPolicy.from_environ(values)
    audit = AuditLog(tmp_path / "audit.jsonl" if durable else None)
    return CapabilityRouter(
        backends=backends,
        authorizer=Authorizer(policy, audit, DenyAllConsent()),
        redaction=RedactionPipeline.from_policy(policy, values),
        script_runner=runner,
        cursor_key=b"k" * 32,
    )


async def call(router: CapabilityRouter, tool: ToolName, body: Mapping[str, object]) -> ToolResponse:
    out = await router.call(tool, SESSION, json.dumps(body))
    assert isinstance(out, ToolResponse)
    return out


def category(response: ToolResponse) -> ErrorCategory:
    assert response.error is not None, response
    return response.error.category


# --------------------------------------------------------------------------- #
# LoopbackHttp hardening
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    ["http://localhost:13337", "http://10.0.0.5:8080", "http://0.0.0.0:80", "http://127.1:80",
     "http://user:pw@127.0.0.1:80", "ftp://127.0.0.1", "http://127.0.0.1.evil.example", "http://[::2]:80"],
)
def test_non_loopback_targets_rejected(url: str) -> None:
    with pytest.raises(SecurityDenied):
        LoopbackHttp(url)


def test_literal_loopbacks_accepted_and_proxy_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:3128")
    for url in ("http://127.0.0.1:8080", "http://[::1]:8080"):
        http = LoopbackHttp(url)
        assert http._client.trust_env is False and http._client.follow_redirects is False  # noqa: SLF001


def test_redirects_oversize_headers_paths_and_deadline() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/redir":
            return httpx.Response(302, headers={"location": "http://evil.example/steal"})
        if request.url.path == "/big":
            return httpx.Response(200, content=b"x" * 5000)
        return httpx.Response(200, text="ok")

    async def scenario() -> None:
        http = LoopbackHttp("http://127.0.0.1:1", transport=httpx.MockTransport(handler), max_response_bytes=1000)
        with pytest.raises(BackendError, match="redirect"):
            await http.request("GET", "/redir")
        assert seen == ["/redir"]  # the Location was never followed
        with pytest.raises(BackendError, match="size limit"):
            await http.request("GET", "/big")
        for name in ("Authorization", "x-api-key", "Cookie", "Host", "Proxy-Authorization"):
            with pytest.raises(SecurityDenied):
                await http.request("GET", "/ok", headers={name: "x"})
        with pytest.raises(BackendError, match="invalid request path"):
            await http.request("GET", "/a/../b")
        with pytest.raises(BackendError, match="invalid request path"):
            await http.request("GET", "//evil.example/x")

        async def slow(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(1)
            return httpx.Response(200)

        fast = LoopbackHttp("http://127.0.0.1:1", transport=httpx.MockTransport(slow), total_timeout_s=0.05)
        with pytest.raises(BackendError) as info:
            await fast.request("GET", "/ok")
        assert info.value.retryable

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# IDA Pro / IDA Free (MCP JSON-RPC)
# --------------------------------------------------------------------------- #


def test_ida_pro_spec_names_hex_normalization_and_dangerous_tools_unreachable(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fake.replies["decompile_function"] = "int main(void) { return 0; }"

    async def scenario() -> None:
        backend = IdaProBackend(mcp_client(fake))
        await backend.start()
        assert fake.methods[:3] == ["initialize", "notifications/initialized", "tools/list"]
        for capability in (Capability.PATCH_BYTES, Capability.PATCH_ASM, Capability.WRITE_MEMORY,
                           Capability.SAVE_DATABASE, Capability.SCRIPT_EVAL, Capability.DEBUGGER_CONTROL,
                           Capability.FIND_BYTES, Capability.OPEN_DATABASE):
            assert not backend.supports(capability)
        router = build_router([backend], tmp_path)
        out = await call(router, "rea_query", {"args": {"capability": "decompile", "address": 4198400}})
        assert out.status == "ok" and out.fragments[0].text.startswith("int main")
        assert fake.calls == [("decompile_function", {"address": "0x401000"})]
        assert fake.sessions[-1] == "sess-abc"  # session id echoed after initialize
        assert fake.client_headers[-1]["mcp-protocol-version"] == "2025-06-18"
        # name-based decompile is not an IDA capability
        by_name = await call(router, "rea_query", {"args": {"capability": "decompile", "name": "main"}})
        assert category(by_name) is ErrorCategory.UNSUPPORTED_CAPABILITY
        # a privileged capability fails closed at the router and never reaches the wire
        patch = await call(router, "rea_privileged", {"args": {
            "capability": "patch_bytes", "address": 4096, "data": "90", "justification": "nop out check"}})
        assert category(patch) is ErrorCategory.DENIED_OVERRIDE
        assert {name for name, _ in fake.calls} == {"decompile_function"}

    asyncio.run(scenario())


def test_blocked_tools_cannot_be_named_by_a_profile_or_called() -> None:
    fake = FakeMcp(SPEC_TOOLS)
    with pytest.raises(ValueError, match="blocked tool"):
        McpToolBackend(BackendKind.IDA_PRO, mcp_client(fake), {(Capability.DECOMPILE, ""): (ToolVariant("py_eval"),)})

    async def scenario() -> None:
        client = mcp_client(fake)
        await client.connect()
        for name in ("py_eval", "dbg_start", "dbg_write", "patch", "patch_asm", "put_int", "idb_save"):
            with pytest.raises(BackendError, match="blocked"):
                await client.call_tool(name, {})
        assert fake.calls == []

    asyncio.run(scenario())


def test_ida_paging_asks_for_limit_plus_one_and_cursor_walks_all_pages(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    asked: list[tuple[int, int]] = []

    def listing(args: dict[str, JsonValue]) -> str:
        offset, count = jint(args["offset"]), jint(args["count"])
        asked.append((offset, count))
        return json.dumps([{"name": f"sub_{i}", "addr": hex(i)} for i in range(offset, min(offset + count, 7))])

    fake.handlers["list_functions"] = listing

    async def scenario() -> None:
        router = build_router([IdaProBackend(mcp_client(fake))], tmp_path)
        names: list[str] = []
        cursor: str | None = None
        for _ in range(5):
            args: dict[str, object] = {"capability": "list_functions", "limit": 3}
            if cursor:
                args["cursor"] = cursor
            out = await call(router, "rea_query", {"args": args})
            assert out.status == "ok" and out.meta is not None
            names += [f.label for f in out.fragments]
            cursor = out.meta.next_cursor
            if cursor is None:
                break
        assert names == [f"sub_{i}" for i in range(7)]
        assert asked == [(0, 4), (3, 4), (6, 4)]  # limit + 1, exact end detection

    asyncio.run(scenario())


def test_sse_framed_reply_is_parsed() -> None:
    fake = FakeMcp(SPEC_TOOLS, sse=True)
    fake.replies["decompile_function"] = "void f(){}"

    async def scenario() -> None:
        backend = IdaProBackend(mcp_client(fake))
        out = await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x10), 0, None))
        assert out.items[0].text == "void f(){}"

    asyncio.run(scenario())


def _decompile(address: int) -> DecompileArgs:
    return DecompileArgs(capability="decompile", address=address)


def test_tool_errors_and_embedded_item_errors_become_backend_errors() -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fake.error_tools.add("decompile_function")
    fake.replies["decompile_function"] = "Decompilation failed: no function"
    fake.replies["rename_function"] = json.dumps([{"address": "0x10", "error": "not a function"}])
    from rea_mcp.core.models import RenameSymbolArgs

    async def scenario() -> None:
        backend = IdaProBackend(mcp_client(fake))
        with pytest.raises(BackendError, match="Decompilation failed"):
            await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x10), 0, None))
        rename = RenameSymbolArgs(capability="rename_symbol", address=0x10, new_name="x")
        with pytest.raises(BackendError, match="not a function"):
            await backend.execute(BackendCall(None, Capability.RENAME_SYMBOL, rename, 0, None))

    asyncio.run(scenario())


def test_schema_gating_fails_closed_and_reports_why() -> None:
    wrong_args = {**SPEC_TOOLS, "decompile_function": {"ea_value": "string"}}  # names do not match
    needs_extra = {**SPEC_TOOLS, "get_xrefs_to": {"address": "string", "mode": "string"}}
    fake = FakeMcp(needs_extra, required={"get_xrefs_to": ["mode"]})

    async def scenario() -> None:
        backend = IdaProBackend(mcp_client(fake))
        await backend.start()
        assert not backend.supports(Capability.XREFS_TO)
        assert any("required arguments ['mode']" in p for p in backend.diagnostics())
        fake2 = FakeMcp(wrong_args)
        backend2 = IdaProBackend(mcp_client(fake2))
        await backend2.start()
        assert not backend2.supports(Capability.DECOMPILE)
        assert "ea_value" in backend2.describe_tools()

    asyncio.run(scenario())


def test_ida_free_uses_readme_names_resolves_argument_shapes_and_has_no_sessions() -> None:
    fake = FakeMcp(README_TOOLS)
    fake.replies["decompile"] = "int sub(void){}"
    fake.replies["find_bytes"] = json.dumps([{"address": "0x40"}])
    fake.replies["get_bytes"] = "90 90"
    from rea_mcp.core.models import CallgraphArgs, FindBytesArgs, GetBytesArgs

    async def scenario() -> None:
        backend = IdaFreeBackend(mcp_client(fake))
        await backend.start()
        assert backend.kind is BackendKind.IDA_FREE
        assert not backend.supports(Capability.LIST_DATABASES) and not backend.supports(Capability.OPEN_DATABASE)
        assert not backend.supports(Capability.SCRIPT_EVAL)
        await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x401000), 0, None))
        await backend.execute(BackendCall(None, Capability.FIND_BYTES, FindBytesArgs(capability="find_bytes", pattern="48 8B ?? 05", limit=5), 0, None))
        await backend.execute(BackendCall(None, Capability.CALLGRAPH, CallgraphArgs(capability="callgraph", roots=(0x1000, 0x2000), max_depth=2), 0, None))
        await backend.execute(BackendCall(None, Capability.GET_BYTES, GetBytesArgs(capability="get_bytes", address=0x1000, size=2), 0, None))
        calls = dict(fake.calls)
        assert calls["decompile"] == {"addr": "0x401000"}  # schema names the argument 'addr'
        assert calls["find_bytes"] == {"patterns": ["48 8B ?? 05"], "limit": 6, "offset": 0}  # array-typed
        assert calls["callgraph"] == {"roots": ["0x1000", "0x2000"], "max_depth": 2}
        assert calls["get_bytes"] == {"addr": "0x1000", "size": 2}

    asyncio.run(scenario())


def test_database_id_is_injected_only_when_the_tool_takes_one() -> None:
    tools = {"decompile": {"addr": "string", "database": "string"}}
    fake = FakeMcp(tools, required={"decompile": ["addr", "database"]})

    async def scenario() -> None:
        backend = IdaProBackend(mcp_client(fake))
        await backend.execute(BackendCall("db-1", Capability.DECOMPILE, _decompile(0x10), 0, None))
        assert fake.calls[-1][1] == {"addr": "0x10", "database": "db-1"}
        with pytest.raises(BackendError, match="database id"):
            await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x10), 0, None))

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Ghidra (REST, plain text)
# --------------------------------------------------------------------------- #


class FakeGhidra:
    def __init__(self) -> None:
        self.log: list[tuple[str, str, str]] = []  # (method, path, query-or-form)
        self.routes: dict[tuple[str, str], Callable[[dict[str, str]], httpx.Response]] = {}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        if request.method == "POST":
            params = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
        if request.url.path != "/health":  # the dialect probe; 1.x answers 404 and its route logs stay unchanged
            self.log.append((request.method, request.url.path, json.dumps(params, sort_keys=True)))
        handler = self.routes.get((request.method, request.url.path))
        return handler(params) if handler is not None else httpx.Response(404, text="Not Found")


def ghidra(fake: FakeGhidra, **kw: bool) -> GhidraBackend:
    return GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=fake.transport()), **kw)


def text(body: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, text=body)


def test_ghidra_spec_routes_paging_and_form_encoding(tmp_path: Path) -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/methods")] = lambda p: text(
        "\n".join(f"fn_{i}" for i in range(int(p["offset"]), min(int(p["offset"]) + int(p["limit"]), 5)))
    )
    fake.routes[("GET", "/decompile")] = lambda p: text(f"void {p['name']}(void) {{}}")
    fake.routes[("POST", "/setDecompilerComment")] = lambda p: text("Comment set successfully")

    async def scenario() -> None:
        router = build_router([ghidra(fake)], tmp_path, {"REA_AUTO_GRANT_MUTATE": "1"})
        seen: list[str] = []
        cursor: str | None = None
        while True:
            args: dict[str, object] = {"capability": "list_functions", "limit": 2}
            if cursor:
                args["cursor"] = cursor
            out = await call(router, "rea_query", {"args": args})
            assert out.status == "ok" and out.meta is not None
            seen += [f.label for f in out.fragments]
            cursor = out.meta.next_cursor
            if cursor is None:
                break
        assert seen == [f"fn_{i}" for i in range(5)]
        assert [json.loads(q) for m, p, q in fake.log if p == "/methods"][0] == {"limit": "3", "offset": "0"}
        named = await call(router, "rea_query", {"args": {"capability": "decompile", "name": "main"}})
        assert named.fragments[0].text == "void main(void) {}"
        commented = await call(router, "rea_mutate", {"args": {
            "capability": "set_comment", "address": 4198400, "comment": "key setup", "kind": "decompiler"}})
        assert commented.status == "ok"
        assert fake.log[-1] == ("POST", "/setDecompilerComment", json.dumps({"address": "0x401000", "comment": "key setup"}, sort_keys=True))

    asyncio.run(scenario())


def test_ghidra_404_falls_back_to_observed_route_and_is_remembered() -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/imports")] = lambda p: text("KERNEL32.dll!CreateFileA\nKERNEL32.dll!ReadFile")

    async def scenario() -> None:
        backend = ghidra(fake)
        from rea_mcp.core.models import PagedListArgs

        args = PagedListArgs(capability="list_imports", limit=10)
        first = await backend.execute(BackendCall(None, Capability.LIST_IMPORTS, args, 0, None))
        second = await backend.execute(BackendCall(None, Capability.LIST_IMPORTS, args, 0, None))
        assert [i.text for i in first.items] == ["KERNEL32.dll!CreateFileA", "KERNEL32.dll!ReadFile"]
        assert [p for _, p, _ in fake.log] == ["/Imports", "/imports", "/imports"]  # 404 cached
        assert second.next_offset is None
        strict = ghidra(FakeGhidra(), allow_observed_routes=False)
        with pytest.raises(BackendError):
            await strict.execute(BackendCall(None, Capability.LIST_IMPORTS, args, 0, None))

    asyncio.run(scenario())


def test_ghidra_address_decompile_needs_observed_routes_and_failure_text_is_an_error() -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/decompile_function")] = lambda p: text(f"// at {p['address']}\nvoid f(){{}}")

    async def scenario() -> None:
        backend = ghidra(fake)
        out = await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x401000), 0, None))
        assert out.items[0].text.startswith("// at 0x401000")
        strict = ghidra(fake, allow_observed_routes=False)
        with pytest.raises(BackendError, match="cannot decompile"):
            await strict.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x401000), 0, None))
        fake.routes[("GET", "/decompile_function")] = lambda p: text("Function not found")
        with pytest.raises(BackendError, match="Function not found"):
            await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x1), 0, None))
        fake.routes[("GET", "/decompile_function")] = lambda p: text("boom", 500)
        with pytest.raises(BackendError, match="HTTP 500"):
            await backend.execute(BackendCall(None, Capability.DECOMPILE, _decompile(0x1), 0, None))

    asyncio.run(scenario())


def test_ghidra_rename_symbol_tries_next_route_on_logical_failure_and_variable_rename_resolves_name() -> None:
    fake = FakeGhidra()
    fake.routes[("POST", "/renameData")] = lambda p: text("Rename failed: no data at address")
    fake.routes[("POST", "/rename_function_by_address")] = lambda p: text("Renamed successfully")
    fake.routes[("GET", "/get_function_by_address")] = lambda p: text("Function: main at 00401000\nSignature: int main(void)")
    fake.routes[("POST", "/renameVariable")] = lambda p: text("Variable renamed")
    from rea_mcp.core.models import RenameSymbolArgs, RenameVariableArgs

    async def scenario() -> None:
        backend = ghidra(fake)
        out = await backend.execute(BackendCall(None, Capability.RENAME_SYMBOL, RenameSymbolArgs(capability="rename_symbol", address=0x401000, new_name="entry"), 0, None))
        assert out.items[0].text == "Renamed successfully"
        posts = [(p, json.loads(q)) for m, p, q in fake.log if m == "POST"]
        assert posts == [
            ("/renameData", {"address": "0x401000", "newName": "entry"}),
            ("/rename_function_by_address", {"function_address": "0x401000", "new_name": "entry"}),
        ]
        before = out.generation
        rv = RenameVariableArgs(capability="rename_variable", function_address=0x401000, old_name="local_8", new_name="key")
        out2 = await backend.execute(BackendCall(None, Capability.RENAME_VARIABLE, rv, 0, None))
        assert out2.generation > before
        assert fake.log[-1][1:] == ("/renameVariable", json.dumps({"functionName": "main", "newName": "key", "oldName": "local_8"}, sort_keys=True))
        fake.routes[("GET", "/get_function_by_address")] = lambda p: text("No function at address")
        with pytest.raises(BackendError, match="resolve a function name"):
            await backend.execute(BackendCall(None, Capability.RENAME_VARIABLE, rv, 0, None))

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Models and router: structural edits, router-owned epochs, split redaction
# --------------------------------------------------------------------------- #


def test_new_model_bounds() -> None:
    ok = MutateRequest.model_validate_json('{"args":{"capability":"define_function","start":"0x1000","end":"0x1040"}}')
    assert ok.args.capability == "define_function"
    for bad in (
        '{"args":{"capability":"define_function","start":4096,"end":4096}}',
        '{"args":{"capability":"define_function","start":4096,"end":2}}',
        '{"args":{"capability":"undefine","address":4096,"size":4097}}',
        '{"args":{"capability":"declare_stack_var","function_address":1,"frame_offset":70000,"name":"a","declaration":"int a;"}}',
        '{"args":{"capability":"delete_stack_var","function_address":1,"name":"bad\\u0001"}}',
    ):
        with pytest.raises(ValidationError):
            MutateRequest.model_validate_json(bad)
    for bad_q in ('{"args":{"capability":"decompile"}}', '{"args":{"capability":"decompile","address":1,"name":"main"}}'):
        with pytest.raises(ValidationError):
            QueryRequest.model_validate_json(bad_q)


class StubBackend:
    """Backend whose own generation never changes: only the router's epoch can invalidate state."""

    kind = BackendKind.IDA_PRO

    def __init__(self) -> None:
        self.calls: list[Capability] = []
        self.texts: dict[Capability, str] = {}

    def supports(self, capability: Capability) -> bool:
        return True

    async def execute(self, call: BackendCall) -> BackendResult:
        self.calls.append(call.capability)
        if call.capability is Capability.LIST_FUNCTIONS:
            limit = getattr(call.args, "limit")
            items = tuple(BackendItem(label=f"f{i}", text=f"f{i} " + "x" * 30) for i in range(call.offset, min(call.offset + limit, 30)))
            more = call.offset + limit < 30
            return BackendResult(items=items, next_offset=call.offset + limit if more else None, generation=1)
        text_ = self.texts.get(call.capability, "ok")
        channel: Literal["artifact", "host"] = (
            "host" if call.capability in (Capability.LIST_DATABASES, Capability.OPEN_DATABASE) else "artifact"
        )
        return BackendResult(items=(BackendItem(label=call.capability.value, text=text_, channel=channel),), generation=1)


STRUCTURAL: list[dict[str, object]] = [
    {"capability": "define_function", "start": 0x1000, "end": 0x1040},
    {"capability": "define_code", "address": 0x1000},
    {"capability": "undefine", "address": 0x1000, "size": 16},
    {"capability": "declare_stack_var", "function_address": 0x1000, "frame_offset": -8, "name": "key", "declaration": "uint8_t key[8];"},
    {"capability": "delete_stack_var", "function_address": 0x1000, "name": "key"},
]


@pytest.mark.parametrize("args", STRUCTURAL, ids=[str(a["capability"]) for a in STRUCTURAL])
def test_structural_edits_are_mutate_safe_grant_gated_and_bump_the_epoch(args: dict[str, object], tmp_path: Path) -> None:
    async def scenario() -> None:
        backend = StubBackend()
        denied = build_router([backend], tmp_path / "a")
        assert category(await call(denied, "rea_mutate", {"args": args})) is ErrorCategory.DENIED_CONSENT
        assert backend.calls == []
        # the privileged facade must not accept them, and no keyfile/override is needed with a grant
        wrong = await call(denied, "rea_privileged", {"args": {**args, "justification": "structural fix"}})
        assert category(wrong) is ErrorCategory.INVALID_REQUEST
        router = build_router([backend], tmp_path / "b", {"REA_AUTO_GRANT_MUTATE": "1"})
        first = await call(router, "rea_query", {"args": {"capability": "list_functions", "limit": 5}})
        assert first.meta is not None
        receipt, cursor = first.meta.receipt_id, first.meta.next_cursor
        assert receipt and cursor
        assert (await call(router, "rea_mutate", {"args": args})).status == "ok"
        stale_receipt = await call(router, "rea_query", {"args": {"capability": "list_functions", "limit": 5}, "control": {"receipt_id": receipt}})
        assert category(stale_receipt) is ErrorCategory.STALE_RECEIPT
        stale_cursor = await call(router, "rea_query", {"args": {"capability": "list_functions", "limit": 5, "cursor": cursor}})
        assert category(stale_cursor) is ErrorCategory.STALE_CURSOR  # backend generation never moved

    asyncio.run(scenario())


def test_epoch_follows_backend_generation_changes_made_out_of_band(tmp_path: Path) -> None:
    class Moving(StubBackend):
        generation = 1

        async def execute(self, call: BackendCall) -> BackendResult:
            result = await super().execute(call)
            return result.model_copy(update={"generation": self.generation})

    async def scenario() -> None:
        backend = Moving()
        router = build_router([backend], tmp_path)
        first = await call(router, "rea_query", {"args": {"capability": "list_functions", "limit": 5}})
        assert first.meta is not None
        cursor = first.meta.next_cursor
        backend.generation = 2  # e.g. the analyst edited the IDB in the GUI
        moved = await call(router, "rea_query", {"args": {"capability": "list_functions", "limit": 5, "cursor": cursor}})
        assert category(moved) is ErrorCategory.STALE_CURSOR

    asyncio.run(scenario())


def test_host_channel_is_scrubbed_but_binary_text_keeps_paths_and_secrets(tmp_path: Path) -> None:
    async def scenario() -> None:
        root = tmp_path / "samples"
        root.mkdir()
        sample = root / "a.bin"
        sample.write_bytes(b"MZ")
        backend = StubBackend()
        backend.texts[Capability.LIST_DATABASES] = (
            f"db at {sample} and /home/yazeed/.ssh/id_rsa and C:\\Users\\yazeed\\x.i64\n"
            "Authorization: Bearer abcdefghijklmnop1234\nenv leak supersecretvalue123"
        )
        backend.texts[Capability.DECOMPILE] = (
            'const char *pdb = "C:\\\\Users\\\\dev\\\\proj\\\\a.pdb"; // /home/builder/src/x.c\n'
            'key = "AKIAABCDEFGHIJKLMNOP"; Authorization: Bearer zzzzzzzzzzzzzzzzzzzz; leak supersecretvalue123'
        )
        env = {"REA_ALLOWED_ROOTS": str(root), "MY_API_TOKEN": "supersecretvalue123"}
        router = build_router([backend], tmp_path / "w", env)
        dbs = await call(router, "rea_query", {"args": {"capability": "list_databases"}})
        host_text = dbs.fragments[0].text
        assert str(sample) in host_text  # inside an allowed root
        assert "/home/yazeed" not in host_text and "C:\\Users\\yazeed" not in host_text
        assert "abcdefghijklmnop1234" not in host_text and "supersecretvalue123" not in host_text
        art = (await call(router, "rea_query", {"args": {"capability": "decompile", "address": 1}})).fragments[0]
        assert "C:\\\\Users\\\\dev\\\\proj\\\\a.pdb" in art.text and "/home/builder/src/x.c" in art.text  # evidence
        assert "AKIAABCDEFGHIJKLMNOP" in art.text and "zzzzzzzzzzzzzzzzzzzz" in art.text
        assert "supersecretvalue123" not in art.text and "[REDACTED:host_secret]" in art.text  # host secret: always
        kinds = {re.split(r"[:\]]", t)[1] for t in art.secret_candidates}
        assert {"aws_access_key", "bearer"} <= kinds

    asyncio.run(scenario())


def test_backend_error_text_is_scrubbed_before_reaching_the_model(tmp_path: Path) -> None:
    class Failing(StubBackend):
        async def execute(self, call: BackendCall) -> BackendResult:
            raise BackendError("cannot open /home/yazeed/secret/db.i64 with Authorization: Bearer abcdefghijklmnop1234")

    async def scenario() -> None:
        router = build_router([Failing()], tmp_path)
        out = await call(router, "rea_query", {"args": {"capability": "list_functions"}})
        assert category(out) is ErrorCategory.BACKEND_ERROR and out.error is not None
        assert "/home/yazeed" not in out.error.message and "abcdefghijklmnop1234" not in out.error.message

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Podman runner
# --------------------------------------------------------------------------- #


class FakeLauncher:
    def __init__(self, output: ProcessOutput | None = None) -> None:
        self.output = output or ProcessOutput(0, b"hello\n", b"", False, False)
        self.runs: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.input_snapshot: dict[str, bytes] = {}
        self.input_modes: dict[str, int] = {}

    async def run(self, argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, max_output: int) -> ProcessOutput:
        self.runs.append((tuple(argv), dict(env)))
        if "run" in argv:
            mount = next(a for a in argv if a.startswith("--volume="))
            directory = Path(mount.split("=", 1)[1].split(":", 1)[0])
            for child in directory.iterdir():
                self.input_snapshot[child.name] = child.read_bytes()
                self.input_modes[child.name] = child.stat().st_mode & 0o777
        return self.output


def runner(launcher: FakeLauncher, tmp_path: Path, limits: SandboxLimits = SandboxLimits()) -> PodmanScriptRunner:
    return PodmanScriptRunner(
        podman_path="/usr/bin/podman", launcher=launcher, tmp_root=tmp_path,
        environ={"PATH": "/usr/bin", "HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000", "OPENAI_API_KEY": "sk-hostsecret"},
        geteuid=lambda: 1000, limits=limits,
    )


def test_podman_argv_has_every_isolation_flag(tmp_path: Path) -> None:
    argv = build_podman_argv(podman="podman", image="docker.io/library/python:3.13-slim", name="rea-x",
                             input_dir=tmp_path / "input", limits=SandboxLimits(), timeout_s=20)
    for flag in ("run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=128", "--pull=never",
                 "--user=65534:65534", "--timeout=20"):
        assert flag in argv, flag
    assert f"--volume={tmp_path / 'input'}:/input:ro,Z" in argv
    assert any(a.startswith("--tmpfs=/tmp:rw,noexec,nosuid,nodev") for a in argv)
    assert argv[-3:] == ("python3", "-I", "/input/script.py")
    assert not any(a.startswith(("--privileged", "--net=host", "--network=host", "--cap-add")) for a in argv)
    with pytest.raises(SandboxUnavailableError):
        build_podman_argv(podman="podman", image="evil image;rm", name="n", input_dir=tmp_path, limits=SandboxLimits(), timeout_s=5)
    with pytest.raises(SandboxUnavailableError):
        build_podman_argv(podman="podman", image="python:3", name="n", input_dir=Path("/tmp/a:rw,b"), limits=SandboxLimits(), timeout_s=5)


def test_runner_mounts_inputs_readonly_scrubs_env_and_cleans_up(tmp_path: Path) -> None:
    launcher = FakeLauncher()

    async def scenario() -> None:
        result = await runner(launcher, tmp_path).run(
            "print('hello')", [ScriptFile("blob.bin", b"\x00\x01"), ScriptFile("dis.txt", b"mov eax, 1")], 30.0
        )
        assert [i.label for i in result.items] == ["stdout", "stderr", "exit_code"]
        assert result.items[0].text == "hello\n"

    asyncio.run(scenario())
    assert launcher.input_snapshot == {"script.py": b"print('hello')", "blob.bin": b"\x00\x01", "dis.txt": b"mov eax, 1"}
    assert all(mode == 0o644 for mode in launcher.input_modes.values())
    run_argv, env = launcher.runs[0]
    assert "OPENAI_API_KEY" not in env and set(env) <= {"PATH", "HOME", "XDG_RUNTIME_DIR"}
    name = next(a for a in run_argv if a.startswith("--name=")).split("=", 1)[1]
    assert launcher.runs[-1][0][1:] == ("rm", "-f", "-t", "0", name)  # forced removal by name
    assert list(tmp_path.glob("rea-sbx-*")) == []  # temp dir removed


def test_runner_failure_modes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        with pytest.raises(SandboxUnavailableError, match="rootless"):
            await PodmanScriptRunner(podman_path="/usr/bin/podman", launcher=FakeLauncher(), geteuid=lambda: 0).run("1", [], 30.0)
        monkeypatch.setattr(shutil, "which", lambda _: None)
        with pytest.raises(SandboxUnavailableError, match="not installed"):
            await PodmanScriptRunner(launcher=FakeLauncher(), geteuid=lambda: 1000).run("1", [], 30.0)
        with pytest.raises(SandboxUnavailableError, match="image"):
            await runner(FakeLauncher(ProcessOutput(125, b"", b"Error: image not known\n", False, False)), tmp_path).run("1", [], 30.0)
        with pytest.raises(BackendError, match="time limit"):
            await runner(FakeLauncher(ProcessOutput(-9, b"", b"", True, False)), tmp_path).run("while 1: pass", [], 30.0)
        flood = await runner(FakeLauncher(ProcessOutput(137, b"x" * 10, b"", False, True)), tmp_path).run("1", [], 30.0)
        assert flood.items[0].text.endswith("(output truncated)") and flood.items[2].text == "137"
        with pytest.raises(BackendError, match="invalid sandbox input name"):
            await runner(FakeLauncher(), tmp_path).run("1", [ScriptFile("../x", b"")], 30.0)
        with pytest.raises(BackendError, match="too large"):
            await runner(FakeLauncher(), tmp_path, limits=SandboxLimits(max_script_bytes=4)).run("print(1)", [], 30.0)
        assert list(tmp_path.glob("rea-sbx-*")) == []

    asyncio.run(scenario())


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not installed")
def test_real_podman_is_rootless_only_when_available() -> None:
    assert PodmanScriptRunner() is not None


# --------------------------------------------------------------------------- #
# script_eval end to end: router fetches inputs, sandbox never touches a backend
# --------------------------------------------------------------------------- #


class CapturingRunner:
    def __init__(self) -> None:
        self.code = ""
        self.files: list[ScriptFile] = []

    async def run(self, code: str, files: Sequence[ScriptFile], timeout_s: float) -> BackendResult:
        self.code, self.files = code, list(files)
        return BackendResult(
            items=(BackendItem(label="stdout", text="decoded: flag{x} leak supersecretvalue123"),), next_offset=None, generation=0
        )


PRIV_ENV = {"REA_PRIVILEGED_OVERRIDE": "enable-dangerous-ops", "REA_PRIVILEGED_ALLOW": "script_eval", "MY_API_TOKEN": "supersecretvalue123"}


def test_script_eval_inputs_are_fetched_by_the_router_with_read_only_calls(tmp_path: Path) -> None:
    async def scenario() -> None:
        backend = StubBackend()
        backend.texts[Capability.GET_BYTES] = "de ad be ef"
        backend.texts[Capability.DISASM] = "mov eax, 1\nret"
        cap = CapturingRunner()
        router = build_router([backend], tmp_path, PRIV_ENV, runner=cap)
        body = {"args": {
            "capability": "script_eval", "code": "print(open('/input/blob').read())", "justification": "xor-decode table",
            "inputs": [
                {"kind": "bytes", "name": "blob", "address": "0x1000", "size": 4},
                {"kind": "text", "name": "dis.txt", "source": "disasm", "address": "0x1000"},
            ]}}
        out = await call(router, "rea_privileged", {**body, "database": None})
        assert out.status == "ok", out
        assert [(f.name, f.data) for f in cap.files] == [("blob", bytes.fromhex("deadbeef")), ("dis.txt", b"mov eax, 1\nret")]
        assert backend.calls == [Capability.GET_BYTES, Capability.DISASM]  # nothing privileged, no py_eval equivalent
        assert "supersecretvalue123" not in out.fragments[0].text and "[REDACTED:host_secret]" in out.fragments[0].text
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert AuditLog.verify_chain(lines) and '"capability":"script_eval"' in lines[0]
        # reserved / duplicate names and wrong sizes are refused
        bad = json.loads(json.dumps(body))
        bad["args"]["inputs"][1]["name"] = "script.py"
        assert category(await call(router, "rea_privileged", bad)) is ErrorCategory.INVALID_REQUEST
        backend.texts[Capability.GET_BYTES] = "de ad"
        assert category(await call(router, "rea_privileged", body)) is ErrorCategory.BACKEND_ERROR

    asyncio.run(scenario())


def test_script_eval_without_override_or_runner_is_refused(tmp_path: Path) -> None:
    async def scenario() -> None:
        body = {"args": {"capability": "script_eval", "code": "print(1)", "justification": "xor-decode table"}}
        no_override = build_router([StubBackend()], tmp_path / "a", runner=CapturingRunner())
        assert category(await call(no_override, "rea_privileged", body)) is ErrorCategory.DENIED_OVERRIDE
        no_runner = build_router([StubBackend()], tmp_path / "b", PRIV_ENV)
        assert category(await call(no_runner, "rea_privileged", body)) is ErrorCategory.SANDBOX_UNAVAILABLE
        as_root = PodmanScriptRunner(podman_path="/usr/bin/podman", launcher=FakeLauncher(), geteuid=lambda: 0)
        rooted = build_router([StubBackend()], tmp_path / "c", PRIV_ENV, runner=as_root)
        assert category(await call(rooted, "rea_privileged", body)) is ErrorCategory.SANDBOX_UNAVAILABLE

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Phase 2 follow-ups: batch writers (ida-free-mcp / newer ida-pro-mcp) and Ghidra name fallback
# --------------------------------------------------------------------------- #

BATCH_TOOLS: dict[str, dict[str, str]] = {
    "rename": {"items": "array"},
    "set_comments": {"items": "array"},
    "set_type": {"items": "array"},
    "put_int": {"items": "array"},  # privileged: must stay unreachable
    "py_eval": {"code": "string"},
}


def test_ida_free_batch_writers_send_the_operator_supplied_item_shapes() -> None:
    from rea_mcp.core.models import RenameSymbolArgs, RenameVariableArgs, SetCommentArgs, SetTypeArgs

    fake = FakeMcp(BATCH_TOOLS)

    async def scenario() -> None:
        backend = IdaFreeBackend(mcp_client(fake))
        await backend.start()
        for capability in (
            Capability.RENAME_SYMBOL, Capability.RENAME_VARIABLE, Capability.SET_COMMENT,
            Capability.SET_TYPE, Capability.SET_FUNCTION_PROTOTYPE,
        ):
            assert backend.supports(capability)
        assert not backend.supports(Capability.PATCH_BYTES) and not backend.supports(Capability.SCRIPT_EVAL)

        def go(capability: Capability, args: RenameSymbolArgs | RenameVariableArgs | SetCommentArgs | SetTypeArgs) -> BackendCall:
            return BackendCall(None, capability, args, 0, None)

        await backend.execute(go(Capability.RENAME_SYMBOL, RenameSymbolArgs(capability="rename_symbol", address=0x401000, new_name="parse_header")))
        await backend.execute(go(Capability.RENAME_VARIABLE, RenameVariableArgs(capability="rename_variable", function_address=0x401000, old_name="v1", new_name="ctx")))
        await backend.execute(go(Capability.SET_COMMENT, SetCommentArgs(capability="set_comment", address=0x401010, comment="checks magic", kind="decompiler")))
        await backend.execute(go(Capability.SET_COMMENT, SetCommentArgs(capability="set_comment", address=0x401010, comment="cmp eax, 5", kind="disasm")))
        await backend.execute(go(Capability.SET_TYPE, SetTypeArgs(capability="set_type", address=0x401000, declaration="int __cdecl foo(void *)")))
        await backend.execute(go(Capability.SET_FUNCTION_PROTOTYPE, SetTypeArgs(capability="set_function_prototype", address=0x401000, declaration="int __cdecl bar(char *)")))
        assert fake.calls == [
            ("rename", {"items": [{"addr": "0x401000", "name": "parse_header"}]}),
            ("rename", {"items": [{"addr": "0x401000", "old": "v1", "new": "ctx"}]}),
            ("set_comments", {"items": [{"addr": "0x401010", "comment": "checks magic", "kind": "decompiler"}]}),
            ("set_comments", {"items": [{"addr": "0x401010", "comment": "cmp eax, 5", "kind": "disassembly"}]}),
            ("set_type", {"items": [{"addr": "0x401000", "ty": "int __cdecl foo(void *)"}]}),
            ("set_type", {"items": [{"addr": "0x401000", "ty": "int __cdecl bar(char *)"}]}),
        ]

    asyncio.run(scenario())


def test_ida_pro_prefers_spec_names_and_falls_back_to_batch_writers() -> None:
    from rea_mcp.core.models import RenameSymbolArgs

    rename = BackendCall(None, Capability.RENAME_SYMBOL, RenameSymbolArgs(capability="rename_symbol", address=0x1000, new_name="entry"), 0, None)

    async def scenario() -> None:
        both = FakeMcp({**SPEC_TOOLS, **BATCH_TOOLS})
        spec_backend = IdaProBackend(mcp_client(both))
        await spec_backend.start()
        await spec_backend.execute(rename)
        assert both.calls[0][0] == "rename_function"  # ordered fallbacks keep the spec first

        newer = FakeMcp(BATCH_TOOLS)
        batch_backend = IdaProBackend(mcp_client(newer))
        await batch_backend.start()
        await batch_backend.execute(rename)
        assert newer.calls == [("rename", {"items": [{"addr": "0x1000", "name": "entry"}]})]
        assert not batch_backend.supports(Capability.PATCH_BYTES)

    asyncio.run(scenario())


def test_ghidra_variable_rename_falls_back_to_decompile_signature_when_lookup_is_404() -> None:
    from rea_mcp.core.models import RenameVariableArgs

    rv = RenameVariableArgs(capability="rename_variable", function_address=0x401000, old_name="local_8", new_name="key")

    async def scenario(decompile_path: str, body: str, expected: str | None) -> None:
        fake = FakeGhidra()  # /get_function_by_address is not routed, so it answers 404
        fake.routes[("GET", decompile_path)] = lambda p: text(body)
        fake.routes[("POST", "/renameVariable")] = lambda p: text("Variable renamed")
        backend = ghidra(fake)
        call = BackendCall(None, Capability.RENAME_VARIABLE, rv, 0, None)
        if expected is None:
            with pytest.raises(BackendError, match="resolve a function name"):
                await backend.execute(call)
            return
        await backend.execute(call)
        gets = [(path, json.loads(q)) for m, path, q in fake.log if m == "GET"]
        assert ("/decompile_function", {"address": "0x401000"}) in gets
        posted = [json.loads(q) for m, path, q in fake.log if m == "POST"]
        assert posted == [{"functionName": expected, "newName": "key", "oldName": "local_8"}]

    asyncio.run(scenario("/decompile_function", "// header\nint parse_header(char *buf)\n{\n  return 0;\n}\n", "parse_header"))
    asyncio.run(scenario("/decompile_function", "void *__fastcall FUN_00401000(void)\n{\n}\n", "FUN_00401000"))
    asyncio.run(scenario("/decompile", "int helper(int a)\n{\n}\n", "helper"))  # the alternate route
    asyncio.run(scenario("/decompile_function", "Decompilation failed", None))
