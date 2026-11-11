"""GhidraMCP 2.0 dialect: replies are shaped exactly as the plugin's source builds them
(``Json.success`` / ``Json.error`` envelopes, ``Page`` and ``Model`` records, snake_case keys)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from pathlib import Path

import httpx
import pytest
from test_phase2 import FakeGhidra
from test_phase5 import dead_ida, dead_ida_free, factories, run_doctor

from rea_mcp.adapters.base import LoopbackHttp
from rea_mcp.adapters.ghidra import Dialect, GhidraBackend
from rea_mcp.core.models import (
    AnyArgs,
    Capability,
    DecompileArgs,
    PagedListArgs,
    RenameSymbolArgs,
    RenameVariableArgs,
    SetCommentArgs,
    SetTypeArgs,
)
from rea_mcp.core.router import BackendCall, BackendError

Handler = Callable[[dict[str, str]], httpx.Response]


def ok(data: object) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": data})


def fail(code: str, message: str, status: int = 404) -> httpx.Response:
    return httpx.Response(status, json={"success": False, "error": {"code": code, "message": message}})


def health(program: str | None = "SelfCAD.exe", version: str = "2.0.0") -> httpx.Response:
    return ok({
        "status": "ok", "version": version, "ghidra_version": "12.1.4", "mode": "gui", "capabilities": ["read"],
        "program": None if program is None else {"name": program, "project_path": "/p", "language_id": "x86:LE:64"},
    })


def page(items: Sequence[object], offset: int = 0, total: int | None = None, has_more: bool = False) -> httpx.Response:
    return ok({"items": items, "offset": offset, "limit": 100, "total": len(items) if total is None else total,
               "has_more": has_more})


def fake_v2(program: str | None = "SelfCAD.exe") -> FakeGhidra:
    fake = FakeGhidra()
    fake.routes[("GET", "/health")] = lambda p: health(program)
    return fake


def backend(fake: FakeGhidra) -> GhidraBackend:
    return GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=fake.transport()))


def call(cap: Capability, args: AnyArgs, offset: int = 0) -> BackendCall:
    return BackendCall(None, cap, args, offset, None)


def listing(fake: FakeGhidra) -> None:
    for route in ("/functions", "/segments", "/imports", "/exports", "/strings", "/data", "/namespaces"):
        fake.routes[("GET", route)] = lambda p: page([{"name": "main", "address": "00401000"}])


def paths(fake: FakeGhidra) -> list[str]:
    return [p for _, p, _ in fake.log]


# ------------------------------------------------------------------ detection


def test_health_selects_the_v2_dialect_and_describes_the_program() -> None:
    fake = fake_v2()

    async def scenario() -> None:
        b = backend(fake)
        assert b.dialect is None and b.supports(Capability.LIST_FUNCTIONS)  # before detection: a superset
        assert await b.detect() is Dialect.V2
        assert b.health is not None and b.health.version == "2.0.0" and b.health.program == "SelfCAD.exe"
        assert "GhidraMCP 2.0.0 on Ghidra 12.1.4 (gui); program: SelfCAD.exe" == b.describe()
        assert b.supports(Capability.LIST_FUNCTIONS) and not b.supports(Capability.CALLEES)
        await b.aclose()

    asyncio.run(scenario())


def test_a_server_without_health_stays_on_the_legacy_dialect() -> None:
    async def scenario() -> None:
        b = backend(FakeGhidra())  # /health is 404
        assert await b.detect() is Dialect.LEGACY and b.health is None
        assert b.supports(Capability.LIST_FUNCTIONS) and "1.x" in b.describe()
        await b.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("reply", [
    httpx.Response(200, text="<html>app</html>"),
    httpx.Response(200, json={"status": "ok"}),
    httpx.Response(200, json={"success": True, "data": {"nothing": 1}}),
    httpx.Response(200, json={"success": True, "data": {"version": 2}}),
    httpx.Response(500, text="boom"),
])
def test_a_health_reply_that_is_not_a_2x_envelope_is_not_v2(reply: httpx.Response) -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/health")] = lambda p: reply

    async def scenario() -> None:
        b = backend(fake)
        assert await b.detect() is Dialect.LEGACY
        await b.aclose()

    asyncio.run(scenario())


def test_an_unknown_major_version_is_refused_not_guessed() -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/health")] = lambda p: health(version="3.1.0")

    async def scenario() -> None:
        b = backend(fake)
        with pytest.raises(BackendError, match="speaks 1.x and 2.x only"):
            await b.execute(call(Capability.LIST_FUNCTIONS, PagedListArgs(capability="list_functions", limit=5)))
        assert b.dialect is None  # not cached: nothing was learned
        await b.aclose()

    asyncio.run(scenario())


def test_a_failed_health_round_trip_is_not_cached() -> None:
    state = {"up": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if not state["up"]:
            raise httpx.ConnectError("refused", request=request)
        return health()

    async def scenario() -> None:
        b = GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=httpx.MockTransport(handler)))
        with pytest.raises(BackendError, match="cannot reach"):
            await b.detect()
        assert b.dialect is None
        state["up"] = True
        assert await b.detect() is Dialect.V2
        await b.aclose()

    asyncio.run(scenario())


# ------------------------------------------------------------------ reads


def test_list_functions_uses_functions_not_methods_and_pages_with_the_extra_item() -> None:
    fake = fake_v2()
    data = [{"name": f"fn_{i}", "address": f"00401{i:03x}"} for i in range(5)]
    fake.routes[("GET", "/functions")] = lambda p: page(
        data[int(p["offset"]): int(p["offset"]) + int(p["limit"])], int(p["offset"]), 5)

    async def scenario() -> None:
        b = backend(fake)
        args = PagedListArgs(capability="list_functions", limit=2)
        first = await b.execute(call(Capability.LIST_FUNCTIONS, args))
        assert [i.label for i in first.items] == ["fn_0", "fn_1"] and first.next_offset == 2
        assert json.loads(first.items[0].text) == {"name": "fn_0", "address": "00401000"}
        last = await b.execute(call(Capability.LIST_FUNCTIONS, args, offset=4))
        assert [i.label for i in last.items] == ["fn_4"] and last.next_offset is None
        assert "/methods" not in paths(fake)
        assert json.loads(fake.log[0][2]) == {"limit": "3", "offset": "0"}
        await b.aclose()

    asyncio.run(scenario())


def test_imports_and_strings_are_snake_case_lowercase_routes() -> None:
    fake = fake_v2()
    fake.routes[("GET", "/imports")] = lambda p: page([{"name": "CreateFileA", "address": "00402000", "namespace": "KERNEL32.DLL"}])
    fake.routes[("GET", "/strings")] = lambda p: page([{"address": "00403000", "value": "hello", "type": "string", "length": 5}])

    async def scenario() -> None:
        b = backend(fake)
        imports = await b.execute(call(Capability.LIST_IMPORTS, PagedListArgs(capability="list_imports", limit=5)))
        strings = await b.execute(call(Capability.LIST_STRINGS, PagedListArgs(capability="list_strings", limit=5, filter="hel")))
        assert imports.items[0].label == "CreateFileA" and strings.items[0].label == "00403000"
        assert paths(fake) == ["/imports", "/strings"] and json.loads(fake.log[1][2])["filter"] == "hel"
        with pytest.raises(BackendError, match="cannot honor all arguments"):  # /imports has no filter
            await b.execute(call(Capability.LIST_IMPORTS, PagedListArgs(capability="list_imports", limit=5, filter="x")))
        await b.aclose()

    asyncio.run(scenario())


def test_decompile_by_name_and_address_returns_the_code_not_the_envelope() -> None:
    fake = fake_v2()
    code = "int main(void) {\n  return 0;\n}"
    fake.routes[("GET", "/decompile")] = lambda p: ok({"function": {"name": p["name"], "address": "00401000"}, "code": code, "truncated": False})
    fake.routes[("GET", "/decompile_function")] = lambda p: ok({"function": {"name": "main", "address": p["address"]}, "code": code, "truncated": True})

    async def scenario() -> None:
        b = backend(fake)
        named = await b.execute(call(Capability.DECOMPILE, DecompileArgs(capability="decompile", name="main")))
        assert named.items[0].text == code and named.items[0].label == "main"
        by_addr = await b.execute(call(Capability.DECOMPILE, DecompileArgs(capability="decompile", address=0x401000)))
        assert by_addr.items[0].text.startswith(code) and "truncated this decompilation" in by_addr.items[0].text
        assert fake.log[-1][1:] == ("/decompile_function", json.dumps({"address": "0x401000"}))
        await b.aclose()

    asyncio.run(scenario())


def test_disassembly_lines_are_readable_and_a_cut_off_page_says_so() -> None:
    fake = fake_v2()
    lines = [{"address": "00401000", "bytes": "55", "instruction": "PUSH RBP", "comment": "prologue"},
             {"address": "00401001", "bytes": "4889e5", "instruction": "MOV RBP,RSP", "comment": None}]
    fake.routes[("GET", "/disassemble_function")] = lambda p: page(lines, 0, 900, True)

    async def scenario() -> None:
        from rea_mcp.core.models import AddressArgs

        b = backend(fake)
        out = await b.execute(call(Capability.DISASM, AddressArgs(capability="disasm", address=0x401000)))
        assert out.items[0].text == "00401000  55  PUSH RBP  ; prologue" and out.items[1].text == "00401001  4889e5  MOV RBP,RSP"
        assert out.items[2].label == "truncated" and "2 of 900" in out.items[2].text and out.next_offset is None
        await b.aclose()

    asyncio.run(scenario())


def test_xrefs_page_and_function_info_object() -> None:
    fake = fake_v2()
    fake.routes[("GET", "/xrefs_to")] = lambda p: page([{"from": "00401050", "type": "UNCONDITIONAL_CALL", "from_function": {"name": "start", "address": "00401040"}}])
    fake.routes[("GET", "/function")] = lambda p: ok({"name": "main", "address": p["address"], "signature": "int main(void)", "is_thunk": False})

    async def scenario() -> None:
        from rea_mcp.core.models import AddressArgs

        b = backend(fake)
        xrefs = await b.execute(call(Capability.XREFS_TO, AddressArgs(capability="xrefs_to", address=0x401000)))
        assert json.loads(xrefs.items[0].text)["from_function"]["name"] == "start"
        info = await b.execute(call(Capability.FUNCTION_INFO, AddressArgs(capability="function_info", address=0x401000)))
        assert json.loads(info.items[0].text)["signature"] == "int main(void)"
        await b.aclose()

    asyncio.run(scenario())


def test_search_functions_maps_the_pattern_to_the_functions_filter() -> None:
    fake = fake_v2()
    fake.routes[("GET", "/functions")] = lambda p: page([{"name": "crypt_init", "address": "00401100"}])

    async def scenario() -> None:
        from rea_mcp.core.models import SearchArgs

        b = backend(fake)
        out = await b.execute(call(Capability.SEARCH_FUNCTIONS, SearchArgs(capability="search_functions", pattern="crypt", limit=5)))
        assert out.items[0].label == "crypt_init" and json.loads(fake.log[-1][2])["filter"] == "crypt"
        await b.aclose()

    asyncio.run(scenario())


# ------------------------------------------------------------------ errors are errors


def test_error_envelopes_become_backend_errors_with_their_code() -> None:
    fake = fake_v2()
    fake.routes[("GET", "/decompile_function")] = lambda p: fail("FUNCTION_NOT_FOUND", "No function at 0x1")
    fake.routes[("GET", "/segments")] = lambda p: fail("NO_PROGRAM", "No program is open", 409)
    fake.routes[("GET", "/data")] = lambda p: fail("INTERNAL_ERROR", "boom", 500)

    async def scenario() -> None:
        b = backend(fake)
        with pytest.raises(BackendError, match="FUNCTION_NOT_FOUND: No function at 0x1"):
            await b.execute(call(Capability.DECOMPILE, DecompileArgs(capability="decompile", address=1)))
        with pytest.raises(BackendError, match="NO_PROGRAM"):
            await b.execute(call(Capability.LIST_SEGMENTS, PagedListArgs(capability="list_segments", limit=5)))
        with pytest.raises(BackendError, match="INTERNAL_ERROR"):
            await b.execute(call(Capability.LIST_GLOBALS, PagedListArgs(capability="list_globals", limit=5)))
        with pytest.raises(BackendError, match="route not found"):  # nothing registered: UNKNOWN_ENDPOINT
            fake.routes[("GET", "/exports")] = lambda p: fail("UNKNOWN_ENDPOINT", "Unknown endpoint: /exports")
            await b.execute(call(Capability.LIST_EXPORTS, PagedListArgs(capability="list_exports", limit=5)))
        await b.aclose()

    asyncio.run(scenario())


def test_a_non_envelope_reply_after_a_2x_health_is_a_fault_not_an_answer() -> None:
    fake = fake_v2()
    fake.routes[("GET", "/functions")] = lambda p: httpx.Response(200, text="fn_a\nfn_b")  # 1.x style text
    fake.routes[("GET", "/segments")] = lambda p: httpx.Response(200, json=[{"name": "x"}])

    async def scenario() -> None:
        b = backend(fake)
        with pytest.raises(BackendError, match="not a JSON envelope"):
            await b.execute(call(Capability.LIST_FUNCTIONS, PagedListArgs(capability="list_functions", limit=5)))
        with pytest.raises(BackendError, match="not a JSON envelope"):
            await b.execute(call(Capability.LIST_SEGMENTS, PagedListArgs(capability="list_segments", limit=5)))
        await b.aclose()

    asyncio.run(scenario())


# ------------------------------------------------------------------ mutators


def test_rename_symbol_tries_the_function_then_the_data_label_and_bumps_the_generation() -> None:
    fake = fake_v2()
    fake.routes[("POST", "/rename_function_by_address")] = lambda p: fail("FUNCTION_NOT_FOUND", "no function there")
    fake.routes[("POST", "/rename_data")] = lambda p: ok({"address": p["address"], "old_name": "DAT_1", "new_name": p["new_name"]})

    async def scenario() -> None:
        b = backend(fake)
        out = await b.execute(call(Capability.RENAME_SYMBOL, RenameSymbolArgs(capability="rename_symbol", address=0x403000, new_name="key_table")))
        assert json.loads(out.items[0].text)["new_name"] == "key_table"
        assert [(m, p) for m, p, _ in fake.log] == [("POST", "/rename_function_by_address"), ("POST", "/rename_data")]
        assert json.loads(fake.log[0][2]) == {"function_address": "0x403000", "new_name": "key_table"}
        assert out.generation > 1
        # a failure of the last route is raised, and nothing is counted as changed
        fake.routes[("POST", "/rename_data")] = lambda p: fail("DATA_NOT_FOUND", "no data there")
        with pytest.raises(BackendError, match="DATA_NOT_FOUND"):
            await b.execute(call(Capability.RENAME_SYMBOL, RenameSymbolArgs(capability="rename_symbol", address=0x9, new_name="zz")))
        await b.aclose()

    asyncio.run(scenario())


def test_rename_variable_is_address_based_with_no_name_lookup() -> None:
    fake = fake_v2()
    fake.routes[("POST", "/rename_variable")] = lambda p: ok({"address": "00401000", "old_name": p["old_name"], "new_name": p["new_name"]})

    async def scenario() -> None:
        b = backend(fake)
        rv = RenameVariableArgs(capability="rename_variable", function_address=0x401000, old_name="local_8", new_name="key")
        out = await b.execute(call(Capability.RENAME_VARIABLE, rv))
        assert out.generation > 1 and paths(fake) == ["/rename_variable"]  # no /function or /decompile lookup first
        assert json.loads(fake.log[0][2]) == {"function_address": "0x401000", "new_name": "key", "old_name": "local_8"}
        await b.aclose()

    asyncio.run(scenario())


def test_comments_prototypes_and_variable_types_use_the_2x_snake_case_params() -> None:
    fake = fake_v2()
    for route in ("/set_decompiler_comment", "/set_disassembly_comment", "/set_function_prototype", "/set_local_variable_type"):
        fake.routes[("POST", route)] = lambda p: ok({"address": "00401000", "comment_type": "EOL", "comment": "x"})

    async def scenario() -> None:
        b = backend(fake)
        await b.execute(call(Capability.SET_COMMENT, SetCommentArgs(capability="set_comment", address=0x401000, comment="c", kind="decompiler")))
        await b.execute(call(Capability.SET_COMMENT, SetCommentArgs(capability="set_comment", address=0x401000, comment="c", kind="disasm")))
        await b.execute(call(Capability.SET_FUNCTION_PROTOTYPE, SetTypeArgs(capability="set_function_prototype", address=0x401000, declaration="int f(int a)")))
        await b.execute(call(Capability.SET_VARIABLE_TYPE, SetTypeArgs(capability="set_variable_type", address=0x401000, declaration="int", variable_name="v")))
        sent = {p: json.loads(q) for _, p, q in fake.log}
        assert sent["/set_decompiler_comment"] == {"address": "0x401000", "comment": "c"}
        assert sent["/set_function_prototype"] == {"function_address": "0x401000", "prototype": "int f(int a)"}
        assert sent["/set_local_variable_type"] == {"function_address": "0x401000", "new_type": "int", "variable_name": "v"}
        await b.aclose()

    asyncio.run(scenario())


# ------------------------------------------------------------------ doctor


ENV = {"REA_GHIDRA_URL": "http://127.0.0.1:8080"}


def test_doctor_reports_a_live_2x_bridge_and_probes_functions_not_methods(tmp_path: Path) -> None:
    fake = fake_v2()
    listing(fake)
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=lambda url: backend(fake))
    code, out = run_doctor(tmp_path, env=ENV, fx=fxs)
    assert code == 0, out
    assert "live; GhidraMCP 2.0.0" in out and "7/7 read-only listing routes answered" in out
    assert "GhidraMCP 2.0.0 on Ghidra 12.1.4 (gui); program: SelfCAD.exe" in out
    live = out.split("PROBED_LIVE (called read-only, answered):")[1].split("STATIC_ROUTE_TABLE")[0]
    assert "list_functions" in live
    assert "/methods" not in paths(fake) and {m for m, _, _ in fake.log} == {"GET"}  # nothing mutating is fired


def test_doctor_does_not_call_a_2x_plugin_with_no_open_program_healthy(tmp_path: Path) -> None:
    fake = fake_v2(program=None)
    for route in ("/functions", "/segments", "/imports", "/exports", "/strings", "/data", "/namespaces"):
        fake.routes[("GET", route)] = lambda p: fail("NO_PROGRAM", "No program is open", 409)
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=lambda url: backend(fake))
    code, out = run_doctor(tmp_path, env=ENV, fx=fxs)
    assert code == 1, out
    assert "no program is open in a CodeBrowser" in out
    assert "live; GhidraMCP" not in out and "PROBED_LIVE" not in out and "no configured backend is live and usable" in out


def test_doctor_does_not_trust_text_replies_from_a_server_that_claims_2x(tmp_path: Path) -> None:
    fake = fake_v2()
    for route in ("/functions", "/segments", "/imports", "/exports", "/strings", "/data", "/namespaces"):
        fake.routes[("GET", route)] = lambda p: httpx.Response(200, text="fn_a\nfn_b")
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=lambda url: backend(fake))
    code, out = run_doctor(tmp_path, env=ENV, fx=fxs)
    assert code == 1 and "PROBED_LIVE" not in out and "live; GhidraMCP" not in out


def test_doctor_names_an_unsupported_2x_version(tmp_path: Path) -> None:
    fake = FakeGhidra()
    fake.routes[("GET", "/health")] = lambda p: health(version="3.0.0")
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=lambda url: backend(fake))
    code, out = run_doctor(tmp_path, env=ENV, fx=fxs)
    assert code == 1 and "speaks 1.x and 2.x only" in out and "live; GhidraMCP" not in out


def test_doctor_marks_functions_unsupported_nowhere_on_2x_and_callees_unsupported(tmp_path: Path) -> None:
    fake = fake_v2()
    listing(fake)
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=lambda url: backend(fake))
    _, out = run_doctor(tmp_path, env=ENV, fx=fxs)
    assert "list_functions  <- " not in out
    assert "callees" in out.split("unsupported:")[1] and "no route in the GhidraMCP 2.0 table" in out
