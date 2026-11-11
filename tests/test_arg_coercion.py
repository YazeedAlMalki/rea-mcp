"""Clients (notably Claude Desktop) sometimes send ``args`` as a JSON string and ``control`` as null.
The server repairs that syntax only; validation, tiers and limits are unchanged."""

from __future__ import annotations

import json
from pathlib import Path

import mcp_types as types
import pytest
from mcp.client.client import Client
from test_phase4 import C_SOURCE, env_for, run, write

from rea_mcp.core.models import ErrorCategory, ToolResponse
from rea_mcp.server import MAX_REQUEST_CHARS, build_app, coerce_arguments

READ = {"capability": "source_read", "target": {"kind": "file", "path": ""}, "symbol": "parse"}


async def raw_call(client: Client, tool: str, arguments: dict[str, object]) -> ToolResponse:
    result = await client.call_tool(tool, arguments)
    assert result.content and isinstance(result.content[0], types.TextContent)
    return ToolResponse.model_validate_json(result.content[0].text)


def read_args(path: Path) -> dict[str, object]:
    return {**READ, "target": {"kind": "file", "path": str(path)}}


def test_args_sent_as_a_json_string_are_repaired(tmp_path: Path) -> None:
    path = write(tmp_path / "a.c", C_SOURCE)
    app = build_app(env_for(tmp_path))

    async def body(client: Client) -> None:
        as_object = await raw_call(client, "rea_query", {"args": read_args(path)})
        as_string = await raw_call(client, "rea_query", {"args": json.dumps(read_args(path))})
        assert as_object.status == "ok" and as_string.status == "ok"
        assert as_string.fragments[0].hash == as_object.fragments[0].hash

    run(app, body)


def test_control_as_null_or_a_json_string_is_repaired(tmp_path: Path) -> None:
    path = write(tmp_path / "a.c", C_SOURCE)
    app = build_app(env_for(tmp_path))

    async def body(client: Client) -> None:
        for control in (None, "{}", '{"token_budget": 4000}'):
            out = await raw_call(client, "rea_query", {"args": json.dumps(read_args(path)), "control": control})
            assert out.status == "ok", control

    run(app, body)


def test_repair_does_not_weaken_validation_or_tiers(tmp_path: Path) -> None:
    app = build_app(env_for(tmp_path))

    async def body(client: Client) -> None:
        # a privileged capability inside a stringified args is still refused by the query tool
        patch = json.dumps({"capability": "patch_bytes", "address": 1, "data": "90"})
        out = await raw_call(client, "rea_query", {"args": patch})
        assert out.error is not None and out.error.category is ErrorCategory.INVALID_REQUEST
        # strings that are not JSON objects stay errors and are never echoed back
        for junk in ("not json hunter2", "[1, 2]", "42", '"hunter2"', "{"):
            res = await raw_call(client, "rea_query", {"args": junk})
            assert res.error is not None and res.error.category is ErrorCategory.INVALID_REQUEST
            assert "hunter2" not in res.error.message
        # unknown capabilities and extra top-level fields are still rejected
        unknown = await raw_call(client, "rea_query", {"args": '{"capability": "nope"}'})
        assert unknown.error is not None and unknown.error.category is ErrorCategory.INVALID_REQUEST
        extra = await client.call_tool("rea_query", {"args": '{"capability": "list_databases"}', "surprise": 1})
        assert extra.is_error
        # rea_capabilities still takes no arguments, repaired or not
        assert (await client.call_tool("rea_capabilities", {"args": "{}"})).is_error

    run(app, body)


def test_coerce_arguments_is_syntax_only() -> None:
    assert coerce_arguments({"args": '{"a": 1}', "database": "d"}) == {"args": {"a": 1}, "database": "d"}
    assert coerce_arguments({"args": {"a": 1}, "control": None}) == {"args": {"a": 1}}
    assert coerce_arguments({"args": "[1]"}) == {"args": "[1]"}  # not an object: untouched
    assert coerce_arguments({"args": "x" * 10, "database": '{"a":1}'})["database"] == '{"a":1}'  # only args/control
    assert coerce_arguments({"args": "[" * 100_000}) == {"args": "[" * 100_000}  # a nesting bomb is not parsed into a crash
    oversize = "{" + '"a":1,' * MAX_REQUEST_CHARS + "}"
    assert coerce_arguments({"args": oversize}) == {"args": oversize}
    original = {"args": '{"a": 1}'}
    coerce_arguments(original)
    assert original == {"args": '{"a": 1}'}  # the caller's mapping is not mutated


def test_the_advertised_example_matches_what_the_server_accepts(tmp_path: Path) -> None:
    from rea_mcp.server import tool_definitions

    query = next(t for t in tool_definitions() if t.name == "rea_query")
    assert query.description is not None and '{"args": {"capability": "list_functions", "limit": 20}}' in query.description
    app = build_app(env_for(tmp_path))

    async def body(client: Client) -> None:
        out = await raw_call(client, "rea_query", {"args": {"capability": "list_functions", "limit": 20}})
        assert out.error is None or out.error.category is not ErrorCategory.INVALID_REQUEST  # valid shape (no backend: other error)

    run(app, body)


@pytest.mark.parametrize("value", [1, True, [], 3.5])
def test_non_string_non_object_values_are_left_for_validation(value: object) -> None:
    assert coerce_arguments({"args": value}) == {"args": value}
