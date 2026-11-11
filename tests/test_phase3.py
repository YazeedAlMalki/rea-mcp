"""Phase 3: leantoken index, hotspot scanner, SARIF importer, evidence ledger, router integration."""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
from collections.abc import Mapping
from pathlib import Path
from typing import get_args

import pytest
from blake3 import blake3
from pydantic import JsonValue, TypeAdapter, ValidationError

from rea_mcp.core.models import (
    BackendItem,
    BackendKind,
    BackendResult,
    Capability,
    ErrorCategory,
    ImportSarifArgs,
    MutateRequest,
    QueryRequest,
    RangeEvidence,
    ScanHotspotsArgs,
    SecurityTier,
    SourceReadArgs,
    ToolResponse,
    content_hash,
)
from rea_mcp.core.router import BackendCall, CapabilityRouter, ToolName
from rea_mcp.core.security import (
    AUTO_GRANT_ENV,
    LEDGER_DIR_ENV,
    ROOTS_ENV,
    AuditLog,
    Authorizer,
    DenyAllConsent,
    RedactionPipeline,
    SecurityPolicy,
    tier_of,
)
from rea_mcp.evidence.engine import EvidenceEngine
from rea_mcp.evidence.ledger import (
    EpisodeLedger,
    FragmentProof,
    Journal,
    LedgerRejected,
    Requirement,
)
from rea_mcp.evidence.leantoken_index import (
    SourceSkipped,
    index_source,
    index_text,
    mask_c_like,
    read_capped,
)
from rea_mcp.evidence.scanner import (
    SarifRejected,
    list_tree,
    parse_sarif,
    scan_bytes,
    scan_listing,
    shannon_entropy,
)

JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
SESSION = "sess-0003"

C_SOURCE = """\
#include <string.h>
#define LIMIT 64
struct header { int magic; int len; };
enum mode { FAST, SLOW };
int counter = 0;
/* int ghost(void) { return 1; } */
static int helper(int x) { return x * 2; }
int parse(char *in, int n) {
    char buf[16];
    strcpy(buf, in);
    return helper(n);
}
"""


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


class Decompiler:
    """Stands in for an IDA/Ghidra backend; only the router talks to it."""

    kind = BackendKind.IDA_PRO

    def __init__(self) -> None:
        self.generation = 1
        self.pseudocode = "int sub_401000(int a) {\n  return a + 1;\n}\n"
        self.calls: list[Capability] = []

    def supports(self, capability: Capability) -> bool:
        return capability in (Capability.DECOMPILE, Capability.RENAME_SYMBOL)

    async def execute(self, call: BackendCall) -> BackendResult:
        self.calls.append(call.capability)
        return BackendResult(items=(BackendItem(label="f", text=self.pseudocode),), generation=self.generation)


class Rig:
    def __init__(self, root: Path, *, grant: bool = True, ledger_dir: Path | None = None) -> None:
        env = {ROOTS_ENV: str(root)}
        if grant:
            env[AUTO_GRANT_ENV] = "1"
        if ledger_dir is not None:
            env[LEDGER_DIR_ENV] = str(ledger_dir)
        self.root = root.resolve()
        self.policy = SecurityPolicy.from_environ(env)
        self.engine = EvidenceEngine(self.policy)
        self.ida = Decompiler()
        self.router = CapabilityRouter(
            backends=[self.engine, self.ida],
            authorizer=Authorizer(self.policy, AuditLog(None), DenyAllConsent()),
            redaction=RedactionPipeline.from_policy(self.policy, {}),
            cursor_key=b"k" * 32,
        )

    async def send(
        self, tool: ToolName, args: Mapping[str, object], control: Mapping[str, object] | None = None,
        *, session: str = SESSION,
    ) -> ToolResponse:
        body = json.dumps({"args": args, "control": control or {}})
        out = await self.router.call(tool, session, body)
        assert isinstance(out, ToolResponse)
        return out

    async def q(self, args: Mapping[str, object], **control: object) -> ToolResponse:
        return await self.send("rea_query", args, control)

    async def m(self, args: Mapping[str, object], **control: object) -> ToolResponse:
        return await self.send("rea_mutate", args, control)


def text_of(response: ToolResponse) -> str:
    return "\n".join(f.text for f in response.fragments)


def err(response: ToolResponse) -> ErrorCategory:
    assert response.error is not None, response
    return response.error.category


def write(root: Path, name: str, body: str | bytes) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body.encode() if isinstance(body, str) else body)
    return path


def first_hash(response: ToolResponse) -> str:
    assert response.status == "ok" and response.fragments, response
    return response.fragments[0].hash


def target_file(path: Path) -> dict[str, object]:
    return {"kind": "file", "path": str(path)}


def fact_args(claim: str, *refs: Mapping[str, object], episode: str = "main") -> dict[str, object]:
    return {"capability": "ledger_record_fact", "episode": episode, "claim": claim, "evidence": list(refs)}


def frag(digest: str) -> dict[str, object]:
    return {"kind": "fragment", "hash": digest}


async def read_symbol(rig: Rig, path: Path, symbol: str = "parse") -> ToolResponse:
    return await rig.q({"capability": "source_read", "target": target_file(path), "symbol": symbol})


# --------------------------------------------------------------------------- #
# Facade and models
# --------------------------------------------------------------------------- #


def test_no_new_top_level_tools_and_evidence_capabilities_are_tiered(tmp_path: Path) -> None:
    assert set(get_args(ToolName)) == {"rea_query", "rea_mutate", "rea_privileged", "rea_capabilities"}
    reads = {"source_outline", "source_read", "scan_hotspots", "ledger_list", "ledger_get", "ledger_summary"}
    writes = {
        "ledger_record_fact", "ledger_record_hypothesis", "ledger_promote", "ledger_refute",
        "ledger_declare_gap", "ledger_close_gap", "import_sarif",
    }
    for name in reads:
        assert tier_of(Capability(name)) is SecurityTier.READ_ONLY
    for name in writes:
        assert tier_of(Capability(name)) is SecurityTier.MUTATE_SAFE
    listing = Rig(tmp_path).router.capabilities()
    by_name = {e.capability.value: e for e in listing.entries}
    assert all(by_name[n].tier is SecurityTier.READ_ONLY for n in reads)
    assert all(by_name[n].tier is SecurityTier.MUTATE_SAFE for n in writes)


def test_evidence_argument_models_are_strict() -> None:
    with pytest.raises(ValidationError):  # exactly one selector
        SourceReadArgs.model_validate_json('{"capability":"source_read","target":{"kind":"file","path":"/a.c"}}')
    with pytest.raises(ValidationError):  # at most 400 lines
        SourceReadArgs.model_validate_json(
            '{"capability":"source_read","target":{"kind":"file","path":"/a.c"},"start_line":1,"end_line":401}'
        )
    with pytest.raises(ValidationError):  # rejected, never clamped
        ScanHotspotsArgs.model_validate_json(
            '{"capability":"scan_hotspots","target":{"kind":"tree","path":"/a"},"max_files":501}'
        )
    with pytest.raises(ValidationError):
        ImportSarifArgs.model_validate_json('{"capability":"import_sarif","path":"/a.sarif","max_results":5001}')
    with pytest.raises(ValidationError):
        RangeEvidence.model_validate_json('{"kind":"range","start":"0x2000","end":"0x1000"}')
    with pytest.raises(ValidationError):  # a fact must cite something
        MutateRequest.model_validate_json('{"args":{"capability":"ledger_record_fact","claim":"abc","evidence":[]}}')
    with pytest.raises(ValidationError):  # tier mismatch is a schema error, not a runtime surprise
        QueryRequest.model_validate_json('{"args":{"capability":"ledger_record_fact","claim":"abc","evidence":[]}}')


# --------------------------------------------------------------------------- #
# leantoken index
# --------------------------------------------------------------------------- #


def test_c_outline_ranges_ignore_comments_and_slice_back_to_the_symbol() -> None:
    src = index_source("a.c", C_SOURCE.encode(), "c_like")
    found = {s.name: s for s in src.symbols}
    assert {"LIMIT", "header", "mode", "counter", "helper", "parse"} <= set(found)
    assert "ghost" not in found  # inside a comment
    assert found["header"].kind == "struct" and found["mode"].kind == "enum"
    assert found["counter"].kind == "global" and found["LIMIT"].kind == "macro"
    parse = found["parse"]
    body = src.data[parse.start_byte : parse.end_byte].decode()
    assert body.startswith("int parse(") and body.endswith("}")
    assert src.slice_lines(parse.start_line, parse.end_line) == body
    assert src.content_hash == blake3(C_SOURCE.encode()).hexdigest()
    assert len(mask_c_like(C_SOURCE.encode())) == len(C_SOURCE.encode())


def test_python_outline_and_pseudocode_outline() -> None:
    py = index_source("m.py", b"X = 1\nclass A:\n    def m(self):\n        pass\ndef f():\n    pass\n", "python")
    assert [(s.name, s.kind) for s in py.symbols] == [("X", "global"), ("A", "class"), ("A.m", "method"), ("f", "function")]
    pseudo = index_text("decompile@0x401000", "int sub_401000(int a) {\n  return a + 1;\n}\n")
    assert [(s.name, s.start_line, s.end_line) for s in pseudo.symbols] == [("sub_401000", 1, 3)]


def test_index_rejects_malformed_utf8_nul_and_oversize_instead_of_replacing(tmp_path: Path) -> None:
    with pytest.raises(SourceSkipped) as bad:
        index_source("x.c", b"int a;\n\xff\n", "c_like")
    assert bad.value.reason == "malformed_utf8"
    with pytest.raises(SourceSkipped) as nul:
        index_source("x.c", b"int a;\x00", "c_like")
    assert nul.value.reason == "binary"
    with pytest.raises(SourceSkipped) as big:
        index_source("x.c", b"a" * (2 * 1024 * 1024 + 1), "c_like")
    assert big.value.reason == "too_large"
    real = write(tmp_path, "real.c", "int a;\n")
    link = tmp_path / "link.c"
    link.symlink_to(real)
    with pytest.raises(SourceSkipped):  # O_NOFOLLOW on the final component
        read_capped(link)
    assert read_capped(real) == b"int a;\n"


def test_outline_read_hash_not_modified_and_known_dedup(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        outline = await rig.q({"capability": "source_outline", "target": target_file(path)})
        assert outline.status == "ok"
        body = text_of(outline)
        assert "symbols=" in body and "parse L8-12" in body and "f=function" in body
        assert outline.meta is not None and outline.meta.tokens_used < 200  # a skeleton, not the file

        first = await read_symbol(rig, path)
        assert first.status == "ok"
        assert text_of(first) == "int parse(char *in, int n) {\n    char buf[16];\n    strcpy(buf, in);\n    return helper(n);\n}"
        assert first.fragments[0].hash == content_hash(text_of(first))
        assert first.fragments[0].label.startswith("parse:L8-12@")

        again = await rig.q(
            {"capability": "source_read", "target": target_file(path), "symbol": "parse"},
            known_hashes=[first.fragments[0].hash],
        )
        assert again.status == "ok" and not again.fragments and again.known[0].tokens_saved > 0
        unchanged = await rig.q(
            {"capability": "source_read", "target": target_file(path), "symbol": "parse"},
            expected_hash=first.fragments[0].hash,
        )
        assert unchanged.status == "not_modified"

    asyncio.run(scenario())


def test_source_read_limits_and_errors(tmp_path: Path) -> None:
    big = "\n".join(f"int v{i};" for i in range(450)) + "\nint huge(void) {\n" + "\n".join("  x();" for _ in range(420)) + "\n}\n"
    path = write(tmp_path, "big.c", big)
    dup = write(tmp_path, "dup.c", "int f(void) { return 1; }\nint f(int a) { return a; }\n")

    async def scenario() -> None:
        rig = Rig(tmp_path)
        too_wide = await read_symbol(rig, path, "huge")
        assert err(too_wide) is ErrorCategory.INVALID_REQUEST and "narrower" in (too_wide.error.message if too_wide.error else "")
        assert err(await read_symbol(rig, path, "nope")) is ErrorCategory.NOT_FOUND
        assert err(await read_symbol(rig, dup, "f")) is ErrorCategory.INVALID_REQUEST  # ambiguous
        past = await rig.q({"capability": "source_read", "target": target_file(dup), "start_line": 50, "end_line": 51})
        assert err(past) is ErrorCategory.INVALID_REQUEST
        ranged = await rig.q({"capability": "source_read", "target": target_file(path), "start_line": 2, "end_line": 3})
        assert text_of(ranged) == "int v1;\nint v2;" and ranged.fragments[0].label.startswith("big.c:L2-3@")

    asyncio.run(scenario())


def test_paths_must_resolve_under_allowed_roots_including_through_symlinks(tmp_path: Path) -> None:
    inside = tmp_path / "root"
    inside.mkdir()
    outside = write(tmp_path, "outside/secret.c", "int s;\n")
    (inside / "escape.c").symlink_to(outside)

    async def scenario() -> None:
        rig = Rig(inside)
        for target in (outside, inside / "escape.c"):
            assert err(await rig.q({"capability": "source_outline", "target": target_file(target)})) is ErrorCategory.DENIED_PATH
        scan = await rig.q({"capability": "scan_hotspots", "target": {"kind": "tree", "path": str(tmp_path / "outside")}})
        assert err(scan) is ErrorCategory.DENIED_PATH
        relative = await rig.q({"capability": "source_outline", "target": {"kind": "file", "path": "a.c"}})
        assert err(relative) is ErrorCategory.DENIED_PATH
        wrong_type = write(inside, "notes.txt", "hello")
        assert err(await rig.q({"capability": "source_outline", "target": target_file(wrong_type)})) is ErrorCategory.INVALID_REQUEST

    asyncio.run(scenario())


def test_outline_paging_and_generation_binding(tmp_path: Path) -> None:
    path = write(tmp_path, "many.c", "".join(f"int fn_{i}(void) {{ return {i}; }}\n" for i in range(60)))

    async def scenario() -> None:
        rig = Rig(tmp_path)
        args = {"capability": "source_outline", "target": target_file(path), "limit": 1}
        pages = [await rig.q(args)]
        assert pages[0].meta is not None and pages[0].meta.next_cursor is not None
        seen = text_of(pages[0]).count("fn_")
        while pages[-1].meta is not None and pages[-1].meta.next_cursor is not None:
            pages.append(await rig.q({**args, "cursor": pages[-1].meta.next_cursor}))
            seen += text_of(pages[-1]).count("fn_")
        assert len(pages) == 3 and seen == 60  # 25 symbols per item
        # the file changes underneath a live cursor: fail closed instead of mixing versions
        first = await rig.q(args)
        cursor = first.meta.next_cursor if first.meta else None
        assert cursor is not None
        write(tmp_path, "many.c", "".join(f"int fn_{i}(void) {{ return {i}; }}\n" for i in range(61)))
        assert err(await rig.q({**args, "cursor": cursor})) is ErrorCategory.STALE_CURSOR

    asyncio.run(scenario())


def test_decompile_target_is_fetched_by_the_router_not_the_engine(tmp_path: Path) -> None:
    async def scenario() -> None:
        rig = Rig(tmp_path)
        target = {"kind": "decompile", "address": "0x401000"}
        outline = await rig.q({"capability": "source_outline", "target": target})
        assert "sub_401000" in text_of(outline) and "decompile@0x401000" in text_of(outline)
        read = await rig.q({"capability": "source_read", "target": target, "symbol": "sub_401000"})
        assert "return a + 1;" in text_of(read)
        assert rig.ida.calls == [Capability.DECOMPILE, Capability.DECOMPILE]
        rig.ida.pseudocode = "int sub_401000(int a) {\n  return strcpy(a, a);\n}\n"
        scan = await rig.q({"capability": "scan_hotspots", "target": target})
        assert "unsafe.strcpy" in text_of(scan)

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


def rules(data: str, suffix: str = ".c") -> dict[str, str]:
    return {h.rule: h.severity for h in scan_bytes(f"t{suffix}", suffix, data.encode()).hotspots}


def test_unsafe_primitives_ignore_comments_and_strings_and_grade_memcpy() -> None:
    found = rules(
        '#include <x.h>\n'
        'void f(char *a, int n) {\n'
        '  strcpy(a, "x"); sprintf(a, "%d", n); gets(a);\n'
        '  memcpy(a, a, n); memcpy(a, a, 16);\n'
        '  printf(a); printf("ok %d", n);\n'
        '  system(a);\n'
        '  // strcpy(a, a);\n'
        '  const char *s = "strcpy(a, b) system(c)";\n'
        '}\n'
    )
    assert found["unsafe.strcpy"] == "high" and found["unsafe.sprintf"] == "high" and found["unsafe.gets"] == "high"
    assert found["unsafe.memcpy"] == "medium"  # the computed-size call wins the line-level dedupe key
    assert found["format.non_literal"] == "medium" and found["sink.exec.system"] == "high"
    all_hits = scan_bytes("t.c", ".c", b'void f(char *a){ // strcpy(a,a)\n const char *s = "system(x)"; }\n').hotspots
    assert all_hits == ()  # comments and string literals are masked


def test_complexity_bitwise_crypto_and_entropy_signals() -> None:
    branches = "".join(f"  if (x == {i} && y) {{ z += {i}; }}\n" for i in range(14))
    assert rules(f"int f(int x, int y) {{\n  int z = 0;\n{branches}  return z;\n}}\n")["complexity.cyclomatic"] in {"medium", "high"}
    mix = "".join(f"  h ^= (h << {i % 7 + 1}) | (h >> {i % 5 + 1}); h &= ~{i};\n" for i in range(20))
    assert "bitwise.dense" in rules(f"unsigned f(unsigned h) {{\n{mix}  return h;\n}}\n")
    assert "crypto.constant" in rules("unsigned iv[2] = { 0x6a09e667, 0xbb67ae85 };\n")
    table = "".join("  " + ", ".join(f"0x{(i * 16 + j) & 0xFF:02x}" for j in range(8)) + ",\n" for i in range(6))
    assert "const.dense_table" in rules(f"unsigned char t[] = {{\n{table}}};\n")
    blob = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0g="
    assert rules(f'const char *k = "{blob}";\n')["entropy.high_entropy_string"] in {"low", "medium"}
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert shannon_entropy(b"") == 0.0


def test_python_signals() -> None:
    found = rules(
        "import os, subprocess, pickle\n"
        "def f(x):\n    os.system(x)\n    eval(x)\n    subprocess.run(x, shell=True)\n    pickle.loads(x)\n",
        ".py",
    )
    assert found["sink.exec.os.system"] == "high" and found["sink.exec.eval"] == "high"
    assert found["sink.exec.subprocess.run"] == "high" and found["unsafe.pickle.loads"] == "medium"


def test_js_safe_integer_violations_but_not_bigint_or_plain_c() -> None:
    assert "js.unsafe_integer" in rules("const a = 9007199254740993;\n", ".js")
    assert "js.unsafe_integer" in rules("const a = 0x20000000000001;\n", ".ts")
    assert "js.unsafe_integer" in rules('{"id": 12345678901234567890}\n', ".json")
    assert "js.unsafe_integer" not in rules("const a = 9007199254740993n; const b = 9007199254740991;\n", ".js")
    assert "js.unsafe_integer" not in rules("unsigned long long a = 18446744073709551615ULL;\n", ".c")


def test_malformed_utf8_binary_symlink_and_max_files_keep_coverage_visible(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    write(tree, "ok.c", "void f(char *a){ strcpy(a, a); }\n")
    write(tree, "bad.c", b"int a;\n\xff\xfe\n")
    write(tree, "bin.c", b"\x00\x01\x02" * 50)
    write(tree, "notes.txt", "ignored")
    write(tree, "node_modules/skip.c", "int x;\n")
    (tree / "link.c").symlink_to(tree / "ok.c")
    report = scan_listing("tree", list_tree(tree, 50), "info")
    assert not report.complete
    reasons = {s.path: s.reason for s in report.skipped}
    assert reasons == {"bad.c": "malformed_utf8", "bin.c": "binary"}
    assert any("entropy" in s.detail for s in report.skipped if s.path == "bin.c")
    assert report.symlinks == 1 and report.unsupported == 1 and report.files_scanned == 1
    assert {h.rule for h in report.hotspots} >= {"unsafe.strcpy", "encoding.malformed_utf8"}
    limited = scan_listing("tree", list_tree(tree, 1), "info")
    assert limited.not_examined == 2 and not limited.complete
    clean = tmp_path / "clean"
    write(clean, "a.c", "int a;\n")
    assert scan_listing("clean", list_tree(clean, 5), "info").complete


def test_scan_through_the_router_reports_coverage_first_and_is_not_citable(tmp_path: Path) -> None:
    tree = tmp_path / "t"
    write(tree, "ok.c", "void f(char *a){ strcpy(a, a); }\n")
    write(tree, "bad.c", b"\xff\n")

    async def scenario() -> None:
        rig = Rig(tmp_path)
        scan = await rig.q({"capability": "scan_hotspots", "target": {"kind": "tree", "path": str(tree)}, "min_severity": "medium"})
        assert scan.status == "ok" and scan.fragments[0].label == "scan:coverage"
        body = text_of(scan)
        assert "INCOMPLETE" in body and "bad.c: malformed_utf8" in body and "unsafe.strcpy" in body
        assert "review candidates" in body
        # candidates are not evidence: the server refuses to treat them as a fragment it can cite
        rejected = await rig.m(fact_args("strcpy overflows in f", frag(scan.fragments[1].hash)))
        assert err(rejected) is ErrorCategory.EVIDENCE_REJECTED
        # ... until the analyst reads the source and cites that
        read = await rig.q({"capability": "source_read", "target": target_file(tree / "ok.c"), "start_line": 1, "end_line": 1})
        accepted = await rig.m(fact_args("f calls strcpy on its own argument", frag(first_hash(read))))
        assert accepted.status == "ok"

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Ledger: facts, hypotheses, gaps
# --------------------------------------------------------------------------- #


def test_fabricated_and_foreign_evidence_is_rejected_and_range_alone_is_not_proof(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        read = await read_symbol(rig, path)
        digest = first_hash(read)
        invented = "ab" * 32
        assert err(await rig.m(fact_args("parse is vulnerable", frag(invented)))) is ErrorCategory.EVIDENCE_REJECTED
        locator = {"kind": "range", "start": "0x401000", "end": "0x401040", "symbol": "parse"}
        assert err(await rig.m(fact_args("parse is vulnerable", locator))) is ErrorCategory.EVIDENCE_REJECTED
        ok = await rig.m(fact_args("parse copies its input with strcpy", frag(digest), locator))
        assert ok.status == "ok" and "recorded confirmed fact f-" in text_of(ok)
        # another session never saw that fragment
        foreign = await rig.send("rea_mutate", fact_args("stolen", frag(digest)), session="sess-other")
        assert err(foreign) is ErrorCategory.EVIDENCE_REJECTED
        # the ledger's own views are not evidence about the binary
        listing = await rig.q({"capability": "ledger_list"})
        assert "CONFIRMED FACT" in text_of(listing)
        assert err(await rig.m(fact_args("circular", frag(listing.fragments[0].hash)))) is ErrorCategory.EVIDENCE_REJECTED

    asyncio.run(scenario())


def test_receipts_must_be_live_citable_and_fresh(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        read = await read_symbol(rig, path)
        receipt = read.meta.receipt_id if read.meta else None
        assert receipt is not None
        cite = {"kind": "receipt", "receipt_id": receipt}
        assert (await rig.m(fact_args("receipt-backed claim", cite))).status == "ok"
        assert err(await rig.m(fact_args("bogus", {"kind": "receipt", "receipt_id": "x" * 22}))) is ErrorCategory.EVIDENCE_REJECTED
        ledger_read = await rig.q({"capability": "ledger_summary"})
        ledger_receipt = ledger_read.meta.receipt_id if ledger_read.meta else None
        assert ledger_receipt is not None
        assert err(await rig.m(fact_args("circular", {"kind": "receipt", "receipt_id": ledger_receipt}))) is ErrorCategory.EVIDENCE_REJECTED
        # a ledger write does not stale a source receipt (independent epochs) ...
        assert (await rig.m(fact_args("second claim on the same receipt", cite))).status == "ok"
        # ... but a changed file does, once the router has observed the change
        write(tmp_path, "a.c", C_SOURCE + "int extra;\n")
        await rig.q({"capability": "source_outline", "target": target_file(path)})
        stale = await rig.m(fact_args("too late", cite))
        assert err(stale) is ErrorCategory.EVIDENCE_REJECTED and "stale" in (stale.error.message if stale.error else "")

    asyncio.run(scenario())


def test_hypothesis_lifecycle_promotion_needs_new_evidence_for_every_requirement(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        seed = first_hash(await read_symbol(rig, path, "parse"))
        helper = first_hash(await read_symbol(rig, path, "helper"))
        counter = first_hash(await rig.q({"capability": "source_read", "target": target_file(path), "start_line": 5, "end_line": 5}))
        made = await rig.m({
            "capability": "ledger_record_hypothesis", "claim": "parse overflows buf",
            "required_evidence": [
                {"description": "show the destination size", "suggested_capability": "source_read"},
                {"description": "show the caller passes attacker data"},
            ],
            "basis": [frag(seed)],
        })
        hid = re.search(r"hypothesis (h-[0-9a-f]{12})", text_of(made))
        assert hid is not None and "NOT a fact" in text_of(made)
        hyp = hid.group(1)
        summary = text_of(await rig.q({"capability": "ledger_summary"}))
        assert "confirmed facts: 0" in summary and "1 open" in summary

        def promote(*pairs: tuple[int, str]) -> dict[str, object]:
            return {
                "capability": "ledger_promote", "hypothesis_id": hyp,
                "satisfies": [{"requirement_index": i, "evidence": frag(h)} for i, h in pairs],
            }

        assert err(await rig.m(promote((0, helper)))) is ErrorCategory.EVIDENCE_REJECTED  # requirement 1 missing
        assert err(await rig.m(promote((0, helper), (1, seed)))) is ErrorCategory.EVIDENCE_REJECTED  # basis reused
        assert err(await rig.m(promote((0, helper), (5, counter)))) is ErrorCategory.EVIDENCE_REJECTED  # unknown index
        done = await rig.m(promote((0, helper), (1, counter)))
        fid = re.search(r"confirmed fact (p-[0-9a-f]{12})", text_of(done))
        assert done.status == "ok" and fid is not None
        assert err(await rig.m(promote((0, helper), (1, counter)))) is ErrorCategory.INVALID_STATE  # already promoted
        got = text_of(await rig.q({"capability": "ledger_get", "entry_id": fid.group(1)}))
        assert "CONFIRMED FACT" in got and f"from {hyp}" in got and "parse overflows buf" in got
        assert "[promoted]" in text_of(await rig.q({"capability": "ledger_get", "entry_id": hyp}))

    asyncio.run(scenario())


def test_refutation_needs_verified_evidence_and_is_final(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        digest = first_hash(await read_symbol(rig, path, "helper"))
        made = await rig.m({
            "capability": "ledger_record_hypothesis", "claim": "helper reads out of bounds",
            "required_evidence": [{"description": "show an indexed read in helper"}],
        })
        hyp = re.search(r"(h-[0-9a-f]{12})", text_of(made))
        assert hyp is not None
        base = {"capability": "ledger_refute", "hypothesis_id": hyp.group(1), "reason": "helper only multiplies"}
        range_only = {**base, "evidence": [{"kind": "range", "start": "0x10", "end": "0x20"}]}
        assert err(await rig.m(range_only)) is ErrorCategory.EVIDENCE_REJECTED
        assert (await rig.m({**base, "evidence": [frag(digest)]})).status == "ok"
        assert err(await rig.m({**base, "evidence": [frag(digest)]})) is ErrorCategory.INVALID_STATE
        assert err(await rig.m({"capability": "ledger_refute", "hypothesis_id": "h-" + "0" * 12, "reason": "nothing", "evidence": [frag(digest)]})) is ErrorCategory.NOT_FOUND

    asyncio.run(scenario())


def test_unanalyzed_gaps_stay_visible_until_closed_with_evidence(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        assert "COMPLETE" in text_of(await rig.q({"capability": "ledger_summary"}))
        declared = await rig.m({
            "capability": "ledger_declare_gap", "reason": "decompile_failed",
            "scope": "sub_402000 would not decompile", "start": "0x402000", "end": "0x402100",
        })
        gid = re.search(r"(g-[0-9a-f]{12})", text_of(declared))
        assert gid is not None
        assert "HAS OPEN GAPS" in text_of(await rig.q({"capability": "ledger_summary"}))
        open_gaps = text_of(await rig.q({"capability": "ledger_list", "view": "gaps", "status": "open"}))
        assert "0x402000-0x402100" in open_gaps and "sub_402000" in open_gaps
        close = {"capability": "ledger_close_gap", "gap_id": gid.group(1), "note": "analyzed by hand"}
        assert err(await rig.m({**close, "evidence": [frag("cd" * 32)]})) is ErrorCategory.EVIDENCE_REJECTED
        proof = first_hash(await read_symbol(rig, path, "helper"))
        assert (await rig.m({**close, "evidence": [frag(proof)]})).status == "ok"
        assert "COMPLETE" in text_of(await rig.q({"capability": "ledger_summary"}))
        assert err(await rig.m({**close, "evidence": [frag(proof)]})) is ErrorCategory.INVALID_STATE
        bad = {"capability": "ledger_declare_gap", "reason": "unknown", "scope": "half a range", "start": "0x10"}
        assert err(await rig.m(bad)) is ErrorCategory.INVALID_REQUEST

    asyncio.run(scenario())


def test_episodes_and_sessions_are_isolated_and_listing_pages(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        proof = first_hash(await read_symbol(rig, path))
        for i in range(3):
            await rig.m(fact_args(f"claim number {i}", frag(proof), episode="alpha"))
        await rig.m(fact_args("only in beta", frag(proof), episode="beta"))
        assert "only in beta" not in text_of(await rig.q({"capability": "ledger_list", "episode": "alpha"}))
        page = await rig.q({"capability": "ledger_list", "episode": "alpha", "limit": 2})
        assert page.meta is not None and page.meta.next_cursor is not None and len(page.fragments) == 2
        rest = await rig.q({"capability": "ledger_list", "episode": "alpha", "limit": 2, "cursor": page.meta.next_cursor})
        assert len(rest.fragments) == 1 and rest.meta is not None and rest.meta.next_cursor is None
        # a write between pages invalidates the cursor
        await rig.m(fact_args("a late claim", frag(proof), episode="alpha"))
        assert err(await rig.q({"capability": "ledger_list", "episode": "alpha", "limit": 2, "cursor": page.meta.next_cursor})) is ErrorCategory.STALE_CURSOR
        assert "claim number" not in text_of(await rig.send("rea_query", {"capability": "ledger_list", "episode": "alpha"}, session="sess-other"))
        assert err(await rig.q({"capability": "ledger_get", "episode": "alpha", "entry_id": "f-" + "0" * 12})) is ErrorCategory.NOT_FOUND

    asyncio.run(scenario())


def test_ledger_writes_are_auto_allowed_but_idb_mutations_still_need_the_grant(tmp_path: Path) -> None:
    path = write(tmp_path, "a.c", C_SOURCE)

    async def scenario() -> None:
        rig = Rig(tmp_path, grant=False)
        proof = first_hash(await read_symbol(rig, path))
        # ledger writes need no human grant ...
        assert (await rig.m(fact_args("no grant needed", frag(proof)))).status == "ok"
        assert (await rig.m({"capability": "ledger_declare_gap", "reason": "not_analyzed", "scope": "rest"})).status == "ok"
        # ... but every receipt/fragment proof is still verified
        assert err(await rig.m(fact_args("forged", frag("ab" * 32)))) is ErrorCategory.EVIDENCE_REJECTED
        # ... and a real disassembler mutation is still gated on the human grant
        rename = {"capability": "rename_symbol", "address": "0x401000", "new_name": "parse_input"}
        assert err(await rig.m(rename)) is ErrorCategory.DENIED_CONSENT
        assert (await rig.q({"capability": "ledger_summary"})).status == "ok"

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Ledger internals: append-only chain, replay, journal
# --------------------------------------------------------------------------- #


def staged_fact(ledger: EpisodeLedger, claim: str, digest: str) -> None:
    proof = FragmentProof(kind="fragment", hash=digest, label="x", capability=Capability.SOURCE_READ, generation=0)
    ledger.commit(ledger.stage([ledger.fact(claim, (proof,))], 1))


def test_chain_replay_tamper_and_validator_invariants() -> None:
    ledger = EpisodeLedger("main")
    staged_fact(ledger, "first claim", "11" * 32)
    staged_fact(ledger, "second claim", "22" * 32)
    lines = ledger.lines
    assert lines[0].prev == "0" * 64 and lines[1].prev == lines[0].hash and ledger.head == lines[1].hash
    assert EpisodeLedger.replay("main", lines).summary() == ledger.summary()
    with pytest.raises(LedgerRejected, match="chain"):
        EpisodeLedger.replay("main", [lines[1]])  # dropped a link
    forged = lines[0].model_copy(update={"at": lines[0].at + 1})
    with pytest.raises(LedgerRejected, match="hash mismatch"):
        EpisodeLedger.replay("main", [forged, lines[1]])
    with pytest.raises(LedgerRejected, match="moved"):  # stale staging cannot fork the chain
        proof = FragmentProof(kind="fragment", hash="33" * 32, label="x", capability=Capability.SOURCE_READ, generation=0)
        staged = ledger.stage([ledger.fact("third claim", (proof,))], 2)
        ledger.commit(staged)
        ledger.commit(staged)
    hyp = ledger.hypothesis("maybe", (Requirement(description="show it"),), ())
    ledger.commit(ledger.stage([hyp], 3))
    with pytest.raises(LedgerRejected):  # a hypothesis id is not a fact id
        ledger.stage([hyp], 4)


def test_durable_journal_replays_and_refuses_tampering(tmp_path: Path) -> None:
    root = tmp_path / "src"
    journal_dir = tmp_path / "ledgers"
    path = write(root, "a.c", C_SOURCE)

    async def first() -> str:
        rig = Rig(root, ledger_dir=journal_dir)
        proof = first_hash(await read_symbol(rig, path))
        assert (await rig.m(fact_args("persisted claim", frag(proof)))).status == "ok"
        await rig.m({"capability": "ledger_declare_gap", "reason": "not_analyzed", "scope": "everything else"})
        return text_of(await rig.q({"capability": "ledger_list"}))

    before = asyncio.run(first())
    files = list(journal_dir.glob("*.jsonl"))
    assert len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600

    async def second() -> str:
        rig = Rig(root, ledger_dir=journal_dir)  # a fresh process
        return text_of(await rig.q({"capability": "ledger_list"}))

    assert asyncio.run(second()) == before
    files[0].write_text(files[0].read_text().replace("persisted claim", "persisted clam!"))

    async def third() -> ToolResponse:
        return await Rig(root, ledger_dir=journal_dir).q({"capability": "ledger_list"})

    assert err(asyncio.run(third())) is ErrorCategory.INVALID_STATE
    missing = Journal(tmp_path / "missing.jsonl", session="s", episode="main", workspace_fingerprint="0" * 64)
    assert missing.load("main").event_count == 0


# --------------------------------------------------------------------------- #
# SARIF importer
# --------------------------------------------------------------------------- #


def sarif_result(uri: str, line: int = 3, rule: str = "c.lang.strcpy", message: str = "unbounded copy") -> dict[str, object]:
    return {
        "ruleId": rule, "level": "error", "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
    }


def sarif_doc(*results: Mapping[str, object], version: str = "2.1.0", tool: str = "semgrep") -> str:
    return json.dumps({
        "version": version, "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": tool, "informationUri": "https://semgrep.dev"}}, "results": list(results)}],
    })


def record_hash(result: Mapping[str, object]) -> str:
    return blake3(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def test_sarif_import_creates_import_backed_facts_and_rejects_hostile_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "src/ok.c", C_SOURCE)
    good = sarif_result("src/ok.c")
    hostile: list[Mapping[str, object]] = [
        sarif_result("https://evil.example/x.c"),
        sarif_result("file://evil.example/share/x.c"),
        sarif_result("data:text/plain;base64,AAAA"),
        sarif_result("C:/Windows/System32/x.c"),
        sarif_result("../outside.c"),
        sarif_result("file:///etc/passwd"),
        sarif_result("src/ok.c", line=9999),
        {"ruleId": "no.location", "message": {"text": "x"}},
    ]
    sarif = write(tmp_path, "report.sarif", sarif_doc(good, *hostile, good))

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("the importer must never open a socket")

    monkeypatch.setattr(socket.socket, "connect", no_network)

    async def scenario() -> None:
        rig = Rig(tmp_path)
        done = await rig.m({"capability": "import_sarif", "path": str(sarif)})
        body = text_of(done)
        assert done.status == "ok" and "seen=10 imported=1 rejected=8" in body and "duplicates=1" in body
        for reason in ("external_uri×4", "path_traversal×1", "outside_roots×1", "region_outside_file×1", "no_location×1"):
            assert reason in body
        import_id = re.search(r"import_id=([0-9a-f]{16})", body)
        assert import_id is not None
        facts = text_of(await rig.q({"capability": "ledger_list", "view": "facts"}))
        assert "semgrep reports c.lang.strcpy [error] at src/ok.c:3: unbounded copy" in facts
        assert "evil.example" not in facts
        gaps = text_of(await rig.q({"capability": "ledger_list", "view": "gaps", "status": "open"}))
        assert "sarif_rejected" in gaps and "8 of 10" in gaps
        # an imported record is verifiable evidence; an invented one is not; so is a record from elsewhere
        cite = {"kind": "import", "import_id": import_id.group(1), "record_hash": record_hash(good)}
        assert (await rig.m(fact_args("semgrep flagged the copy in parse", cite))).status == "ok"
        forged = {**cite, "record_hash": "ee" * 32}
        assert err(await rig.m(fact_args("forged", forged))) is ErrorCategory.EVIDENCE_REJECTED
        assert err(await rig.m(fact_args("other episode", cite, episode="elsewhere"))) is ErrorCategory.EVIDENCE_REJECTED
        again = await rig.m({"capability": "import_sarif", "path": str(sarif)})
        assert err(again) is ErrorCategory.INVALID_STATE

    asyncio.run(scenario())


def test_sarif_limits_version_and_paths(tmp_path: Path) -> None:
    write(tmp_path, "ok.c", C_SOURCE)
    many = [sarif_result("ok.c", rule=f"rule.{i}") for i in range(5)]
    capped = write(tmp_path, "capped.sarif", sarif_doc(*many))
    old = write(tmp_path, "old.sarif", sarif_doc(version="2.0.0"))
    junk = write(tmp_path, "junk.sarif", "{not json")
    unsafe_line = write(tmp_path, "line.sarif", sarif_doc(sarif_result("ok.c", line=2**60)))
    outside = tmp_path.parent / "elsewhere.sarif"
    outside.write_text(sarif_doc(many[0]))

    async def scenario() -> None:
        rig = Rig(tmp_path)
        limited = await rig.m({"capability": "import_sarif", "path": str(capped), "max_results": 2})
        assert "imported=2" in text_of(limited) and "not_imported_over_max=3" in text_of(limited)
        assert "budget_truncated" in text_of(await rig.q({"capability": "ledger_list", "view": "gaps"}))
        for bad in (old, junk):
            assert err(await rig.m({"capability": "import_sarif", "path": str(bad), "episode": "x"})) is ErrorCategory.EVIDENCE_REJECTED
        lone = await rig.m({"capability": "import_sarif", "path": str(unsafe_line), "episode": "y"})
        assert "imported=0 rejected=1 (invalid_result×1)" in text_of(lone)
        assert err(await rig.m({"capability": "import_sarif", "path": str(outside)})) is ErrorCategory.DENIED_PATH
        escape_root = await rig.m({"capability": "import_sarif", "path": str(capped), "source_root": str(tmp_path.parent), "episode": "z"})
        assert err(escape_root) is ErrorCategory.DENIED_PATH

    asyncio.run(scenario())
    with pytest.raises(SarifRejected):
        parse_sarif(b'{"version":"2.1.0","runs":[]}', source_root=tmp_path, roots=(tmp_path,), max_results=5)


def test_scanner_module_has_no_network_or_process_imports() -> None:
    import rea_mcp.evidence.scanner as scanner

    source = Path(scanner.__file__).read_text()
    forbidden = r"^\s*(?:import|from)\s+(?:httpx|requests|socket|ssl|urllib\.request|http\.client|subprocess|ftplib)\b"
    assert re.search(forbidden, source, re.MULTILINE) is None
    assert os.path.exists(scanner.__file__)
