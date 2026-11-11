import asyncio
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from rea_mcp.core.models import (
    BackendItem, BackendKind, BackendResult, Capability, DecompileArgs, ErrorCategory, QueryRequest,
    ToolResponse,
)
from rea_mcp.core.router import BackendCall, CapabilityRouter, ToolName
from rea_mcp.core.security import (
    Authorizer, AuditLog, DenyAllConsent, RedactionPipeline, SecurityPolicy,
)

SESSION = "sess-0001"


class FakeBackend:
    kind = BackendKind.IDA_PRO

    def __init__(self) -> None:
        self.generation = 1
        self.calls: list[Capability] = []
        self.functions = [f"sub_{i:04x}" for i in range(50)]
        self.decomp = "int main(void) { return 0; }"

    def supports(self, capability: Capability) -> bool:
        return True

    async def execute(self, call: BackendCall) -> BackendResult:
        self.calls.append(call.capability)
        if call.capability is Capability.LIST_FUNCTIONS:
            limit = getattr(call.args, "limit")
            chunk = self.functions[call.offset : call.offset + limit]
            more = call.offset + limit < len(self.functions)
            return BackendResult(
                items=tuple(BackendItem(label=n, text=f"{n}: " + "x" * 30) for n in chunk),
                next_offset=call.offset + limit if more else None,
                generation=self.generation,
            )
        if call.capability is Capability.DECOMPILE:
            return BackendResult(items=(BackendItem(label="main", text=self.decomp),), generation=self.generation)
        if call.capability is Capability.SET_COMMENT or call.capability is Capability.PATCH_BYTES:
            self.generation += 1
        return BackendResult(items=(BackendItem(label="ok", text="done"),), generation=self.generation)


def make(env: dict[str, str], tmp: Path, durable: bool = True) -> tuple[CapabilityRouter, FakeBackend, AuditLog]:
    policy = SecurityPolicy.from_environ(env)
    audit = AuditLog(tmp / "audit.jsonl" if durable else None)
    backend = FakeBackend()
    router = CapabilityRouter(
        backends=[backend],
        authorizer=Authorizer(policy, audit, DenyAllConsent()),
        redaction=RedactionPipeline.from_policy(policy, {}),
        cursor_key=b"k" * 32,
    )
    return router, backend, audit


def run(router: CapabilityRouter, tool: ToolName, body: dict[str, object]) -> ToolResponse:
    out = asyncio.run(router.call(tool, SESSION, json.dumps(body)))
    assert isinstance(out, ToolResponse)
    return out


def q(args: dict[str, object], **control: object) -> dict[str, object]:
    return {"database": "db1", "args": args, "control": control}


def cat(r: ToolResponse) -> ErrorCategory:
    assert r.error is not None, r
    return r.error.category


# ---------------------------------------------------------------- tiers ----
def test_read_only_default_works(tmp_path: Path) -> None:
    router, _, _ = make({}, tmp_path)
    r = run(router, "rea_query", q({"capability": "decompile", "address": "0x401000"}))
    assert r.status == "ok" and r.fragments[0].text.startswith("int main")


def test_mutate_denied_without_consent_and_allowed_with_auto_grant(tmp_path: Path) -> None:
    body = q({"capability": "set_comment", "address": 4096, "comment": "hi"})
    router, backend, _ = make({}, tmp_path)
    assert cat(run(router, "rea_mutate", body)) is ErrorCategory.DENIED_CONSENT
    assert backend.calls == []
    router2, backend2, _ = make({"REA_AUTO_GRANT_MUTATE": "1"}, tmp_path / "b")
    assert run(router2, "rea_mutate", body).status == "ok" and backend2.calls


def test_privileged_hard_disabled_by_default_and_logged(tmp_path: Path) -> None:
    router, backend, audit = make({}, tmp_path)
    body = q({"capability": "patch_bytes", "address": 4096, "data": "90", "justification": "nop out check"})
    assert cat(run(router, "rea_privileged", body)) is ErrorCategory.DENIED_OVERRIDE
    assert backend.calls == []
    assert audit.memory[-1]["event"] == "denied"


def test_privileged_needs_flag_allowlist_keyfile_and_durable_audit(tmp_path: Path) -> None:
    body = q({"capability": "patch_bytes", "address": 4096, "data": "90", "justification": "nop out check"})
    key = tmp_path / "token.key"
    env = {"REA_PRIVILEGED_OVERRIDE": "enable-dangerous-ops", "REA_PRIVILEGED_ALLOW": "patch_bytes",
           "REA_PRIVILEGED_KEYFILE": str(key)}
    router, backend, audit = make(env, tmp_path)
    assert cat(run(router, "rea_privileged", body)) is ErrorCategory.DENIED_OVERRIDE  # key absent
    key.write_text("present")
    assert run(router, "rea_privileged", body).status == "ok"
    assert backend.calls == [Capability.PATCH_BYTES]
    key.unlink()  # removal revokes immediately
    assert cat(run(router, "rea_privileged", body)) is ErrorCategory.DENIED_OVERRIDE
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert AuditLog.verify_chain(lines)
    tampered = [lines[0].replace("patch_bytes", "decompile")] + lines[1:]
    assert not AuditLog.verify_chain(tampered)
    # not in allow-list
    r2, _, _ = make({**env, "REA_PRIVILEGED_ALLOW": "save_database"}, tmp_path / "c")
    key.write_text("x")
    assert cat(run(r2, "rea_privileged", body)) is ErrorCategory.DENIED_OVERRIDE
    # no durable audit => fail closed
    r3, b3, _ = make({"REA_PRIVILEGED_OVERRIDE": "enable-dangerous-ops", "REA_PRIVILEGED_ALLOW": "patch_bytes"}, tmp_path, durable=False)
    assert cat(run(r3, "rea_privileged", body)) is ErrorCategory.AUDIT_FAILURE and b3.calls == []


def test_script_eval_never_reaches_backend(tmp_path: Path) -> None:
    env = {"REA_PRIVILEGED_OVERRIDE": "enable-dangerous-ops", "REA_PRIVILEGED_ALLOW": "script_eval"}
    router, backend, _ = make(env, tmp_path)
    body = q({"capability": "script_eval", "code": "print(1)", "justification": "inspect idb state"})
    assert cat(run(router, "rea_privileged", body)) is ErrorCategory.SANDBOX_UNAVAILABLE
    assert backend.calls == []


def test_tier_cannot_be_smuggled_through_wrong_facade(tmp_path: Path) -> None:
    router, backend, _ = make({}, tmp_path)
    body = q({"capability": "patch_bytes", "address": 1, "data": "90", "justification": "nop out check"})
    assert cat(run(router, "rea_query", body)) is ErrorCategory.INVALID_REQUEST
    assert cat(run(router, "rea_mutate", body)) is ErrorCategory.INVALID_REQUEST
    assert backend.calls == []


def test_allowlist_typo_fails_closed() -> None:
    with pytest.raises(ValueError):
        SecurityPolicy.from_environ({"REA_PRIVILEGED_ALLOW": "patch_byts"})
    with pytest.raises(ValueError):
        SecurityPolicy.from_environ({"REA_PRIVILEGED_ALLOW": "decompile"})


# ------------------------------------------------------ strict validation ----
@pytest.mark.parametrize("args", [
    {"capability": "decompile", "address": 2**53},          # unsafe JSON integer
    {"capability": "decompile", "address": True},           # bool
    {"capability": "decompile", "address": "0x1ffffffffffffffff"},  # > u64
    {"capability": "decompile", "address": 1, "extra": 1},  # unknown field
    {"capability": "list_functions", "limit": 1001},        # reject, never clamp
    {"capability": "list_functions", "limit": 0},
    {"capability": "get_bytes", "address": 1, "size": 4097},
    {"capability": "find_bytes", "pattern": "zz"},
])
def test_bad_inputs_rejected(args: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        QueryRequest.model_validate_json(json.dumps({"args": args}))


def test_budget_bounds_and_utf8_and_hex_address() -> None:
    with pytest.raises(ValidationError):
        QueryRequest.model_validate_json('{"args":{"capability":"decompile","address":1},"control":{"token_budget":32001}}')
    with pytest.raises(ValidationError):
        QueryRequest.model_validate_json('{"args":{"capability":"find_regex","pattern":"a\\ud800b"}}')
    ok = QueryRequest.model_validate_json('{"args":{"capability":"decompile","address":"0xFFFFFFFFFFFFFFFF"}}')
    assert isinstance(ok.args, DecompileArgs) and ok.args.address == 2**64 - 1


# ------------------------------------------------- budget, cursor, dedup ----
def test_truncation_cursor_roundtrip_and_tamper(tmp_path: Path) -> None:
    router, _, _ = make({}, tmp_path)
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(40):
        args: dict[str, object] = {"capability": "list_functions", "limit": 50}
        if cursor:
            args["cursor"] = cursor
        r = run(router, "rea_query", q(args, token_budget=100))
        assert r.status == "ok" and r.meta is not None
        assert r.meta.tokens_used <= 100
        seen += [f.label for f in r.fragments]
        cursor = r.meta.next_cursor
        if cursor is None:
            assert r.meta.result_complete
            break
    assert seen == [f"sub_{i:04x}" for i in range(50)]  # no gaps, no repeats
    first = run(router, "rea_query", q({"capability": "list_functions", "limit": 50}, token_budget=100))
    assert first.meta and first.meta.omission and first.meta.omission.omitted_fragments > 0
    token = first.meta.next_cursor
    assert token is not None
    bad = token[:-1] + ("0" if token[-1] != "0" else "1")
    r = run(router, "rea_query", q({"capability": "list_functions", "limit": 50, "cursor": bad}))
    assert cat(r) is ErrorCategory.STALE_CURSOR
    other = run(router, "rea_query", q({"capability": "list_functions", "limit": 10, "cursor": first.meta.next_cursor}))
    assert cat(other) is ErrorCategory.STALE_CURSOR  # different predicate


def test_budget_too_small(tmp_path: Path) -> None:
    router, _, _ = make({}, tmp_path)
    r = run(router, "rea_query", q({"capability": "decompile", "address": 1}, token_budget=2))
    assert cat(r) is ErrorCategory.BUDGET_TOO_SMALL


def test_dedup_receipt_known_hashes_not_modified_and_stale(tmp_path: Path) -> None:
    router, backend, _ = make({"REA_AUTO_GRANT_MUTATE": "1"}, tmp_path)
    args = {"capability": "decompile", "address": 1}
    r1 = run(router, "rea_query", q(args))
    assert r1.fragments and r1.meta and r1.meta.receipt_id
    digest = r1.fragments[0].hash
    r2 = run(router, "rea_query", q(args, receipt_id=r1.meta.receipt_id))
    assert not r2.fragments and r2.known[0].hash == digest and r2.known[0].tokens_saved > 0
    r3 = run(router, "rea_query", q(args, known_hashes=[digest]))  # stateless fallback
    assert not r3.fragments and r3.known
    r4 = run(router, "rea_query", q(args, expected_hash=digest))
    assert r4.status == "not_modified"
    run(router, "rea_mutate", q({"capability": "set_comment", "address": 1, "comment": "c"}))
    r5 = run(router, "rea_query", q(args, receipt_id=r1.meta.receipt_id))
    assert cat(r5) is ErrorCategory.STALE_RECEIPT
    r6 = run(router, "rea_query", q(args, receipt_id="A" * 22))
    assert cat(r6) is ErrorCategory.UNKNOWN_RECEIPT
    backend.decomp = "int main(void) { return 1; }"  # changed content => new hash, resent
    r7 = run(router, "rea_query", q(args, known_hashes=[digest]))
    assert r7.fragments and r7.fragments[0].hash != digest


# ----------------------------------------------------------- redaction ----
KEY = "AKIAABCDEFGHIJKLMNOP"


def test_artifact_secrets_are_kept_and_tagged_by_default(tmp_path: Path) -> None:
    router, backend, _ = make({}, tmp_path)
    backend.decomp = f'k = "{KEY}"; again {KEY}'
    r = run(router, "rea_query", q({"capability": "decompile", "address": 1}))
    frag = r.fragments[0]
    assert frag.text.count(KEY) == 2  # evidence untouched
    assert len(frag.secret_candidates) == 1  # same secret => same fingerprint tag
    assert re.fullmatch(r"\[SECRET_CANDIDATE:aws_access_key:[0-9a-f]{8}\]", frag.secret_candidates[0])


def test_artifact_redaction_is_opt_in(tmp_path: Path) -> None:
    router, backend, _ = make({"REA_REDACT_ARTIFACTS": "on"}, tmp_path)
    backend.decomp = f"k = {KEY}; password = hunter2hunter2"
    frag = run(router, "rea_query", q({"capability": "decompile", "address": 1})).fragments[0]
    assert KEY not in frag.text and "hunter2" not in frag.text and not frag.secret_candidates
    assert len(re.findall(r"\[REDACTED:aws_access_key:[0-9a-f]{8}\]", frag.text)) == 1
    with pytest.raises(ValueError):
        SecurityPolicy.from_environ({"REA_REDACT_ARTIFACTS": "maybe"})


def test_host_secrets_are_always_redacted_even_from_artifact_text(tmp_path: Path) -> None:
    policy = SecurityPolicy.from_environ({})
    red = RedactionPipeline.from_policy(policy, {"MY_API_TOKEN": "supersecretvalue123", "HOME": "/x"})
    assert red.scrub_artifact("x supersecretvalue123 y").text == "x [REDACTED:host_secret] y"
    assert KEY in red.scrub_artifact(KEY).text  # but binary secrets stay


def test_lone_surrogate_from_backend_is_made_visible(tmp_path: Path) -> None:
    router, backend, _ = make({}, tmp_path)
    backend.decomp = "bad\ud800 and nul\x00"
    r = run(router, "rea_query", q({"capability": "decompile", "address": 1}))
    assert r.status == "ok" and "\\ud800" in r.fragments[0].text and "\x00" not in r.fragments[0].text


# ---------------------------------------------------------------- paths ----
def test_open_database_path_confined_to_roots(tmp_path: Path) -> None:
    root = tmp_path / "samples"; root.mkdir()
    (root / "a.bin").write_bytes(b"MZ")
    outside = tmp_path / "secret.bin"; outside.write_bytes(b"x")
    (root / "link").symlink_to(outside)
    router, backend, _ = make({"REA_AUTO_GRANT_MUTATE": "1", "REA_ALLOWED_ROOTS": str(root)}, tmp_path / "w")
    ok = run(router, "rea_mutate", {"args": {"capability": "open_database", "input_path": str(root / "a.bin")}})
    assert ok.status == "ok"
    for p in (str(root / "link"), str(outside), "relative.bin", str(root / ".." / "secret.bin")):
        assert cat(run(router, "rea_mutate", {"args": {"capability": "open_database", "input_path": p}})) is ErrorCategory.DENIED_PATH


def test_capabilities_listing_reflects_policy(tmp_path: Path) -> None:
    router, _, _ = make({}, tmp_path)
    entries = {e.capability: e for e in router.capabilities().entries}
    assert entries[Capability.DECOMPILE].enabled
    assert not entries[Capability.PATCH_BYTES].enabled and not entries[Capability.SCRIPT_EVAL].enabled
