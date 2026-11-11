"""Built-in methodology playbooks, served as MCP prompts and as ``rea://prompts/{name}`` resources.

The five playbooks are original text written for this server's capability model. They follow the
shape of the community prompt collections this project consolidates (JoasASantos/REA-Prompts:
phase-ordered, evidence-first reverse-engineering prompts; aicodeking/leanrea: token-lean,
dedup-aware tool use) but copy none of their wording, because the point of a playbook here is that
every step names a real capability of the four-tool facade and the evidence rules the server
enforces.

Every rendered playbook starts with the same operating rules (``OPERATING_RULES``), so no prompt can
forget the facade, the token controls, or the ledger discipline. Prompt arguments are validated and
rendered as JSON string literals, never spliced in as free text, so a hostile argument cannot
restructure the playbook.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from pydantic import TypeAdapter, ValidationError

from rea_mcp.core.models import EpisodeId, ShortText, StrictModel

PROMPT_URI_PREFIX: Final = "rea://prompts/"

_EPISODE: Final[TypeAdapter[EpisodeId]] = TypeAdapter(EpisodeId)
_TEXT: Final[TypeAdapter[ShortText]] = TypeAdapter(ShortText)


class PromptError(ValueError):
    """Unknown prompt, or arguments that failed validation."""


@dataclass(frozen=True, slots=True)
class PromptArgument:
    name: str
    description: str
    required: bool


class PromptInputs(StrictModel):
    target: ShortText = "the database or source tree the user named"
    focus: ShortText = "none given; use the playbook defaults"
    episode: EpisodeId = "main"


@dataclass(frozen=True, slots=True)
class Playbook:
    name: str
    title: str
    description: str
    steps: tuple[str, ...]

    def render(self, inputs: PromptInputs) -> str:
        header = (
            f"# {self.title}\n\n"
            f"Target: {json.dumps(inputs.target)}\n"
            f"Focus: {json.dumps(inputs.focus)}\n"
            f"Ledger episode: {json.dumps(inputs.episode)}\n"
        )
        body = "\n".join(f"{i}. {step}" for i, step in enumerate(self.steps, start=1))
        return f"{header}\n{OPERATING_RULES}\n## Procedure\n\n{body}\n\n{CLOSING_RULES}"


PROMPT_ARGUMENTS: Final[tuple[PromptArgument, ...]] = (
    PromptArgument("target", "What to analyze: a database id, a file, or a source directory (max 256 chars).", False),
    PromptArgument("focus", "A narrower question to answer first (max 256 chars).", False),
    PromptArgument("episode", "Evidence-ledger episode name to record into (default 'main').", False),
)

OPERATING_RULES: Final = """\
## Operating rules (apply to every step)

**The four tools.** You have exactly these, and nothing else reaches the disassembler:
- `rea_capabilities`: call it first. It lists every capability, its tier, and whether it is enabled
  right now. Never assume a capability exists; plan around what is enabled.
- `rea_query`: read-only analysis (decompile, disasm, xrefs, listings, search, byte reads, source
  reads, hotspot scans, ledger views). This is where most of the work happens.
- `rea_mutate`: ledger notes need no approval. Edits to the disassembler database (rename, comment,
  type, structural edits) require the human's per-session approval; if it is refused, say so and
  continue read-only. Do not retry a refused edit.
- `rea_privileged`: patching, memory writes, saving, scripts, debugger control. Disabled unless the
  operator enabled it. Do not call it unless the user explicitly asked for that operation.

**Call shape.** Every call is `{"args": {"capability": "<name>", ...}, "control": {...}}`, with
optional `database` and `backend` when more than one is open. Addresses may be hex strings.

**Be token-lean.** The server deduplicates for you if you let it:
- Keep the `receipt_id` from each read response's `meta` and send it back as `control.receipt_id` on
  later reads of the same database. Fragments you already hold come back as short references.
- Send the hashes of fragments you still hold as `control.known_hashes`.
- Set a small `control.token_budget`, then follow `meta.next_cursor` to page instead of asking for
  everything. A `STALE_RECEIPT` or `STALE_CURSOR` error means the database changed: re-read, do not
  reuse old facts without checking them.
- Check `meta.result_complete` and `meta.truncated`. A truncated answer is not a complete answer.

**Record what you learn in the Evidence Ledger** (`ledger_*` capabilities, all under `rea_mutate`):
- `ConfirmedFact` (`ledger_record_fact`): a claim backed by evidence the server itself issued to you in
  this session: `{"kind": "fragment", "hash": ...}` or `{"kind": "receipt", "receipt_id": ...}`. A
  range locator alone never confirms anything, and hashes you typed from memory are rejected.
- `Hypothesis` (`ledger_record_hypothesis`): anything you believe but have not shown. State what
  evidence would settle it as `required_evidence`. Promote it with `ledger_promote` only after you
  have fetched new evidence that satisfies each requirement; a hypothesis cannot vouch for itself.
  If the evidence contradicts it, use `ledger_refute`.
- `UnanalyzedGap` (`ledger_declare_gap`): code or data you did not examine, or could not (decompile
  failed, packed, out of scope, budget). Close it with `ledger_close_gap` once you have examined it.
  A scan or listing that reports incomplete coverage does not record a gap by itself; declare it.
- Read the ledger back with `ledger_summary` and `ledger_list` (these results describe your notes;
  they are never evidence for new facts).
"""

CLOSING_RULES: Final = """\
## Before you answer

- Call `ledger_summary`. Report ConfirmedFacts, Hypotheses and UnanalyzedGaps as three separate groups.
- Never present a Hypothesis as a finding. Say what would confirm it.
- Cite fragment hashes or receipt ids for each ConfirmedFact so the reader can check them.
- State what you did not examine. If a section of the target was not covered, it is a gap.
"""

TRIAGE: Final = Playbook(
    name="triage-binary",
    title="Triage a binary",
    description="First-pass orientation: what it is, what it imports, where the interesting code is.",
    steps=(
        "Call `rea_capabilities`, then `list_databases` to see which database and backend you have.",
        "Orient: `list_segments`, `list_imports`, `list_exports` (small pages). Note packer signs "
        "(few imports, high-entropy or writable+executable sections, tiny code section); if present, "
        "declare a `packed_or_encrypted` gap instead of guessing at what is hidden.",
        "Surface intent: `list_strings` with a `filter`, then `find_regex` for URLs, paths, format "
        "strings, registry keys and error messages. Record only what a returned fragment shows.",
        "Find the entry points: `search_functions`, `list_functions` with a filter, and `xrefs_to` on the "
        "most telling import or string. Prefer a short call chain over a long list.",
        "Read the few functions that matter with `decompile` (fall back to `disasm` if it fails; a failed "
        "decompile is a gap, not a conclusion). Use `callees` and `callgraph` with a small `max_depth` "
        "to place each in context.",
        "Write down results as you go: facts with the fragment that shows them, guesses as hypotheses "
        "with the evidence that would settle them, everything skipped as a gap.",
        "Optional, only if the human approves the session grant: `rename_symbol` and `set_comment` on "
        "functions you have confirmed, so the next reader sees them. Never rename on a hypothesis.",
    ),
)

CRYPTO: Final = Playbook(
    name="crypto-audit",
    title="Audit cryptographic use",
    description="Find crypto primitives, keys, nonces and misuse, and separate what is shown from what is assumed.",
    steps=(
        "Call `rea_capabilities`. Plan only with enabled capabilities.",
        "Locate candidates three ways and compare: imports (`list_imports` with a filter for crypto "
        "libraries and OS crypto APIs), constants (`find_bytes` for well-known S-box, round-constant and "
        "initial-value prefixes, with `??` wildcards), and strings (`find_regex` for algorithm names, "
        "PEM headers, curve names). A hit by one method is a hypothesis; agreement across two is stronger.",
        "For each candidate, `xrefs_to` the constant or import, then `decompile` the referencing "
        "function. Identify algorithm, mode, key and IV/nonce sources, and where the output goes.",
        "Check misuse, one claim at a time, each with its evidence: hard-coded key or IV, nonce reuse, "
        "ECB or unauthenticated modes, weak or home-grown primitives, predictable randomness, "
        "unchecked MAC or signature results, comparison that is not constant-time, key material kept "
        "after use.",
        "Treat key-like data carefully: report where it is and how it is derived, and record it only as "
        "tagged `[SECRET_CANDIDATE:...]` output. Do not paste raw key bytes into notes you write.",
        "Anything you inferred from a name, a constant or a similar function elsewhere is a Hypothesis. "
        "Settle it by reading the surrounding code, then `ledger_promote` or `ledger_refute`.",
        "Declare gaps for code paths you did not read, especially anything reached only through "
        "indirect calls or other modules.",
    ),
)

PROTOCOL: Final = Playbook(
    name="protocol-reconstruction",
    title="Reconstruct a protocol or file format",
    description="Recover message layouts, state machine and parsing rules from the code that handles them.",
    steps=(
        "Call `rea_capabilities`. Identify the I/O boundary: `list_imports` filtered for socket, file, "
        "pipe and parsing APIs, and `list_strings` for magic values, field names and version strings.",
        "Walk inward from each receive/read/parse call with `xrefs_to`, `callees` and `callgraph` (small "
        "depth). Name the dispatcher: the function that switches on a message or record type.",
        "For each message or record type, `decompile` its handler and write down offset, size, "
        "endianness, meaning and validation of each field. Use `get_bytes` on static tables and sample "
        "data, and `read_struct` when a type is already defined.",
        "Record each field layout as a fact only when a fragment shows the access (for example the "
        "bounds check or the read at that offset). A layout deduced from one example is a Hypothesis.",
        "Recover the state machine: which handler is reachable from which state, what each transition "
        "checks. Mark transitions you inferred but did not see as hypotheses.",
        "Look for parser weaknesses as separate hypotheses: unchecked lengths, integer arithmetic on "
        "sizes, nested or recursive structures, trusting a count before validating the buffer.",
        "Only with the human's approval: `declare_type` and `set_type` to capture confirmed layouts in "
        "the database. Declare gaps for message types or flags you have not read.",
    ),
)

VULNERABILITY: Final = Playbook(
    name="vulnerability-surface-audit",
    title="Map the vulnerability surface",
    description="Enumerate input sources and dangerous sinks, trace candidate paths, and keep candidates apart from proof.",
    steps=(
        "Call `rea_capabilities`. If the target is a source tree, start with `scan_hotspots` (read-only "
        "triage). Its findings are candidates, never proof. If its first item reports incomplete "
        "coverage, call `ledger_declare_gap` for what it skipped. For SARIF from another tool, "
        "`import_sarif` opens gaps for you; imported results are claims to verify, not facts.",
        "For a binary, list sources and sinks: `list_imports` and `find_regex` for input APIs "
        "(network, file, environment, command line, IPC) and for unbounded copy, format, "
        "allocation-size and command-execution APIs.",
        "For each sink, `xrefs_to` it and trace back toward a source with `callees`/`callgraph`. A "
        "path is a hypothesis until you have read every function along it and seen what bounds or "
        "validates the data.",
        "Read the guarded code, not just the sink: lengths, signedness, truncation, loop bounds, "
        "ownership and lifetime. Use `decompile`, and `disasm` where the decompiler hides a check.",
        "Rank by what you can show. A confirmed path with no effective check is a ConfirmedFact with "
        "its fragments. A plausible path with an unread function is a Hypothesis whose required evidence "
        "is that function. A sink never reached is a gap.",
        "Do not run, patch, or debug the target. `rea_privileged` is out of scope for this audit "
        "unless the user explicitly asks for dynamic confirmation.",
    ),
)

REVIEW: Final = Playbook(
    name="evidence-review",
    title="Review the evidence ledger",
    description="Audit an analysis in progress: check every claim against its evidence and close or declare gaps.",
    steps=(
        "Call `ledger_summary`, then `ledger_list` with `view` set to each of facts, hypotheses, gaps and "
        "imports. Page with the returned cursor; a write between pages invalidates it, so restart.",
        "For each ConfirmedFact, `ledger_get` it and re-read the cited evidence with a fresh query "
        "(use `receipt_id` and `known_hashes` so unchanged material costs almost nothing). If the "
        "database changed since, the old evidence is stale: re-check before relying on it.",
        "For each open Hypothesis, decide: is there new evidence that satisfies every required item? "
        "If yes, fetch it and `ledger_promote`. If the evidence contradicts it, `ledger_refute`. "
        "If neither, leave it open and say what is missing.",
        "For each open gap, either examine the code and `ledger_close_gap` with the evidence, or leave "
        "it open. Do not close a gap with a note alone.",
        "Look for unrecorded coverage: functions, sections and strings that no fact, hypothesis or gap "
        "mentions. Declare them as gaps.",
        "Produce the review as three lists (ConfirmedFacts, Hypotheses, UnanalyzedGaps) and a short "
        "list of claims you downgraded, with the reason for each.",
    ),
)

PLAYBOOKS: Final[tuple[Playbook, ...]] = (TRIAGE, CRYPTO, PROTOCOL, VULNERABILITY, REVIEW)
_BY_NAME: Final[Mapping[str, Playbook]] = {p.name: p for p in PLAYBOOKS}


def prompt_names() -> tuple[str, ...]:
    return tuple(p.name for p in PLAYBOOKS)


def get_playbook(name: str) -> Playbook:
    try:
        return _BY_NAME[name]
    except KeyError as exc:
        raise PromptError(f"unknown prompt {name!r}") from exc


def parse_inputs(raw: Mapping[str, str] | None) -> PromptInputs:
    """Validate prompt arguments. Unknown names are rejected rather than ignored."""
    values = dict(raw or {})
    unknown = sorted(set(values) - {a.name for a in PROMPT_ARGUMENTS})
    if unknown:
        raise PromptError(f"unknown prompt argument(s): {', '.join(unknown)}")
    try:
        for key in ("target", "focus"):
            if key in values:
                text = _TEXT.validate_python(values[key])
                if not text.strip() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
                    raise PromptError(f"{key}: must be non-empty single-line text")
                values[key] = text
        if "episode" in values:
            values["episode"] = _EPISODE.validate_python(values["episode"])
        return PromptInputs.model_validate(values)
    except ValidationError as exc:
        where = ", ".join(str(e["loc"][-1]) if e["loc"] else "value" for e in exc.errors()[:3])
        raise PromptError(f"invalid prompt argument(s): {where}") from exc


def render_prompt(name: str, raw: Mapping[str, str] | None = None) -> str:
    return get_playbook(name).render(parse_inputs(raw))
