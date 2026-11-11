"""Built-in fallback case catalog, served as ``rea://cases/{category}`` when no corpus is mounted.

Original, deliberately short method notes (one per kind of target), written for this server's
playbooks. They are guidance for choosing an approach, not a copy of any external repository: the
community collections (Awesome-REA, rea-gems, rea-case-rankings, touhou-reverse-engineering) are
meant to be cloned locally and mounted through ``REA_KNOWLEDGE_DIR``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class BuiltinCase:
    category: str
    title: str
    playbook: str
    body: str


BUILTIN_CASES: Final[tuple[BuiltinCase, ...]] = (
    BuiltinCase(
        "malware-triage", "Malware triage", "triage-binary",
        "Work from the outside in. Imports, strings and section layout usually tell you whether the "
        "sample is packed before you read any code. A tiny import table with a large high-entropy "
        "section means the real program is not on disk yet: declare a `packed_or_encrypted` gap and "
        "say so, rather than describing the stub as the program.\n\n"
        "Look for the configuration blob (C2 addresses, mutexes, keys). It is often decoded by a "
        "short routine near the entry point; find its consumers with `xrefs_to` on the decoder.\n\n"
        "Pitfalls: names recovered from a similar family are hypotheses; behavior inferred from "
        "imports alone is not observed behavior; an anti-analysis check you did not read is a gap.",
    ),
    BuiltinCase(
        "firmware-and-embedded", "Firmware and embedded targets", "triage-binary",
        "Establish the load address and architecture first; every address-based result is wrong if "
        "they are. Confirm with a known string table or vector table before trusting xrefs.\n\n"
        "Find the memory-mapped I/O accesses and the interrupt handlers; they anchor the rest. "
        "Look for update, bootloader and authentication code, and for hard-coded credentials and "
        "keys, which are common and worth recording as tagged secret candidates.\n\n"
        "Pitfalls: stripped RTOS code looks like one large function; data inside code regions "
        "produces garbage disassembly, so declare ranges you could not classify as gaps.",
    ),
    BuiltinCase(
        "crypto-and-licensing", "Crypto and license checks", "crypto-audit",
        "Identify the primitive by constants before names: S-boxes, round constants and initial "
        "values survive stripping and obfuscation. Then find where key and input come from; the "
        "weakness is usually there, not in the primitive.\n\n"
        "For license and activation checks, separate the check from its consequence. Read what the "
        "check compares and against what; do not conclude it can be bypassed from the shape of the "
        "branch alone. This server does not patch by default and nothing here asks you to.\n\n"
        "Pitfalls: a custom cipher that looks like a standard one; a constant-time claim you did not "
        "verify; reusing a key you only inferred.",
    ),
    BuiltinCase(
        "file-format-and-protocol", "File formats and network protocols", "protocol-reconstruction",
        "Start at the parser's entry and the dispatcher that switches on a type or tag; the field "
        "layouts hang off it. Confirm each layout by the read or bounds check that touches the "
        "offset, not by one sample file.\n\n"
        "Record endianness, alignment and length semantics explicitly; most reimplementation bugs "
        "are there. Capture confirmed layouts as types (with approval) so later decompilation reads "
        "better.\n\n"
        "Pitfalls: optional fields guarded by flags you have not seen set; versioned layouts; "
        "length fields that count more or less than you assumed.",
    ),
    BuiltinCase(
        "vulnerability-research", "Vulnerability research", "vulnerability-surface-audit",
        "Enumerate sources and sinks, then trace. A path is a hypothesis until every function on it "
        "has been read and the checks on the data are known. Scanner and SARIF findings are "
        "candidates for that process, not results of it.\n\n"
        "Prefer few well-evidenced findings to many guesses: each confirmed finding should cite the "
        "fragments that show the missing or ineffective check. Sinks you did not reach are gaps.\n\n"
        "Pitfalls: signed/unsigned and truncation at the boundary between the check and the use; "
        "bounds checks on a copy of a length rather than the one used; code reachable only through "
        "indirect calls.",
    ),
    BuiltinCase(
        "game-and-application-modding", "Game and application internals", "triage-binary",
        "Interoperability work: find the data structures first (entities, inventory, save files) and "
        "the functions that read and write them. Serialization code is a good start because it "
        "names every field in order.\n\n"
        "Name and type what you confirm so the database stays readable (this needs the session "
        "approval). Keep a ledger of which offsets are confirmed and which are guesses; save-file "
        "formats change between versions.\n\n"
        "Pitfalls: engine-generated code that looks hand-written; scripting layers that hold the "
        "real logic outside the native binary (declare it as a gap).",
    ),
)
