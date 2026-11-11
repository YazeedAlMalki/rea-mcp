"""Append-only, hash-chained Evidence Ledger, one per (session, episode).

Two kinds of finding, never mixed (smokinggun's confirmed-vs-hypothesis rule):

* ``Fact`` (``ConfirmedFact``): a claim backed by at least one *verified* proof: a fragment hash
  the router really sent to this session, a live receipt, or a record imported from a SARIF file.
  A ``RangeLocator`` (address/symbol range) names where the evidence lives but is never proof by
  itself, because the server cannot check it against anything.
* ``Hypothesis``: a claim plus the ``required_evidence`` that would promote or refute it. Promotion
  needs *new* verified evidence for every requirement (the basis that suggested the hypothesis does
  not count) and creates a fact; refutation needs verified evidence too.
* ``Gap`` (``UnanalyzedGap``): missing coverage. Gaps are first-class entries that stay ``open``
  until closed with evidence; ``summary()`` reports ``coverage == "has_open_gaps"`` while any exist.

State is event-sourced: every change is one ``LedgerEvent`` appended to a BLAKE3 hash chain
(``JournalLine``). Statuses are derived by replaying events, nothing is edited in place, and a
journal that fails verification is refused rather than repaired.
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Literal

from blake3 import blake3
from pydantic import ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from rea_mcp.core.fsafe import open_nofollow
from rea_mcp.core.models import (
    Address,
    Blake3Hex,
    Capability,
    Claim,
    EpisodeId,
    ErrorCategory,
    GapReason,
    ImportId,
    LedgerId,
    ReceiptId,
    ShortText,
    StrictModel,
    SymbolName,
)

GENESIS: Final = "0" * 64
MAX_EVENTS: Final = 20_000
_NonNegative = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]


class LedgerRejected(Exception):
    """A command that would break a ledger invariant. Nothing was appended."""

    def __init__(self, category: ErrorCategory, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.message = message


# --------------------------------------------------------------------------- #
# Proofs
# --------------------------------------------------------------------------- #


class FragmentProof(StrictModel):
    """A response fragment the router sent to this session (identity = its BLAKE3 hash)."""

    kind: Literal["fragment"]
    hash: Blake3Hex
    label: ShortText
    capability: Capability
    generation: _NonNegative


class ReceiptProof(StrictModel):
    """A live, non-stale receipt, frozen as a digest over the hashes it covered at record time."""

    kind: Literal["receipt"]
    receipt_id: ReceiptId
    digest: Blake3Hex
    fragments: _NonNegative
    generation: _NonNegative


class ImportProof(StrictModel):
    kind: Literal["import"]
    import_id: ImportId
    record_hash: Blake3Hex


class RangeLocator(StrictModel):
    kind: Literal["range"]
    start: Address
    end: Address
    symbol: SymbolName | None = None


VerifiedProof = Annotated[FragmentProof | ReceiptProof | ImportProof, Field(discriminator="kind")]
Proof = Annotated[
    FragmentProof | ReceiptProof | ImportProof | RangeLocator, Field(discriminator="kind")
]


def proof_key(proof: FragmentProof | ReceiptProof | ImportProof | RangeLocator) -> str:
    """Stable identity used to stop a hypothesis' own basis from 'promoting' it."""
    if isinstance(proof, FragmentProof):
        return f"fragment:{proof.hash}"
    if isinstance(proof, ReceiptProof):
        return f"receipt:{proof.digest}"
    if isinstance(proof, ImportProof):
        return f"import:{proof.import_id}:{proof.record_hash}"
    return f"range:{proof.start:x}-{proof.end:x}:{proof.symbol or ''}"


def _has_verified(proofs: Sequence[FragmentProof | ReceiptProof | ImportProof | RangeLocator]) -> bool:
    return any(not isinstance(p, RangeLocator) for p in proofs)


class Requirement(StrictModel):
    description: Claim
    suggested_capability: Capability | None = None


class Satisfied(StrictModel):
    index: Annotated[int, Field(strict=True, ge=0, le=7)]
    proof: VerifiedProof


# --------------------------------------------------------------------------- #
# Events (what is stored) and the hash-chained journal line
# --------------------------------------------------------------------------- #

Origin = Literal["analyst", "promoted", "sarif"]


class FactRecorded(StrictModel):
    type: Literal["fact"]
    id: LedgerId
    origin: Literal["analyst", "sarif"]
    claim: Claim
    proofs: Annotated[tuple[Proof, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def _needs_verified_proof(self) -> FactRecorded:
        if not _has_verified(self.proofs):
            raise ValueError("a confirmed fact needs at least one verified proof (not just a range)")
        return self


class HypothesisRecorded(StrictModel):
    type: Literal["hypothesis"]
    id: LedgerId
    claim: Claim
    requirements: Annotated[tuple[Requirement, ...], Field(min_length=1, max_length=8)]
    basis: Annotated[tuple[Proof, ...], Field(max_length=8)] = ()


class HypothesisPromoted(StrictModel):
    type: Literal["promoted"]
    hypothesis_id: LedgerId
    fact_id: LedgerId
    satisfied: Annotated[tuple[Satisfied, ...], Field(min_length=1, max_length=16)]


class HypothesisRefuted(StrictModel):
    type: Literal["refuted"]
    hypothesis_id: LedgerId
    reason: Claim
    proofs: Annotated[tuple[Proof, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def _needs_verified_proof(self) -> HypothesisRefuted:
        if not _has_verified(self.proofs):
            raise ValueError("a refutation needs at least one verified proof")
        return self


class GapDeclared(StrictModel):
    type: Literal["gap"]
    id: LedgerId
    reason: GapReason
    scope: Claim
    start: Address | None = None
    end: Address | None = None


class GapClosed(StrictModel):
    type: Literal["gap_closed"]
    gap_id: LedgerId
    note: Claim
    proofs: Annotated[tuple[Proof, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def _needs_verified_proof(self) -> GapClosed:
        if not _has_verified(self.proofs):
            raise ValueError("closing a gap needs at least one verified proof")
        return self


class SarifImported(StrictModel):
    type: Literal["sarif_import"]
    import_id: ImportId
    tool: ShortText
    file_hash: Blake3Hex
    results_seen: _NonNegative
    results_imported: _NonNegative
    results_rejected: _NonNegative
    record_hashes: Annotated[tuple[Blake3Hex, ...], Field(max_length=5_000)]


LedgerEvent = Annotated[
    FactRecorded | HypothesisRecorded | HypothesisPromoted | HypothesisRefuted
    | GapDeclared | GapClosed | SarifImported,
    Field(discriminator="type"),
]


class JournalLine(StrictModel):
    """One link of the chain: ``hash = BLAKE3(prev || canonical event JSON)``."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    seq: _NonNegative
    prev: Blake3Hex
    at: _NonNegative
    event: LedgerEvent
    hash: Blake3Hex


_LINE: Final = TypeAdapter(JournalLine)
Staged = tuple[JournalLine, ...]


def _digest(prev: str, at: int, seq: int, event_json: str) -> str:
    return blake3(f"{prev}|{seq}|{at}|{event_json}".encode()).hexdigest()


def new_id(prefix: Literal["f", "h", "g", "p", "i"], seed: str) -> str:
    """Ledger id: a one-letter kind plus 12 hex digits of BLAKE3 over a seed that includes the
    sequence number, so equal claims at different times never collide."""
    return f"{prefix}-{blake3(seed.encode()).hexdigest()[:12]}"


# --------------------------------------------------------------------------- #
# Derived views
# --------------------------------------------------------------------------- #


class FactView(StrictModel):
    id: LedgerId
    seq: _NonNegative
    origin: Origin
    claim: Claim
    proofs: tuple[Proof, ...]
    promoted_from: LedgerId | None = None


class HypothesisView(StrictModel):
    id: LedgerId
    seq: _NonNegative
    claim: Claim
    status: Literal["open", "promoted", "refuted"]
    requirements: tuple[Requirement, ...]
    basis: tuple[Proof, ...]
    satisfied_indexes: tuple[int, ...] = ()
    fact_id: LedgerId | None = None
    refutation: str | None = None


class GapView(StrictModel):
    id: LedgerId
    seq: _NonNegative
    status: Literal["open", "closed"]
    reason: GapReason
    scope: Claim
    start: Address | None = None
    end: Address | None = None
    closed_note: str | None = None


class ImportView(StrictModel):
    import_id: ImportId
    seq: _NonNegative
    tool: ShortText
    file_hash: Blake3Hex
    results_seen: _NonNegative
    results_imported: _NonNegative
    results_rejected: _NonNegative


Entry = FactView | HypothesisView | GapView | ImportView


class LedgerSummary(StrictModel):
    episode: EpisodeId
    events: _NonNegative
    head: Blake3Hex
    facts: _NonNegative
    hypotheses_open: _NonNegative
    hypotheses_promoted: _NonNegative
    hypotheses_refuted: _NonNegative
    gaps_open: _NonNegative
    gaps_closed: _NonNegative
    imports: _NonNegative
    coverage: Literal["complete", "has_open_gaps"]


# --------------------------------------------------------------------------- #
# The ledger
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _State:
    facts: OrderedDict[str, FactView]
    hypotheses: OrderedDict[str, HypothesisView]
    gaps: OrderedDict[str, GapView]
    imports: OrderedDict[str, ImportView]
    import_hashes: dict[str, frozenset[str]]


def _empty_state() -> _State:
    return _State(OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict(), {})


class EpisodeLedger:
    """In-memory view of one journal. ``stage_*`` validates and builds lines; ``commit`` applies
    them. Callers serialize writers (the router holds one write lock per backend kind)."""

    def __init__(self, episode: str, genesis: str = GENESIS) -> None:
        self.episode = episode
        self.genesis = genesis
        self._lines: list[JournalLine] = []
        self._state = _empty_state()

    # ---- identity ---------------------------------------------------------

    @property
    def head(self) -> str:
        return self._lines[-1].hash if self._lines else self.genesis

    @property
    def event_count(self) -> int:
        return len(self._lines)

    @property
    def lines(self) -> tuple[JournalLine, ...]:
        return tuple(self._lines)

    @classmethod
    def replay(cls, episode: str, lines: Iterable[JournalLine], genesis: str = GENESIS) -> EpisodeLedger:
        """Rebuild from a journal, verifying the chain and every invariant. Raises on any defect."""
        ledger = cls(episode, genesis)
        for line in lines:
            if line.seq != len(ledger._lines) or line.prev != ledger.head:
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "journal chain is broken")
            expected = _digest(line.prev, line.at, line.seq, line.event.model_dump_json())
            if line.hash != expected:
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "journal line hash mismatch")
            ledger._check(line.event, ledger._pending_imports(()))
            ledger._apply(line)
            ledger._lines.append(line)
        return ledger

    # ---- staging ----------------------------------------------------------

    def stage(self, events: Sequence[LedgerEvent], at: int) -> Staged:
        """Validate ``events`` against the committed state (plus earlier events of the same
        batch) and chain them. Nothing changes until ``commit``."""
        if len(self._lines) + len(events) > MAX_EVENTS:
            raise LedgerRejected(ErrorCategory.CAPACITY_EXHAUSTED, f"ledger is limited to {MAX_EVENTS} events")
        staged: list[JournalLine] = []
        prev, seq = self.head, len(self._lines)
        for index, event in enumerate(events):
            self._check(event, self._pending_imports(events[:index]), self._pending_ids(events[:index]))
            line = JournalLine(
                seq=seq, prev=prev, at=at, event=event,
                hash=_digest(prev, at, seq, event.model_dump_json()),
            )
            staged.append(line)
            prev, seq = line.hash, seq + 1
        return tuple(staged)

    def commit(self, staged: Staged) -> None:
        for line in staged:
            if line.seq != len(self._lines) or line.prev != self.head:
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "ledger moved since the lines were staged")
            self._apply(line)
            self._lines.append(line)

    # ---- command builders (pure) -----------------------------------------

    def fact(
        self, claim: str, proofs: tuple[Proof, ...], *, origin: Literal["analyst", "sarif"] = "analyst",
        slot: int = 0,
    ) -> FactRecorded:
        """``slot`` distinguishes events staged in the same batch (they share ``len(lines)``)."""
        return FactRecorded(
            type="fact",
            id=new_id("i" if origin == "sarif" else "f", f"{self.episode}|{len(self._lines)}|{slot}|{claim}"),
            origin=origin, claim=claim, proofs=proofs,
        )

    def hypothesis(
        self, claim: str, requirements: tuple[Requirement, ...], basis: tuple[Proof, ...]
    ) -> HypothesisRecorded:
        return HypothesisRecorded(
            type="hypothesis", id=new_id("h", f"{self.episode}|{len(self._lines)}|{claim}"),
            claim=claim, requirements=requirements, basis=basis,
        )

    def promotion(self, hypothesis_id: str, satisfied: tuple[Satisfied, ...]) -> HypothesisPromoted:
        return HypothesisPromoted(
            type="promoted", hypothesis_id=hypothesis_id,
            fact_id=new_id("p", f"{self.episode}|{len(self._lines)}|{hypothesis_id}"),
            satisfied=satisfied,
        )

    def gap(
        self, reason: GapReason, scope: str, start: int | None, end: int | None, *, slot: int = 0
    ) -> GapDeclared:
        return GapDeclared(
            type="gap", id=new_id("g", f"{self.episode}|{len(self._lines)}|{slot}|{reason}|{scope}"),
            reason=reason, scope=scope, start=start, end=end,
        )

    # ---- invariants -------------------------------------------------------

    def _pending_imports(self, earlier: Sequence[LedgerEvent]) -> dict[str, frozenset[str]]:
        pending = dict(self._state.import_hashes)
        for event in earlier:
            if isinstance(event, SarifImported):
                pending[event.import_id] = frozenset(event.record_hashes)
        return pending

    @staticmethod
    def _pending_ids(earlier: Sequence[LedgerEvent]) -> frozenset[str]:
        ids: set[str] = set()
        for event in earlier:
            if isinstance(event, (FactRecorded, HypothesisRecorded, GapDeclared)):
                ids.add(event.id)
            elif isinstance(event, HypothesisPromoted):
                ids.add(event.fact_id)
        return frozenset(ids)

    def _taken(self, entry_id: str, extra: frozenset[str]) -> bool:
        s = self._state
        return entry_id in extra or entry_id in s.facts or entry_id in s.hypotheses or entry_id in s.gaps

    def _check(
        self,
        event: LedgerEvent,
        imports: dict[str, frozenset[str]],
        extra_ids: frozenset[str] = frozenset(),
    ) -> None:
        s = self._state
        if isinstance(event, FactRecorded):
            if self._taken(event.id, extra_ids):
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "duplicate ledger id")
            self._check_imports(event.proofs, imports)
        elif isinstance(event, HypothesisRecorded):
            if self._taken(event.id, extra_ids):
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "duplicate ledger id")
            self._check_imports(event.basis, imports)
        elif isinstance(event, HypothesisPromoted):
            hyp = self._open_hypothesis(event.hypothesis_id)
            if self._taken(event.fact_id, extra_ids):
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "duplicate ledger id")
            covered = {sat.index for sat in event.satisfied}
            wanted = set(range(len(hyp.requirements)))
            if covered != wanted:
                missing = sorted(wanted - covered)
                extra = sorted(covered - wanted)
                raise LedgerRejected(
                    ErrorCategory.EVIDENCE_REJECTED,
                    f"every requirement needs evidence; missing {missing}"
                    + (f", unknown {extra}" if extra else ""),
                )
            basis_keys = {proof_key(p) for p in hyp.basis}
            for sat in event.satisfied:
                if proof_key(sat.proof) in basis_keys:
                    raise LedgerRejected(
                        ErrorCategory.EVIDENCE_REJECTED,
                        f"requirement {sat.index} cannot be satisfied by the evidence that suggested the hypothesis",
                    )
            self._check_imports(tuple(sat.proof for sat in event.satisfied), imports)
        elif isinstance(event, HypothesisRefuted):
            self._open_hypothesis(event.hypothesis_id)
            self._check_imports(event.proofs, imports)
        elif isinstance(event, GapDeclared):
            if self._taken(event.id, extra_ids):
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "duplicate ledger id")
            if (event.start is None) != (event.end is None):
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "gap range needs both start and end")
        elif isinstance(event, GapClosed):
            gap = s.gaps.get(event.gap_id)
            if gap is None:
                raise LedgerRejected(ErrorCategory.NOT_FOUND, "no such gap")
            if gap.status != "open":
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "gap is already closed")
            self._check_imports(event.proofs, imports)
        else:
            if event.import_id in s.imports:
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "import id already used")
            if event.results_imported + event.results_rejected > event.results_seen:
                raise LedgerRejected(ErrorCategory.INVALID_STATE, "import counts are inconsistent")

    def _open_hypothesis(self, hypothesis_id: str) -> HypothesisView:
        hyp = self._state.hypotheses.get(hypothesis_id)
        if hyp is None:
            raise LedgerRejected(ErrorCategory.NOT_FOUND, "no such hypothesis")
        if hyp.status != "open":
            raise LedgerRejected(ErrorCategory.INVALID_STATE, f"hypothesis is already {hyp.status}")
        return hyp

    @staticmethod
    def _check_imports(
        proofs: Sequence[FragmentProof | ReceiptProof | ImportProof | RangeLocator],
        imports: dict[str, frozenset[str]],
    ) -> None:
        for proof in proofs:
            if isinstance(proof, ImportProof):
                hashes = imports.get(proof.import_id)
                if hashes is None or proof.record_hash not in hashes:
                    raise LedgerRejected(
                        ErrorCategory.EVIDENCE_REJECTED, "import record is not in this episode's ledger"
                    )

    # ---- apply ------------------------------------------------------------

    def _apply(self, line: JournalLine) -> None:
        s, event, seq = self._state, line.event, line.seq
        if isinstance(event, FactRecorded):
            s.facts[event.id] = FactView(
                id=event.id, seq=seq, origin=event.origin, claim=event.claim, proofs=event.proofs
            )
        elif isinstance(event, HypothesisRecorded):
            s.hypotheses[event.id] = HypothesisView(
                id=event.id, seq=seq, claim=event.claim, status="open",
                requirements=event.requirements, basis=event.basis,
            )
        elif isinstance(event, HypothesisPromoted):
            hyp = s.hypotheses[event.hypothesis_id]
            s.hypotheses[hyp.id] = hyp.model_copy(update={
                "status": "promoted", "fact_id": event.fact_id,
                "satisfied_indexes": tuple(sorted(sat.index for sat in event.satisfied)),
            })
            s.facts[event.fact_id] = FactView(
                id=event.fact_id, seq=seq, origin="promoted", claim=hyp.claim,
                proofs=tuple(sat.proof for sat in event.satisfied), promoted_from=hyp.id,
            )
        elif isinstance(event, HypothesisRefuted):
            hyp = s.hypotheses[event.hypothesis_id]
            s.hypotheses[hyp.id] = hyp.model_copy(update={"status": "refuted", "refutation": event.reason})
        elif isinstance(event, GapDeclared):
            s.gaps[event.id] = GapView(
                id=event.id, seq=seq, status="open", reason=event.reason, scope=event.scope,
                start=event.start, end=event.end,
            )
        elif isinstance(event, GapClosed):
            gap = s.gaps[event.gap_id]
            s.gaps[gap.id] = gap.model_copy(update={"status": "closed", "closed_note": event.note})
        else:
            s.imports[event.import_id] = ImportView(
                import_id=event.import_id, seq=seq, tool=event.tool, file_hash=event.file_hash,
                results_seen=event.results_seen, results_imported=event.results_imported,
                results_rejected=event.results_rejected,
            )
            s.import_hashes[event.import_id] = frozenset(event.record_hashes)

    # ---- queries ----------------------------------------------------------

    def find_import(self, file_hash: str) -> ImportView | None:
        return next((i for i in self._state.imports.values() if i.file_hash == file_hash), None)

    def get(self, entry_id: str) -> Entry | None:
        s = self._state
        return s.facts.get(entry_id) or s.hypotheses.get(entry_id) or s.gaps.get(entry_id) or s.imports.get(entry_id)

    def entries(
        self,
        view: Literal["all", "facts", "hypotheses", "gaps", "imports"],
        status: Literal["any", "open", "promoted", "refuted", "closed"],
    ) -> list[Entry]:
        s = self._state
        pool: list[Entry] = []
        if view in {"all", "facts"}:
            pool.extend(s.facts.values())
        if view in {"all", "hypotheses"}:
            pool.extend(s.hypotheses.values())
        if view in {"all", "gaps"}:
            pool.extend(s.gaps.values())
        if view in {"all", "imports"}:
            pool.extend(s.imports.values())
        pool.sort(key=lambda e: e.seq)
        if status == "any":
            return pool
        return [e for e in pool if getattr(e, "status", None) == status]

    def summary(self) -> LedgerSummary:
        s = self._state
        hyps = list(s.hypotheses.values())
        open_gaps = sum(1 for g in s.gaps.values() if g.status == "open")
        return LedgerSummary(
            episode=self.episode, events=len(self._lines), head=self.head, facts=len(s.facts),
            hypotheses_open=sum(1 for h in hyps if h.status == "open"),
            hypotheses_promoted=sum(1 for h in hyps if h.status == "promoted"),
            hypotheses_refuted=sum(1 for h in hyps if h.status == "refuted"),
            gaps_open=open_gaps, gaps_closed=len(s.gaps) - open_gaps, imports=len(s.imports),
            coverage="has_open_gaps" if open_gaps else "complete",
        )


# --------------------------------------------------------------------------- #
# Durable journal (optional; REA_LEDGER_DIR)
# --------------------------------------------------------------------------- #


class JournalHeader(StrictModel):
    """First record of every journal file. ``genesis`` (the chain's starting hash) commits to the
    workspace, session and episode, so a journal cannot be replayed against another target tree."""

    type: Literal["journal"]
    version: Literal[1]
    session: ShortText
    episode: EpisodeId
    workspace_fingerprint: Blake3Hex
    genesis: Blake3Hex


def journal_genesis(session: str, episode: str, fingerprint: str) -> str:
    return blake3(f"rea-ledger-v1|{fingerprint}|{session}|{episode}".encode()).hexdigest()


class Journal:
    """JSONL file, mode 0600: a header record, then the hash chain, one fsync per staged batch.

    Loading verifies the header (self-consistent, same session and episode, same workspace unless
    ``allow_foreign_workspace``) and then the whole chain."""

    def __init__(
        self, path: Path, *, session: str, episode: str, workspace_fingerprint: str,
        allow_foreign_workspace: bool = False,
    ) -> None:
        self._path = path
        self._session = session
        self._episode = episode
        self._fingerprint = workspace_fingerprint
        self._allow_foreign = allow_foreign_workspace

    @property
    def path(self) -> Path:
        return self._path

    def header(self) -> JournalHeader:
        return JournalHeader(
            type="journal", version=1, session=self._session, episode=self._episode,
            workspace_fingerprint=self._fingerprint,
            genesis=journal_genesis(self._session, self._episode, self._fingerprint),
        )

    def load(self, episode: str) -> EpisodeLedger:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return EpisodeLedger(episode, self.header().genesis)
        lines: list[JournalLine] = []
        try:
            with self._path.open("rb") as handle:
                header = JournalHeader.model_validate_json(handle.readline())
                for raw in handle:
                    lines.append(_LINE.validate_json(raw))
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise LedgerRejected(ErrorCategory.INVALID_STATE, "ledger journal is unreadable or corrupt") from exc
        if header.genesis != journal_genesis(header.session, header.episode, header.workspace_fingerprint):
            raise LedgerRejected(ErrorCategory.INVALID_STATE, "journal header was altered")
        if header.session != self._session or header.episode != self._episode:
            raise LedgerRejected(ErrorCategory.INVALID_STATE, "journal belongs to another session or episode")
        if header.workspace_fingerprint != self._fingerprint and not self._allow_foreign:
            raise LedgerRejected(
                ErrorCategory.INVALID_STATE,
                "journal was written for a different workspace (REA_ALLOWED_ROOTS changed); "
                "set REA_LEDGER_ALLOW_WORKSPACE_MISMATCH=1 to load it anyway",
            )
        return EpisodeLedger.replay(episode, lines, header.genesis)

    def append(self, staged: Staged) -> None:
        payload = "".join(line.model_dump_json() + "\n" for line in staged).encode()
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = open_nofollow(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                if os.fstat(fd).st_size == 0:
                    payload = (self.header().model_dump_json() + "\n").encode() + payload
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise LedgerRejected(ErrorCategory.BACKEND_ERROR, "could not write the ledger journal") from exc
