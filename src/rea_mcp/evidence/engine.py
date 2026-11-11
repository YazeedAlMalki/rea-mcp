"""The evidence engine: a pseudo-backend the router dispatches the 13 evidence capabilities to.

It adds no top-level MCP tool. ``source_*`` / ``scan_hotspots`` / ``ledger_{list,get,summary}`` ride
``rea_query``; ``ledger_record_*`` / ``promote`` / ``refute`` / gaps / ``import_sarif`` ride
``rea_mutate``. The router does the generic work (strict parsing, tiers, consent, cursors,
redaction, BLAKE3 fragment hashing, ``known_hashes`` / ``expected_hash`` / receipts, budgets); the
engine only produces ``BackendItem`` s and verifies evidence references against the router's own
delivery record (``EvidenceLookup``), so an LLM cannot label a hallucination as a confirmed fact.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final

from blake3 import blake3
from pydantic import ValidationError

from rea_mcp.core.models import (
    EVIDENCE_CAPABILITIES,
    MAX_SLICE_LINES,
    BackendItem,
    BackendKind,
    BackendResult,
    Capability,
    CloseGapArgs,
    DeclareGapArgs,
    DecompileTarget,
    ErrorCategory,
    EvidenceRef,
    FileTarget,
    FragmentEvidence,
    ImportEvidence,
    ImportSarifArgs,
    LedgerGetArgs,
    LedgerListArgs,
    LedgerSummaryArgs,
    PromoteArgs,
    RangeEvidence,
    ReceiptEvidence,
    RecordFactArgs,
    RecordHypothesisArgs,
    RefuteArgs,
    ScanHotspotsArgs,
    SourceOutlineArgs,
    SourceReadArgs,
    TreeTarget,
    VerifiableRef,
)
from rea_mcp.core.paging import GenerationCounter, window
from rea_mcp.core.router import BackendCall, EvidenceLookup, RefusedError
from rea_mcp.core.security import SecurityDenied, SecurityPolicy, resolve_under_roots
from rea_mcp.evidence.ledger import (
    EpisodeLedger,
    Entry,
    FactView,
    FragmentProof,
    GapClosed,
    GapView,
    HypothesisRefuted,
    HypothesisView,
    ImportProof,
    ImportView,
    Journal,
    LedgerEvent,
    LedgerRejected,
    LedgerSummary,
    Proof,
    RangeLocator,
    ReceiptProof,
    Requirement,
    SarifImported,
    Satisfied,
    VerifiedProof,
)
from rea_mcp.evidence.leantoken_index import (
    SOURCE_SUFFIXES,
    IndexedSource,
    SourceSkipped,
    Symbol,
    index_source,
    index_text,
    language_for,
    read_capped,
)
from rea_mcp.evidence.scanner import (
    MAX_SARIF_BYTES,
    Hotspot,
    SarifBatch,
    SarifRejected,
    ScanReport,
    list_tree,
    order_hotspots,
    parse_sarif,
    scan_listing,
    scan_pseudocode,
    single_file_listing,
)

SYMBOLS_PER_ITEM: Final = 25
HOTSPOTS_PER_ITEM: Final = 25
MAX_EPISODES_PER_SESSION: Final = 16
MAX_LEDGERS: Final = 256
INDEX_CACHE: Final = 32
SCAN_CACHE: Final = 8
_KIND_CODE: Final = {
    "function": "f", "method": "m", "struct": "S", "union": "U", "enum": "E", "class": "C",
    "interface": "I", "trait": "T", "namespace": "N", "global": "g", "macro": "#",
}
_LEGEND: Final = "f=function m=method S=struct U=union E=enum C=class I=interface T=trait N=namespace g=global #=macro"
_SEV: Final = {"high": "high", "medium": "med", "low": "low", "info": "info"}


def _short(digest: str) -> str:
    return digest[:16]


def _item(label: str, text: str) -> BackendItem:
    return BackendItem(label=label[:256], text=text)


class EvidenceEngine:
    """Implements ``DisassemblerBackend`` (kind ``evidence``)."""

    def __init__(self, policy: SecurityPolicy, *, clock: Callable[[], float] = time.time) -> None:
        self._policy = policy
        self._clock = clock
        self._source_gen = GenerationCounter()
        self._ledger_gen = GenerationCounter()
        self._seen: dict[str, str] = {}
        self._ledgers: dict[tuple[str, str], EpisodeLedger] = {}
        self._journals: dict[tuple[str, str], Journal] = {}
        self._write_lock = asyncio.Lock()
        self._index_cache: OrderedDict[tuple[Path, int, int], IndexedSource] = OrderedDict()
        self._scan_cache: OrderedDict[tuple[str, str, int, str], ScanReport] = OrderedDict()

    # ---- DisassemblerBackend ------------------------------------------------

    @property
    def kind(self) -> BackendKind:
        return BackendKind.EVIDENCE

    def supports(self, capability: Capability) -> bool:
        return capability in EVIDENCE_CAPABILITIES

    async def execute(self, call: BackendCall) -> BackendResult:
        args = call.args
        try:
            if isinstance(args, SourceOutlineArgs):
                return await self._outline(call, args)
            if isinstance(args, SourceReadArgs):
                return await self._read(call, args)
            if isinstance(args, ScanHotspotsArgs):
                return await self._scan(call, args)
            if isinstance(args, LedgerSummaryArgs):
                return await self._ledger_summary(call, args)
            if isinstance(args, LedgerGetArgs):
                return await self._ledger_get(call, args)
            if isinstance(args, LedgerListArgs):
                return await self._ledger_list(call, args)
            if isinstance(args, ImportSarifArgs):
                return await self._import_sarif(call, args)
            return await self._write(call)
        except LedgerRejected as rejected:
            raise RefusedError(rejected.category, rejected.message) from rejected
        except ValidationError as invalid:  # a ledger invariant enforced by the model itself
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "ledger entry failed validation") from invalid

    # ---- generation ---------------------------------------------------------

    def _observe(self, label: str, digest: str) -> None:
        """Bump the source generation only when something already seen has changed."""
        previous = self._seen.get(label)
        self._seen[label] = digest
        if previous is not None and previous != digest:
            self._source_gen.bump()

    # ---- source targets -----------------------------------------------------

    def _file(self, raw: str, *, directory: bool = False) -> Path:
        try:
            path = resolve_under_roots(raw, self._policy.allowed_roots)
        except SecurityDenied as denied:
            raise RefusedError(denied.category, denied.message) from denied
        if directory != path.is_dir() or not (path.is_dir() or path.is_file()):
            raise RefusedError(
                ErrorCategory.INVALID_REQUEST, "expected a directory" if directory else "expected a regular file"
            )
        return path

    def _display(self, path: Path) -> str:
        for root in self._policy.allowed_roots:
            if path.is_relative_to(root):
                return path.relative_to(root).as_posix() or path.name
        return path.name

    async def _load(self, target: FileTarget | DecompileTarget, call: BackendCall) -> IndexedSource:
        if isinstance(target, DecompileTarget):
            if call.payload is None:
                raise RefusedError(ErrorCategory.BACKEND_UNAVAILABLE, "no decompiler output was supplied")
            try:
                src = index_text(call.payload.label, call.payload.text)
            except SourceSkipped as skip:
                raise RefusedError(ErrorCategory.INVALID_REQUEST, f"cannot index pseudocode: {skip.detail}") from skip
            self._observe(src.label, src.content_hash)
            return src
        path = self._file(target.path)
        language = language_for(path.suffix.lower())
        if language is None:
            raise RefusedError(
                ErrorCategory.INVALID_REQUEST,
                f"unsupported file type {path.suffix or '(none)'}; supported: {', '.join(sorted(SOURCE_SUFFIXES))}",
            )
        info = path.stat()
        key = (path, info.st_size, info.st_mtime_ns)
        cached = self._index_cache.get(key)
        if cached is None:
            label = self._display(path)
            try:
                data = await asyncio.to_thread(read_capped, path)
                cached = await asyncio.to_thread(index_source, label, data, language)
            except SourceSkipped as skip:
                raise RefusedError(ErrorCategory.INVALID_REQUEST, f"cannot index {label}: {skip.reason}: {skip.detail}") from skip
            self._index_cache[key] = cached
            while len(self._index_cache) > INDEX_CACHE:
                self._index_cache.popitem(last=False)
        self._index_cache.move_to_end(key)
        self._observe(str(path), cached.content_hash)
        return cached

    # ---- source_outline -----------------------------------------------------

    async def _outline(self, call: BackendCall, args: SourceOutlineArgs) -> BackendResult:
        src = await self._load(args.target, call)
        chunks = [src.symbols[i : i + SYMBOLS_PER_ITEM] for i in range(0, len(src.symbols), SYMBOLS_PER_ITEM)] or [()]
        items: list[BackendItem] = []
        base = src.label.rsplit("/", 1)[-1]
        for index, chunk in enumerate(chunks):
            lines: list[str] = []
            if index == 0:
                lines.append(
                    f"{src.label} {src.language} sha={_short(src.content_hash)} lines={src.line_count} "
                    f"bytes={len(src.data)} symbols={len(src.symbols)}"
                )
                lines.append(_LEGEND)
                lines.extend(f"note: {note}" for note in src.notes)
                if not src.symbols:
                    lines.append("no symbols recognised; use source_read with a line range")
            lines.extend(_symbol_line(s) for s in chunk)
            items.append(_item(f"outline:{base}#{index}", "\n".join(lines)))
        return window(items[call.offset : call.offset + args.limit + 1], args.limit, call.offset, self._source_gen.value)

    # ---- source_read --------------------------------------------------------

    async def _read(self, call: BackendCall, args: SourceReadArgs) -> BackendResult:
        src = await self._load(args.target, call)
        name = src.label.rsplit("/", 1)[-1]
        if args.symbol is not None:
            matches = [s for s in src.symbols if s.name == args.symbol]
            if not matches:
                raise RefusedError(
                    ErrorCategory.NOT_FOUND, f"no symbol {args.symbol!r} in {src.label}; call source_outline"
                )
            if len(matches) > 1:
                spots = ", ".join(f"L{m.start_line}" for m in matches[:6])
                raise RefusedError(
                    ErrorCategory.INVALID_REQUEST,
                    f"symbol {args.symbol!r} is ambiguous ({len(matches)} matches at {spots}); use a line range",
                )
            first, last = matches[0].start_line, matches[0].end_line
            name = args.symbol
        else:
            first, last = args.start_line or 1, args.end_line or 1
            if first > src.line_count:
                raise RefusedError(
                    ErrorCategory.INVALID_REQUEST, f"start_line {first} is past the end ({src.line_count} lines)"
                )
        first, last = max(1, first - args.context_lines), min(src.line_count, last + args.context_lines)
        if last - first + 1 > MAX_SLICE_LINES:
            raise RefusedError(
                ErrorCategory.INVALID_REQUEST,
                f"slice spans {last - first + 1} lines (max {MAX_SLICE_LINES}); read a narrower line range",
            )
        text = src.slice_lines(first, last)
        label = f"{name[:120]}:L{first}-{last}@{src.content_hash[:12]}"
        return BackendResult(items=(_item(label, text),), generation=self._source_gen.value)

    # ---- scan_hotspots ------------------------------------------------------

    async def _scan(self, call: BackendCall, args: ScanHotspotsArgs) -> BackendResult:
        report = await self._report(call, args)
        ordered = order_hotspots(report)
        groups: list[tuple[str, tuple[Hotspot, ...]]] = []
        index = 0
        while index < len(ordered):
            path = ordered[index].path
            end = index
            while end < len(ordered) and ordered[end].path == path and end - index < HOTSPOTS_PER_ITEM:
                end += 1
            groups.append((path, ordered[index:end]))
            index = end
        items = [_item("scan:coverage", _coverage_text(report, len(ordered)))]
        items.extend(
            _item(f"scan:{path[-120:]}#{n}", "\n".join(_hotspot_line(h) for h in group))
            for n, (path, group) in enumerate(groups)
        )
        return window(items[call.offset : call.offset + args.limit + 1], args.limit, call.offset, self._source_gen.value)

    async def _report(self, call: BackendCall, args: ScanHotspotsArgs) -> ScanReport:
        target = args.target
        if isinstance(target, DecompileTarget):
            if call.payload is None:
                raise RefusedError(ErrorCategory.BACKEND_UNAVAILABLE, "no decompiler output was supplied")
            report = scan_pseudocode(call.payload.label, call.payload.text, args.min_severity)
        else:
            path = self._file(target.path, directory=isinstance(target, TreeTarget))
            label = self._display(path)
            if isinstance(target, TreeTarget):
                listing = await asyncio.to_thread(list_tree, path, args.max_files)
            else:
                listing = single_file_listing(path, label)
            key = (str(path), args.min_severity, args.max_files, listing.fingerprint)
            cached = self._scan_cache.get(key)
            if cached is None:
                cached = await asyncio.to_thread(scan_listing, label, listing, args.min_severity)
                self._scan_cache[key] = cached
                while len(self._scan_cache) > SCAN_CACHE:
                    self._scan_cache.popitem(last=False)
            self._scan_cache.move_to_end(key)
            report = cached
            self._observe(f"scan:{path}", report.digest)
            return report
        self._observe(f"scan:{report.label}", report.digest)
        return report

    # ---- ledger reads -------------------------------------------------------

    async def _ledger(self, session_id: str, episode: str, *, create: bool) -> EpisodeLedger:
        key = (session_id, episode)
        existing = self._ledgers.get(key)
        if existing is not None:
            return existing
        journal = self._journal(key)
        ledger = await asyncio.to_thread(journal.load, episode) if journal is not None else EpisodeLedger(episode)
        if not create and ledger.event_count == 0:
            return ledger  # a read of an empty episode registers nothing
        used = sum(1 for sid, _ in self._ledgers if sid == session_id)
        if used >= MAX_EPISODES_PER_SESSION or len(self._ledgers) >= MAX_LEDGERS:
            raise RefusedError(ErrorCategory.CAPACITY_EXHAUSTED, "too many open episodes for this session")
        self._ledgers[key] = ledger
        return ledger

    def _journal(self, key: tuple[str, str]) -> Journal | None:
        directory = self._policy.ledger_dir
        if directory is None:
            return None
        journal = self._journals.get(key)
        if journal is None:
            journal = Journal(
                directory / f"{key[0]}__{key[1]}.jsonl", session=key[0], episode=key[1],
                workspace_fingerprint=self._policy.workspace_fingerprint(),
                allow_foreign_workspace=self._policy.ledger_allow_foreign_workspace,
            )
            self._journals[key] = journal
        return journal

    async def _ledger_summary(self, call: BackendCall, args: LedgerSummaryArgs) -> BackendResult:
        ledger = await self._ledger(call.session_id, args.episode, create=False)
        return BackendResult(
            items=(_item(f"ledger:{args.episode}:summary", _summary_text(ledger.summary())),),
            generation=self._ledger_gen.value,
        )

    async def _ledger_get(self, call: BackendCall, args: LedgerGetArgs) -> BackendResult:
        ledger = await self._ledger(call.session_id, args.episode, create=False)
        entry = ledger.get(args.entry_id)
        if entry is None:
            raise RefusedError(ErrorCategory.NOT_FOUND, f"no ledger entry {args.entry_id} in episode {args.episode}")
        return BackendResult(items=(_entry_item(entry),), generation=self._ledger_gen.value)

    async def _ledger_list(self, call: BackendCall, args: LedgerListArgs) -> BackendResult:
        ledger = await self._ledger(call.session_id, args.episode, create=False)
        entries = ledger.entries(args.view, args.status)
        page = entries[call.offset : call.offset + args.limit + 1]
        return window([_entry_item(e) for e in page], args.limit, call.offset, self._ledger_gen.value)

    # ---- ledger writes ------------------------------------------------------

    async def _commit(
        self, call: BackendCall, episode: str, ledger: EpisodeLedger, events: Sequence[LedgerEvent]
    ) -> None:
        staged = ledger.stage(events, int(self._clock()))
        journal = self._journal((call.session_id, episode))
        if journal is not None:
            await asyncio.to_thread(journal.append, staged)  # durable before visible
        ledger.commit(staged)
        self._ledgers.setdefault((call.session_id, episode), ledger)
        self._ledger_gen.bump()

    def _proofs(
        self, refs: Sequence[EvidenceRef], lookup: EvidenceLookup | None
    ) -> tuple[Proof, ...]:
        out: list[Proof] = []
        for ref in refs:
            proof = self._proof(ref, lookup)
            if proof not in out:
                out.append(proof)
        return tuple(out)

    @staticmethod
    def _proof(ref: EvidenceRef | VerifiableRef, lookup: EvidenceLookup | None) -> Proof:
        if isinstance(ref, RangeEvidence):
            return RangeLocator(kind="range", start=ref.start, end=ref.end, symbol=ref.symbol)
        if isinstance(ref, ImportEvidence):
            return ImportProof(kind="import", import_id=ref.import_id, record_hash=ref.record_hash)
        if lookup is None:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "no delivery record is available to verify evidence")
        if isinstance(ref, FragmentEvidence):
            sent = lookup.fragment(ref.hash)
            if sent is None:
                raise RefusedError(
                    ErrorCategory.EVIDENCE_REJECTED,
                    f"fragment {_short(ref.hash)} was not sent to this session (or has been evicted); read it again",
                )
            return FragmentProof(
                kind="fragment", hash=sent.digest, label=sent.label, capability=sent.capability,
                generation=sent.generation,
            )
        info = lookup.receipt(ref.receipt_id)
        if info is None:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "receipt is unknown, expired, or not citable")
        if not info.fresh:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "receipt is stale; the data behind it changed")
        if info.fragments == 0:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "receipt covers no fragments")
        return ReceiptProof(
            kind="receipt", receipt_id=info.receipt_id, digest=info.digest, fragments=info.fragments,
            generation=info.generation,
        )

    @staticmethod
    def _need_verified(proofs: tuple[Proof, ...]) -> tuple[Proof, ...]:
        if all(isinstance(p, RangeLocator) for p in proofs):
            raise RefusedError(
                ErrorCategory.EVIDENCE_REJECTED,
                "an address range only says where evidence lives; add a fragment, receipt or import reference",
            )
        return proofs

    def _verified(self, ref: VerifiableRef, lookup: EvidenceLookup | None) -> VerifiedProof:
        proof = self._proof(ref, lookup)
        if isinstance(proof, RangeLocator):  # unreachable: VerifiableRef excludes ranges
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, "a range is not verifiable evidence")
        return proof

    async def _write(self, call: BackendCall) -> BackendResult:
        args = call.args
        async with self._write_lock:
            if isinstance(args, RecordFactArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=True)
                proofs = self._need_verified(self._proofs(args.evidence, call.lookup))
                event = ledger.fact(args.claim, proofs)
                await self._commit(call, args.episode, ledger, [event])
                return self._ack(f"recorded confirmed fact {event.id} ({_proof_words(proofs)})")
            if isinstance(args, RecordHypothesisArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=True)
                basis = self._proofs(args.basis, call.lookup)
                requirements = tuple(
                    Requirement(description=r.description, suggested_capability=r.suggested_capability)
                    for r in args.required_evidence
                )
                hyp = ledger.hypothesis(args.claim, requirements, basis)
                await self._commit(call, args.episode, ledger, [hyp])
                return self._ack(
                    f"recorded hypothesis {hyp.id}: NOT a fact; needs evidence for {len(requirements)} requirement(s)"
                )
            if isinstance(args, PromoteArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=False)
                satisfied = tuple(
                    Satisfied(index=s.requirement_index, proof=self._verified(s.evidence, call.lookup))
                    for s in args.satisfies
                )
                promotion = ledger.promotion(args.hypothesis_id, satisfied)
                await self._commit(call, args.episode, ledger, [promotion])
                return self._ack(f"promoted {args.hypothesis_id} -> confirmed fact {promotion.fact_id}")
            if isinstance(args, RefuteArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=False)
                refuted = _refuted(args.hypothesis_id, args.reason, self._need_verified(self._proofs(args.evidence, call.lookup)))
                await self._commit(call, args.episode, ledger, [refuted])
                return self._ack(f"refuted {args.hypothesis_id}")
            if isinstance(args, DeclareGapArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=True)
                gap = ledger.gap(args.reason, args.scope, args.start, args.end)
                await self._commit(call, args.episode, ledger, [gap])
                return self._ack(f"declared unanalyzed gap {gap.id} ({args.reason}); coverage stays incomplete until it is closed")
            if isinstance(args, CloseGapArgs):
                ledger = await self._ledger(call.session_id, args.episode, create=False)
                closed = _gap_closed(args.gap_id, args.note, self._need_verified(self._proofs(args.evidence, call.lookup)))
                await self._commit(call, args.episode, ledger, [closed])
                return self._ack(f"closed gap {args.gap_id}")
        raise RefusedError(ErrorCategory.UNSUPPORTED_CAPABILITY, "unsupported evidence operation")

    def _ack(self, text: str) -> BackendResult:
        return BackendResult(items=(_item("ledger:ack", text),), generation=self._ledger_gen.value)

    # ---- SARIF import -------------------------------------------------------

    async def _import_sarif(self, call: BackendCall, args: ImportSarifArgs) -> BackendResult:
        roots = self._policy.allowed_roots
        path = self._file(args.path)
        try:
            root = resolve_under_roots(args.source_root, roots) if args.source_root is not None else path.parent
        except SecurityDenied as denied:
            raise RefusedError(denied.category, denied.message) from denied
        if not root.is_dir():
            raise RefusedError(ErrorCategory.INVALID_REQUEST, "source_root must be a directory")
        try:
            data = await asyncio.to_thread(read_capped, path, MAX_SARIF_BYTES)
            batch = await asyncio.to_thread(
                lambda: parse_sarif(data, source_root=root, roots=roots, max_results=args.max_results)
            )
        except SourceSkipped as skip:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, f"cannot read SARIF file: {skip.detail}") from skip
        except SarifRejected as rejected:
            raise RefusedError(ErrorCategory.EVIDENCE_REJECTED, str(rejected)) from rejected
        async with self._write_lock:
            ledger = await self._ledger(call.session_id, args.episode, create=True)
            previous = ledger.find_import(batch.file_hash)
            if previous is not None:
                raise RefusedError(
                    ErrorCategory.INVALID_STATE,
                    f"this SARIF file was already imported into episode {args.episode} as {previous.import_id}",
                )
            events, import_id, gap_ids = _import_events(ledger, batch, args.episode, call.session_id)
            await self._commit(call, args.episode, ledger, events)
        reasons = ", ".join(f"{name}×{n}" for name, n in batch.rejected) or "none"
        text = (
            f"imported SARIF import_id={import_id} tool={batch.tool} seen={batch.seen} "
            f"imported={len(batch.findings)} rejected={sum(n for _, n in batch.rejected)} ({reasons}) "
            f"duplicates={batch.duplicates} not_imported_over_max={batch.truncated}"
        )
        if gap_ids:
            text += f"; opened gaps {', '.join(gap_ids)} (coverage incomplete)"
        return self._ack(text)


# --------------------------------------------------------------------------- #
# Event builders and rendering (pure)
# --------------------------------------------------------------------------- #


def _refuted(hypothesis_id: str, reason: str, proofs: tuple[Proof, ...]) -> LedgerEvent:
    return HypothesisRefuted(type="refuted", hypothesis_id=hypothesis_id, reason=reason, proofs=proofs)


def _gap_closed(gap_id: str, note: str, proofs: tuple[Proof, ...]) -> LedgerEvent:
    return GapClosed(type="gap_closed", gap_id=gap_id, note=note, proofs=proofs)


def _import_events(
    ledger: EpisodeLedger, batch: SarifBatch, episode: str, session_id: str
) -> tuple[list[LedgerEvent], str, list[str]]:
    import_id = blake3(f"{session_id}|{episode}|{batch.file_hash}|{ledger.event_count}".encode()).hexdigest()[:16]
    rejected_total = sum(n for _, n in batch.rejected)
    events: list[LedgerEvent] = [SarifImported(
        type="sarif_import", import_id=import_id, tool=batch.tool, file_hash=batch.file_hash,
        results_seen=batch.seen, results_imported=len(batch.findings), results_rejected=rejected_total,
        record_hashes=tuple(f.record_hash for f in batch.findings),
    )]
    for slot, finding in enumerate(batch.findings, start=1):
        events.append(ledger.fact(
            finding.claim, (ImportProof(kind="import", import_id=import_id, record_hash=finding.record_hash),),
            origin="sarif", slot=slot,
        ))
    gap_ids: list[str] = []
    base = len(batch.findings) + 1
    if rejected_total:
        reasons = ", ".join(f"{name}×{n}" for name, n in batch.rejected)
        gap = ledger.gap(
            "sarif_rejected", f"import {import_id}: {rejected_total} of {batch.seen} results rejected ({reasons})",
            None, None, slot=base,
        )
        events.append(gap)
        gap_ids.append(gap.id)
    if batch.truncated:
        gap = ledger.gap(
            "budget_truncated",
            f"import {import_id}: {batch.truncated} results beyond max_results were not imported",
            None, None, slot=base + 1,
        )
        events.append(gap)
        gap_ids.append(gap.id)
    return events, import_id, gap_ids


def _symbol_line(sym: Symbol) -> str:
    lines = f"L{sym.start_line}" if sym.start_line == sym.end_line else f"L{sym.start_line}-{sym.end_line}"
    return f"{_KIND_CODE[sym.kind]} {sym.name} {lines} B{sym.start_byte}-{sym.end_byte}"


def _hotspot_line(h: Hotspot) -> str:
    where = f"L{h.line}" if h.line == h.end_line else f"L{h.line}-{h.end_line}"
    scope = f" in {h.symbol}" if h.symbol else ""
    tail = f" | {h.snippet}" if h.snippet else ""
    return f"{_SEV[h.severity]} {h.rule} {where}{scope}: {h.detail}{tail}"


def _coverage_text(report: ScanReport, hotspot_count: int) -> str:
    head = f"{report.label}: scanned {report.files_scanned} file(s), {hotspot_count} hotspot(s) at the requested severity"
    if report.complete:
        return f"coverage: COMPLETE. {head}. Hotspots are review candidates, not findings."
    lines = [f"coverage: INCOMPLETE. {head}. Hotspots are review candidates, not findings."]
    if report.skipped_total:
        lines.append(f"not analyzed: {report.skipped_total} file(s)")
        lines.extend(f"- {s.path}: {s.reason} ({s.detail})" for s in report.skipped)
        if report.skipped_total > len(report.skipped):
            lines.append(f"- ... and {report.skipped_total - len(report.skipped)} more")
    if report.not_examined:
        lines.append(f"not examined (max_files reached): {report.not_examined} file(s)")
    if report.walk_truncated:
        lines.append("directory walk stopped early (entry limit or unreadable directory)")
    if report.symlinks:
        lines.append(f"symlinks not followed: {report.symlinks}")
    if report.too_deep:
        lines.append(f"directories deeper than the limit: {report.too_deep}")
    if report.unsupported:
        lines.append(f"files of unsupported types ignored: {report.unsupported}")
    lines.append("record these with ledger_declare_gap (reason skipped_by_scanner) so coverage stays visible")
    return "\n".join(lines)


def _proof_words(proofs: Sequence[Proof]) -> str:
    parts: list[str] = []
    for p in proofs:
        if isinstance(p, FragmentProof):
            parts.append(f"fragment {_short(p.hash)} via {p.capability.value}")
        elif isinstance(p, ReceiptProof):
            parts.append(f"receipt {p.receipt_id[:8]}.. over {p.fragments} fragment(s)")
        elif isinstance(p, ImportProof):
            parts.append(f"import {p.import_id}/{_short(p.record_hash)}")
        else:
            span = f"0x{p.start:x}-0x{p.end:x}" + (f" {p.symbol}" if p.symbol else "")
            parts.append(f"range {span} (locator)")
    return "; ".join(parts)


def _entry_item(entry: Entry) -> BackendItem:
    if isinstance(entry, FactView):
        origin = entry.origin + (f" from {entry.promoted_from}" if entry.promoted_from else "")
        return _item(entry.id, f"CONFIRMED FACT {entry.id} [{origin}] #{entry.seq}\nclaim: {entry.claim}\nproof: {_proof_words(entry.proofs)}")
    if isinstance(entry, HypothesisView):
        lines = [f"HYPOTHESIS {entry.id} [{entry.status}] #{entry.seq} (unverified)", f"claim: {entry.claim}"]
        for i, req in enumerate(entry.requirements):
            mark = "x" if i in entry.satisfied_indexes else " "
            hint = f" (try {req.suggested_capability.value})" if req.suggested_capability else ""
            lines.append(f"need[{i}] [{mark}] {req.description}{hint}")
        if entry.basis:
            lines.append(f"basis: {_proof_words(entry.basis)}")
        if entry.fact_id:
            lines.append(f"promoted to {entry.fact_id}")
        if entry.refutation:
            lines.append(f"refuted: {entry.refutation}")
        return _item(entry.id, "\n".join(lines))
    if isinstance(entry, GapView):
        span = f" 0x{entry.start:x}-0x{entry.end:x}" if entry.start is not None and entry.end is not None else ""
        note = f"\nclosed: {entry.closed_note}" if entry.closed_note else ""
        return _item(entry.id, f"UNANALYZED GAP {entry.id} [{entry.status}] {entry.reason}{span} #{entry.seq}\nscope: {entry.scope}{note}")
    assert isinstance(entry, ImportView)
    return _item(
        f"import:{entry.import_id}",
        f"SARIF IMPORT {entry.import_id} #{entry.seq} tool={entry.tool} file={_short(entry.file_hash)} "
        f"seen={entry.results_seen} imported={entry.results_imported} rejected={entry.results_rejected}",
    )


def _summary_text(s: LedgerSummary) -> str:
    return (
        f"episode {s.episode}: {s.events} events, head {_short(s.head)}\n"
        f"confirmed facts: {s.facts} | hypotheses: {s.hypotheses_open} open, {s.hypotheses_promoted} promoted, "
        f"{s.hypotheses_refuted} refuted | gaps: {s.gaps_open} open, {s.gaps_closed} closed | sarif imports: {s.imports}\n"
        f"coverage: {s.coverage.upper().replace('_', ' ')}"
    )
