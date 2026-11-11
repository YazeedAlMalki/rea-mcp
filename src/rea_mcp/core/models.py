"""Strict wire and domain models for the REA MCP (Phase 1).

Invariants enforced here, by analogy to the anti-slop / smokinggun / leantoken
rules (those repos target TypeScript and Rust; these are the Python/Pydantic
equivalents, not ports):

* No untyped dictionaries or untyped values anywhere: every field has a concrete
  type; capability arguments are a closed, discriminated union.
* ``strict=True`` + ``extra="forbid"`` + ``frozen=True`` on every model: no
  coercion, no unknown fields, no mutation after validation (parse at the
  boundary, then trust the type).
* Bounded integers are *rejected* when out of range, never clamped (leantoken).
* Numeric JSON addresses must be <= 2**53-1 (smokinggun safe-integer rule);
  full 64-bit addresses are passed as ``"0x..."`` hex strings.
* Text must be encodable as UTF-8 (lone surrogates are rejected, not replaced)
  and must not contain NUL.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from blake3 import blake3
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

# --------------------------------------------------------------------------- #
# Limits (single source of truth; every bound is rejected, never clamped)
# --------------------------------------------------------------------------- #

MAX_SAFE_INTEGER: Final[int] = 2**53 - 1
MAX_U64: Final[int] = 2**64 - 1
MIN_TOKEN_BUDGET: Final[int] = 1
MAX_TOKEN_BUDGET: Final[int] = 32_000
DEFAULT_TOKEN_BUDGET: Final[int] = 4_000
MAX_PAGE_LIMIT: Final[int] = 1_000
DEFAULT_PAGE_LIMIT: Final[int] = 100
MAX_KNOWN_HASHES: Final[int] = 512
MAX_READ_BYTES: Final[int] = 4_096
MAX_PATCH_BYTES: Final[int] = 256
MAX_SCRIPT_CHARS: Final[int] = 16_000
MAX_SCRIPT_INPUTS: Final[int] = 8
MAX_DEFINE_SPAN: Final[int] = 2**24
MAX_SLICE_LINES: Final[int] = 400


# --------------------------------------------------------------------------- #
# Validated scalar types
# --------------------------------------------------------------------------- #


def _require_utf8(value: str) -> str:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("text is not valid UTF-8 (contains a lone surrogate)") from exc
    if "\x00" in value:
        raise ValueError("text must not contain NUL")
    return value


def _parse_address(value: int | str) -> int:
    """Accept a safe-integer JSON number or a ``0x`` hex string; reject bool."""
    if isinstance(value, bool):
        raise ValueError("address must not be a boolean")
    if isinstance(value, int):
        if value > MAX_SAFE_INTEGER:
            raise ValueError("numeric address exceeds 2**53-1; pass it as a 0x hex string")
        return value
    text = value.strip().lower()
    if not text.startswith("0x") or not 3 <= len(text) <= 18:
        raise ValueError("address string must look like 0x1a2b (1-16 hex digits)")
    try:
        return int(text, 16)
    except ValueError as exc:
        raise ValueError("address string is not valid hexadecimal") from exc


Address = Annotated[int, BeforeValidator(_parse_address), Field(strict=True, ge=0, le=MAX_U64)]
TokenBudget = Annotated[int, Field(strict=True, ge=MIN_TOKEN_BUDGET, le=MAX_TOKEN_BUDGET)]
PageLimit = Annotated[int, Field(strict=True, ge=1, le=MAX_PAGE_LIMIT)]
ByteCount = Annotated[int, Field(strict=True, ge=1, le=MAX_READ_BYTES)]
Depth = Annotated[int, Field(strict=True, ge=1, le=8)]
StackOffset = Annotated[int, Field(strict=True, ge=-65_536, le=65_536)]
ScriptInputName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
CandidateTag = Annotated[
    str, StringConstraints(pattern=r"^\[SECRET_CANDIDATE:[a-z_]{1,32}:[0-9a-f]{8}\]$")
]
EpisodeId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")]
LedgerId = Annotated[str, StringConstraints(pattern=r"^[fhgpsi]-[0-9a-f]{12}$")]
ImportId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
LineNumber = Annotated[int, Field(strict=True, ge=1, le=10_000_000)]
Generation = Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)]
TokenCount = Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)]

Claim = Annotated[str, StringConstraints(min_length=3, max_length=1_000), AfterValidator(_require_utf8)]
SafeText = Annotated[str, StringConstraints(max_length=2_000), AfterValidator(_require_utf8)]
ShortText = Annotated[str, StringConstraints(max_length=256), AfterValidator(_require_utf8)]
Pattern = Annotated[str, StringConstraints(min_length=1, max_length=256), AfterValidator(_require_utf8)]
Declaration = Annotated[str, StringConstraints(min_length=1, max_length=1_024), AfterValidator(_require_utf8)]
PathText = Annotated[str, StringConstraints(min_length=1, max_length=1_024), AfterValidator(_require_utf8)]
ScriptText = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_SCRIPT_CHARS), AfterValidator(_require_utf8)
]
Justification = Annotated[
    str, StringConstraints(min_length=8, max_length=500), AfterValidator(_require_utf8)
]
# Symbol names: any printable text without control characters.
SymbolName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=256, pattern=r"^[^\x00-\x1f\x7f]+$"),
    AfterValidator(_require_utf8),
]
DatabaseId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
ReceiptId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{16,64}$")]
CursorToken = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,256}$")]
Blake3Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
HexBytes = Annotated[str, StringConstraints(pattern=r"^(?:[0-9A-Fa-f]{2}){1,256}$")]
BytePattern = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9A-Fa-f]{2}|\?\?)(?: (?:[0-9A-Fa-f]{2}|\?\?)){0,63}$"),
]


def content_hash(text: str) -> str:
    """BLAKE3 content address of a response fragment (lowercase hex, 64 chars)."""
    return blake3(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, validate_default=True)


class BackendKind(StrEnum):
    EVIDENCE = "evidence"
    IDA_PRO = "ida_pro"
    IDA_FREE = "ida_free"
    GHIDRA = "ghidra"


class SecurityTier(StrEnum):
    READ_ONLY = "read_only"
    MUTATE_SAFE = "mutate_safe"
    PRIVILEGED_DANGEROUS = "privileged_dangerous"


class Capability(StrEnum):
    """Backend-neutral capabilities. Anything not listed here is not routable."""

    # READ_ONLY
    LIST_DATABASES = "list_databases"
    DECOMPILE = "decompile"
    DISASM = "disasm"
    XREFS_TO = "xrefs_to"
    XREFS_FROM = "xrefs_from"
    CALLEES = "callees"
    BASIC_BLOCKS = "basic_blocks"
    STACK_FRAME = "stack_frame"
    FUNCTION_INFO = "function_info"
    LIST_FUNCTIONS = "list_functions"
    LIST_GLOBALS = "list_globals"
    LIST_SEGMENTS = "list_segments"
    LIST_IMPORTS = "list_imports"
    LIST_EXPORTS = "list_exports"
    LIST_STRINGS = "list_strings"
    LIST_NAMESPACES = "list_namespaces"
    SEARCH_FUNCTIONS = "search_functions"
    FIND_REGEX = "find_regex"
    FIND_BYTES = "find_bytes"
    GET_BYTES = "get_bytes"
    CALLGRAPH = "callgraph"
    READ_STRUCT = "read_struct"
    # READ_ONLY, evidence engine (local files / decompiled text / the per-session ledger)
    LEDGER_LIST = "ledger_list"
    LEDGER_GET = "ledger_get"
    LEDGER_SUMMARY = "ledger_summary"
    SCAN_HOTSPOTS = "scan_hotspots"
    SOURCE_OUTLINE = "source_outline"
    SOURCE_READ = "source_read"
    # MUTATE_SAFE (analysis state only: names, types, comments, item/function/stack-frame
    # boundaries; never program bytes. Per-session human grant; bumps the generation.)
    OPEN_DATABASE = "open_database"
    CLOSE_DATABASE = "close_database"
    RENAME_SYMBOL = "rename_symbol"
    RENAME_VARIABLE = "rename_variable"
    SET_COMMENT = "set_comment"
    SET_TYPE = "set_type"
    SET_FUNCTION_PROTOTYPE = "set_function_prototype"
    SET_VARIABLE_TYPE = "set_variable_type"
    DECLARE_TYPE = "declare_type"
    ADD_BOOKMARK = "add_bookmark"
    DEFINE_FUNCTION = "define_function"
    DEFINE_CODE = "define_code"
    UNDEFINE = "undefine"
    DECLARE_STACK_VAR = "declare_stack_var"
    DELETE_STACK_VAR = "delete_stack_var"
    # MUTATE_SAFE, evidence engine: appends to the analysis ledger, never touches a database
    LEDGER_RECORD_FACT = "ledger_record_fact"
    LEDGER_RECORD_HYPOTHESIS = "ledger_record_hypothesis"
    LEDGER_PROMOTE = "ledger_promote"
    LEDGER_REFUTE = "ledger_refute"
    LEDGER_DECLARE_GAP = "ledger_declare_gap"
    LEDGER_CLOSE_GAP = "ledger_close_gap"
    IMPORT_SARIF = "import_sarif"
    # PRIVILEGED_DANGEROUS
    PATCH_BYTES = "patch_bytes"
    PATCH_ASM = "patch_asm"
    WRITE_MEMORY = "write_memory"
    SAVE_DATABASE = "save_database"
    SCRIPT_EVAL = "script_eval"
    DEBUGGER_CONTROL = "debugger_control"


class ErrorCategory(StrEnum):
    INVALID_REQUEST = "invalid_request"
    DENIED_TIER = "denied_tier"
    DENIED_OVERRIDE = "denied_override"
    DENIED_CONSENT = "denied_consent"
    DENIED_PATH = "denied_path"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    BACKEND_ERROR = "backend_error"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    TIMEOUT = "timeout"
    STALE_CURSOR = "stale_cursor"
    STALE_RECEIPT = "stale_receipt"
    UNKNOWN_RECEIPT = "unknown_receipt"
    BUDGET_TOO_SMALL = "budget_too_small"
    CAPACITY_EXHAUSTED = "capacity_exhausted"
    AUDIT_FAILURE = "audit_failure"
    EVIDENCE_REJECTED = "evidence_rejected"
    INVALID_STATE = "invalid_state"
    NOT_FOUND = "not_found"


# --------------------------------------------------------------------------- #
# Capability arguments (closed discriminated unions, one per tier)
# --------------------------------------------------------------------------- #


class ListDatabasesArgs(StrictModel):
    capability: Literal["list_databases"]


class AddressArgs(StrictModel):
    capability: Literal[
        "disasm", "xrefs_to", "xrefs_from", "callees",
        "basic_blocks", "stack_frame", "function_info",
    ]
    address: Address


class DecompileArgs(StrictModel):
    """By address (IDA, Ghidra) or by function name (GhidraMCP ``/decompile?name=``)."""

    capability: Literal["decompile"]
    address: Address | None = None
    name: SymbolName | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> DecompileArgs:
        if (self.address is None) == (self.name is None):
            raise ValueError("decompile requires exactly one of address or name")
        return self


class PagedListArgs(StrictModel):
    capability: Literal[
        "list_functions", "list_globals", "list_segments", "list_imports",
        "list_exports", "list_strings", "list_namespaces",
    ]
    filter: ShortText | None = None
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class SearchArgs(StrictModel):
    capability: Literal["search_functions", "find_regex"]
    pattern: Pattern
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class FindBytesArgs(StrictModel):
    capability: Literal["find_bytes"]
    pattern: BytePattern
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class GetBytesArgs(StrictModel):
    capability: Literal["get_bytes"]
    address: Address
    size: ByteCount


class CallgraphArgs(StrictModel):
    capability: Literal["callgraph"]
    roots: Annotated[tuple[Address, ...], Field(min_length=1, max_length=16)]
    max_depth: Depth = 3


class ReadStructArgs(StrictModel):
    capability: Literal["read_struct"]
    name: SymbolName
    address: Address | None = None


class FileTarget(StrictModel):
    """A file under ``REA_ALLOWED_ROOTS`` (symlinks resolved, then re-checked)."""

    kind: Literal["file"]
    path: PathText


class TreeTarget(StrictModel):
    kind: Literal["tree"]
    path: PathText


class DecompileTarget(StrictModel):
    """Pseudocode fetched by the router from a disassembler backend."""

    kind: Literal["decompile"]
    address: Address


SingleSource = Annotated[FileTarget | DecompileTarget, Field(discriminator="kind")]
AnySource = Annotated[FileTarget | TreeTarget | DecompileTarget, Field(discriminator="kind")]
Severity = Literal["info", "low", "medium", "high"]


class SourceOutlineArgs(StrictModel):
    capability: Literal["source_outline"]
    target: SingleSource
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class SourceReadArgs(StrictModel):
    """Range-bounded slice: by symbol name, or by 1-based inclusive line range (<= 400 lines)."""

    capability: Literal["source_read"]
    target: SingleSource
    symbol: SymbolName | None = None
    start_line: LineNumber | None = None
    end_line: LineNumber | None = None
    context_lines: Annotated[int, Field(strict=True, ge=0, le=20)] = 0

    @model_validator(mode="after")
    def _one_selector(self) -> SourceReadArgs:
        by_lines = self.start_line is not None or self.end_line is not None
        if (self.symbol is not None) == by_lines:
            raise ValueError("give either symbol or start_line+end_line")
        if by_lines:
            if self.start_line is None or self.end_line is None or self.end_line < self.start_line:
                raise ValueError("start_line and end_line are both required, end >= start")
            if self.end_line - self.start_line + 1 > MAX_SLICE_LINES:
                raise ValueError(f"a slice is at most {MAX_SLICE_LINES} lines")
        return self


class ScanHotspotsArgs(StrictModel):
    """Read-only triage. Findings are candidates for review, never proof."""

    capability: Literal["scan_hotspots"]
    target: AnySource
    min_severity: Severity = "low"
    max_files: Annotated[int, Field(strict=True, ge=1, le=500)] = 200
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class LedgerListArgs(StrictModel):
    capability: Literal["ledger_list"]
    episode: EpisodeId = "main"
    view: Literal["all", "facts", "hypotheses", "gaps", "imports"] = "all"
    status: Literal["any", "open", "promoted", "refuted", "closed"] = "any"
    cursor: CursorToken | None = None
    limit: PageLimit = DEFAULT_PAGE_LIMIT


class LedgerGetArgs(StrictModel):
    capability: Literal["ledger_get"]
    episode: EpisodeId = "main"
    entry_id: LedgerId


class LedgerSummaryArgs(StrictModel):
    capability: Literal["ledger_summary"]
    episode: EpisodeId = "main"


ReadArgs = Annotated[
    ListDatabasesArgs | AddressArgs | DecompileArgs | PagedListArgs | SearchArgs | FindBytesArgs
    | GetBytesArgs | CallgraphArgs | ReadStructArgs
    | SourceOutlineArgs | SourceReadArgs | ScanHotspotsArgs
    | LedgerListArgs | LedgerGetArgs | LedgerSummaryArgs,
    Field(discriminator="capability"),
]


class OpenDatabaseArgs(StrictModel):
    capability: Literal["open_database"]
    input_path: PathText
    run_auto_analysis: bool = True


class CloseDatabaseArgs(StrictModel):
    """Closing never saves; saving is the privileged ``save_database`` capability."""

    capability: Literal["close_database"]
    save: Literal[False] = False


class RenameSymbolArgs(StrictModel):
    capability: Literal["rename_symbol"]
    address: Address
    new_name: SymbolName


class RenameVariableArgs(StrictModel):
    capability: Literal["rename_variable"]
    function_address: Address
    old_name: SymbolName
    new_name: SymbolName


class SetCommentArgs(StrictModel):
    capability: Literal["set_comment"]
    address: Address
    comment: SafeText
    kind: Literal["decompiler", "disasm"] = "disasm"


class SetTypeArgs(StrictModel):
    capability: Literal["set_type", "set_function_prototype", "set_variable_type"]
    address: Address
    declaration: Declaration
    variable_name: SymbolName | None = None

    @model_validator(mode="after")
    def _variable_name_rules(self) -> SetTypeArgs:
        needs_name = self.capability == "set_variable_type"
        if needs_name and self.variable_name is None:
            raise ValueError("set_variable_type requires variable_name")
        if not needs_name and self.variable_name is not None:
            raise ValueError("variable_name is only valid for set_variable_type")
        return self


class DeclareTypeArgs(StrictModel):
    capability: Literal["declare_type"]
    declaration: Declaration


class AddBookmarkArgs(StrictModel):
    capability: Literal["add_bookmark"]
    address: Address
    note: SafeText


class DefineFunctionArgs(StrictModel):
    capability: Literal["define_function"]
    start: Address
    end: Address | None = None

    @model_validator(mode="after")
    def _range(self) -> DefineFunctionArgs:
        if self.end is not None and not 0 < self.end - self.start <= MAX_DEFINE_SPAN:
            raise ValueError("end must be greater than start and within the maximum span")
        return self


class DefineCodeArgs(StrictModel):
    capability: Literal["define_code"]
    address: Address


class UndefineArgs(StrictModel):
    capability: Literal["undefine"]
    address: Address
    size: ByteCount


class DeclareStackVarArgs(StrictModel):
    capability: Literal["declare_stack_var"]
    function_address: Address
    frame_offset: StackOffset
    name: SymbolName
    declaration: Declaration


class DeleteStackVarArgs(StrictModel):
    capability: Literal["delete_stack_var"]
    function_address: Address
    name: SymbolName


class FragmentEvidence(StrictModel):
    """A response fragment this session was sent (verified against the server's own record)."""

    kind: Literal["fragment"]
    hash: Blake3Hex


class ReceiptEvidence(StrictModel):
    kind: Literal["receipt"]
    receipt_id: ReceiptId


class ImportEvidence(StrictModel):
    """A record imported through ``import_sarif`` (verified against the ledger's import table)."""

    kind: Literal["import"]
    import_id: ImportId
    record_hash: Blake3Hex


class RangeEvidence(StrictModel):
    """Locator only: names where the evidence lives; never verifiable on its own."""

    kind: Literal["range"]
    start: Address
    end: Address
    symbol: SymbolName | None = None

    @model_validator(mode="after")
    def _ordered(self) -> RangeEvidence:
        if not 0 < self.end - self.start <= MAX_DEFINE_SPAN:
            raise ValueError("end must be greater than start within the maximum span")
        return self


EvidenceRef = Annotated[
    FragmentEvidence | ReceiptEvidence | ImportEvidence | RangeEvidence, Field(discriminator="kind")
]
VerifiableRef = Annotated[
    FragmentEvidence | ReceiptEvidence | ImportEvidence, Field(discriminator="kind")
]
EvidenceList = Annotated[tuple[EvidenceRef, ...], Field(min_length=1, max_length=8)]


class RequiredEvidence(StrictModel):
    description: Claim
    suggested_capability: Capability | None = None


class Satisfaction(StrictModel):
    requirement_index: Annotated[int, Field(strict=True, ge=0, le=7)]
    evidence: VerifiableRef


GapReason = Literal[
    "not_analyzed", "decompile_failed", "backend_unsupported", "budget_truncated",
    "out_of_scope", "packed_or_encrypted", "skipped_by_scanner", "sarif_rejected", "unknown",
]


class RecordFactArgs(StrictModel):
    capability: Literal["ledger_record_fact"]
    episode: EpisodeId = "main"
    claim: Claim
    evidence: EvidenceList


class RecordHypothesisArgs(StrictModel):
    capability: Literal["ledger_record_hypothesis"]
    episode: EpisodeId = "main"
    claim: Claim
    required_evidence: Annotated[tuple[RequiredEvidence, ...], Field(min_length=1, max_length=8)]
    basis: Annotated[tuple[EvidenceRef, ...], Field(max_length=8)] = ()


class PromoteArgs(StrictModel):
    capability: Literal["ledger_promote"]
    episode: EpisodeId = "main"
    hypothesis_id: LedgerId
    satisfies: Annotated[tuple[Satisfaction, ...], Field(min_length=1, max_length=16)]


class RefuteArgs(StrictModel):
    capability: Literal["ledger_refute"]
    episode: EpisodeId = "main"
    hypothesis_id: LedgerId
    reason: Claim
    evidence: EvidenceList


class DeclareGapArgs(StrictModel):
    capability: Literal["ledger_declare_gap"]
    episode: EpisodeId = "main"
    reason: GapReason
    scope: Claim
    start: Address | None = None
    end: Address | None = None

    @model_validator(mode="after")
    def _range(self) -> DeclareGapArgs:
        if (self.start is None) != (self.end is None):
            raise ValueError("give both start and end, or neither")
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("end must be greater than start")
        return self


class CloseGapArgs(StrictModel):
    capability: Literal["ledger_close_gap"]
    episode: EpisodeId = "main"
    gap_id: LedgerId
    note: Claim
    evidence: EvidenceList


class ImportSarifArgs(StrictModel):
    """Offline SARIF 2.1.0 import. Nothing named inside the file is ever fetched."""

    capability: Literal["import_sarif"]
    episode: EpisodeId = "main"
    path: PathText
    source_root: PathText | None = None
    max_results: Annotated[int, Field(strict=True, ge=1, le=5_000)] = 500


MutateArgs = Annotated[
    OpenDatabaseArgs | CloseDatabaseArgs | RenameSymbolArgs | RenameVariableArgs
    | SetCommentArgs | SetTypeArgs | DeclareTypeArgs | AddBookmarkArgs
    | DefineFunctionArgs | DefineCodeArgs | UndefineArgs | DeclareStackVarArgs
    | DeleteStackVarArgs
    | RecordFactArgs | RecordHypothesisArgs | PromoteArgs | RefuteArgs
    | DeclareGapArgs | CloseGapArgs | ImportSarifArgs,
    Field(discriminator="capability"),
]


class PatchBytesArgs(StrictModel):
    capability: Literal["patch_bytes"]
    address: Address
    data: HexBytes
    justification: Justification


class PatchAsmArgs(StrictModel):
    capability: Literal["patch_asm"]
    address: Address
    asm: ShortText
    justification: Justification


class WriteMemoryArgs(StrictModel):
    capability: Literal["write_memory"]
    address: Address
    data: HexBytes
    space: Literal["idb", "process"]
    justification: Justification


class SaveDatabaseArgs(StrictModel):
    capability: Literal["save_database"]
    path: PathText | None = None
    justification: Justification


class ScriptInputBytes(StrictModel):
    """Bytes read by the router (``get_bytes``) and mounted read-only as ``/input/<name>``."""

    kind: Literal["bytes"]
    name: ScriptInputName
    address: Address
    size: ByteCount


class ScriptInputText(StrictModel):
    """Disassembly or pseudocode fetched by the router and mounted as UTF-8 text."""

    kind: Literal["text"]
    name: ScriptInputName
    source: Literal["disasm", "decompile"]
    address: Address


ScriptInput = Annotated[ScriptInputBytes | ScriptInputText, Field(discriminator="kind")]


class ScriptEvalArgs(StrictModel):
    """Never forwarded to a disassembler host; runs only in an isolated runner."""

    capability: Literal["script_eval"]
    code: ScriptText
    inputs: Annotated[tuple[ScriptInput, ...], Field(max_length=MAX_SCRIPT_INPUTS)] = ()
    language: Literal["python"] = "python"
    justification: Justification


class DebuggerControlArgs(StrictModel):
    capability: Literal["debugger_control"]
    action: Literal[
        "start", "continue", "run_to", "step_into", "step_over", "exit",
        "add_breakpoint", "delete_breakpoint", "toggle_breakpoint",
    ]
    address: Address | None = None
    justification: Justification


PrivilegedArgs = Annotated[
    PatchBytesArgs | PatchAsmArgs | WriteMemoryArgs | SaveDatabaseArgs
    | ScriptEvalArgs | DebuggerControlArgs,
    Field(discriminator="capability"),
]

AnyArgs = (
    ListDatabasesArgs | AddressArgs | PagedListArgs | SearchArgs | FindBytesArgs
    | GetBytesArgs | CallgraphArgs | ReadStructArgs | DecompileArgs
    | SourceOutlineArgs | SourceReadArgs | ScanHotspotsArgs
    | LedgerListArgs | LedgerGetArgs | LedgerSummaryArgs
    | RecordFactArgs | RecordHypothesisArgs | PromoteArgs | RefuteArgs
    | DeclareGapArgs | CloseGapArgs | ImportSarifArgs
    | OpenDatabaseArgs | CloseDatabaseArgs | RenameSymbolArgs | RenameVariableArgs
    | SetCommentArgs | SetTypeArgs | DeclareTypeArgs | AddBookmarkArgs
    | DefineFunctionArgs | DefineCodeArgs | UndefineArgs | DeclareStackVarArgs
    | DeleteStackVarArgs
    | PatchBytesArgs | PatchAsmArgs | WriteMemoryArgs | SaveDatabaseArgs
    | ScriptEvalArgs | DebuggerControlArgs
)

PAGED_ARGS: Final = (
    PagedListArgs, SearchArgs, FindBytesArgs, SourceOutlineArgs, ScanHotspotsArgs, LedgerListArgs
)
EVIDENCE_CAPABILITIES: Final[frozenset[Capability]] = frozenset({
    Capability.LEDGER_LIST, Capability.LEDGER_GET, Capability.LEDGER_SUMMARY,
    Capability.SCAN_HOTSPOTS, Capability.SOURCE_OUTLINE, Capability.SOURCE_READ,
    Capability.LEDGER_RECORD_FACT, Capability.LEDGER_RECORD_HYPOTHESIS, Capability.LEDGER_PROMOTE,
    Capability.LEDGER_REFUTE, Capability.LEDGER_DECLARE_GAP, Capability.LEDGER_CLOSE_GAP,
    Capability.IMPORT_SARIF,
})
# Notes in the append-only ledger never touch the binary or the database, so they need no human grant.
LEDGER_WRITES: Final[frozenset[Capability]] = frozenset({
    Capability.LEDGER_RECORD_FACT, Capability.LEDGER_RECORD_HYPOTHESIS, Capability.LEDGER_PROMOTE,
    Capability.LEDGER_REFUTE, Capability.LEDGER_DECLARE_GAP, Capability.LEDGER_CLOSE_GAP,
    Capability.IMPORT_SARIF,
})
# Results of these describe the ledger itself, so they are never citable as evidence.
LEDGER_READS: Final[frozenset[Capability]] = frozenset({
    Capability.LEDGER_LIST, Capability.LEDGER_GET, Capability.LEDGER_SUMMARY,
})


# --------------------------------------------------------------------------- #
# Request envelopes: three facade tools, one per tier (+ rea_capabilities)
# --------------------------------------------------------------------------- #


class ResponseControl(StrictModel):
    """leantoken-style budget and dedup controls shared by every facade tool."""

    token_budget: TokenBudget = DEFAULT_TOKEN_BUDGET
    receipt_id: ReceiptId | None = None
    known_hashes: Annotated[tuple[Blake3Hex, ...], Field(max_length=MAX_KNOWN_HASHES)] = ()
    expected_hash: Blake3Hex | None = None


class _RequestBase(StrictModel):
    database: DatabaseId | None = None
    backend: BackendKind | None = None
    control: ResponseControl = Field(default_factory=ResponseControl)


class QueryRequest(_RequestBase):
    args: ReadArgs


class MutateRequest(_RequestBase):
    args: MutateArgs


class PrivilegedRequest(_RequestBase):
    args: PrivilegedArgs


# --------------------------------------------------------------------------- #
# Backend contract and response envelope
# --------------------------------------------------------------------------- #


class BackendItem(StrictModel):
    """``channel`` splits the redaction scopes: ``artifact`` text comes from the target
    binary (evidence; secrets tagged, optionally redacted); ``host`` text describes the
    analyst's machine (database paths, bridge diagnostics) and always gets host scrubbing."""

    label: ShortText
    text: str
    channel: Literal["artifact", "host"] = "artifact"


class BackendResult(StrictModel):
    items: tuple[BackendItem, ...]
    next_offset: Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)] | None = None
    generation: Generation


class FragmentRef(StrictModel):
    hash: Blake3Hex
    label: ShortText
    tokens_saved: TokenCount


class Fragment(StrictModel):
    hash: Blake3Hex
    label: ShortText
    text: str
    tokens: TokenCount
    secret_candidates: Annotated[tuple[CandidateTag, ...], Field(max_length=32)] = ()


class OmissionSummary(StrictModel):
    omitted_fragments: TokenCount
    omitted_tokens_estimate: TokenCount
    reason: Literal["token_budget"]


class ResponseMeta(StrictModel):
    capability: Capability
    backend: BackendKind | None
    receipt_id: ReceiptId | None
    generation: Generation
    token_budget: TokenBudget
    tokens_used: TokenCount
    truncated: bool
    result_complete: bool
    fragment_hashes: tuple[Blake3Hex, ...]
    next_cursor: CursorToken | None = None
    omission: OmissionSummary | None = None


class ErrorInfo(StrictModel):
    category: ErrorCategory
    message: ShortText
    retryable: bool = False


class ToolResponse(StrictModel):
    status: Literal["ok", "not_modified", "error"]
    fragments: tuple[Fragment, ...] = ()
    known: tuple[FragmentRef, ...] = ()
    meta: ResponseMeta | None = None
    error: ErrorInfo | None = None

    @model_validator(mode="after")
    def _status_consistency(self) -> ToolResponse:
        if (self.status == "error") != (self.error is not None):
            raise ValueError("error must be set exactly when status == 'error'")
        if self.status == "ok" and self.meta is None:
            raise ValueError("ok responses require meta")
        return self


class CapabilityEntry(StrictModel):
    capability: Capability
    tier: SecurityTier
    enabled: bool
    reason: ShortText


class CapabilityListing(StrictModel):
    entries: tuple[CapabilityEntry, ...]
