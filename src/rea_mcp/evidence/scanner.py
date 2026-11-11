"""Offline hotspot scanner and SARIF 2.1.0 importer (the ``morluto/smokinggun`` triage layer).

Everything here is read-only and offline: no network module is imported, nothing named inside a
scanned file or a SARIF report is ever opened except local files that resolve under
``REA_ALLOWED_ROOTS``. Findings are *candidates for review*; they become evidence only after a
human-directed ``source_read`` and ``ledger_record_fact``.

Coverage is never silent (smokinggun): every file the scanner could not analyze (too large, binary,
malformed UTF-8, unreadable, symlink, beyond ``max_files``, beyond the byte budget) is listed in
``ScanReport.skipped`` / counted in the report, and ``ScanReport.complete`` is false.
"""

from __future__ import annotations

import ast
import bisect
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal
from urllib.parse import unquote, urlsplit

from blake3 import blake3
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from rea_mcp.core.fsafe import entry_is_link
from rea_mcp.core.models import MAX_SAFE_INTEGER, Severity
from rea_mcp.evidence.leantoken_index import (
    MAX_FILE_BYTES,
    PARSE_NAME,
    SOURCE_SUFFIXES,
    IndexedSource,
    SourceSkipped,
    Symbol,
    index_source,
    index_text,
    language_for,
    mask_code,
    read_capped,
)

SEVERITY_RANK: Final[dict[Severity, int]] = {"info": 0, "low": 1, "medium": 2, "high": 3}
SCAN_SUFFIXES: Final = SOURCE_SUFFIXES | {".json"}
JS_SUFFIXES: Final = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".json"})
SKIP_DIRS: Final = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
})
MAX_WALK_DEPTH: Final = 32
MAX_WALK_ENTRIES: Final = 50_000
MAX_TOTAL_BYTES: Final = 64 * 1024 * 1024
MAX_SKIP_DETAILS: Final = 50

CC_LOW: Final = 10
CC_MEDIUM: Final = 15
CC_HIGH: Final = 25
BITOP_MIN: Final = 30
BITOP_HIGH: Final = 80
TABLE_WINDOW_LINES: Final = 32
TABLE_MIN_LITERALS: Final = 24
ENTROPY_MIN_CHARS: Final = 24
ENTROPY_THRESHOLD: Final = 4.5


@dataclass(frozen=True, slots=True)
class Hotspot:
    rule: str
    severity: Severity
    path: str
    line: int
    end_line: int
    symbol: str | None
    detail: str
    snippet: str


@dataclass(frozen=True, slots=True)
class SkippedFile:
    path: str
    reason: str
    detail: str


@dataclass(frozen=True, slots=True)
class FileScan:
    hotspots: tuple[Hotspot, ...]
    skipped: SkippedFile | None
    content_hash: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    label: str
    digest: str
    files_scanned: int
    hotspots: tuple[Hotspot, ...]
    skipped: tuple[SkippedFile, ...]
    skipped_total: int
    unsupported: int
    not_examined: int
    walk_truncated: bool
    symlinks: int
    too_deep: int

    @property
    def complete(self) -> bool:
        return (
            self.skipped_total == 0 and self.not_examined == 0 and not self.walk_truncated
            and self.symlinks == 0 and self.too_deep == 0
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0.0 for empty input."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


def _enclosing(symbols: tuple[Symbol, ...], pos: int) -> str | None:
    funcs = [s for s in symbols if s.kind in {"function", "method"}]
    starts = [s.start_byte for s in funcs]
    index = bisect.bisect_right(starts, pos) - 1
    while index >= 0:
        sym = funcs[index]
        if sym.start_byte <= pos < sym.end_byte:
            return sym.name
        if sym.end_byte <= pos and all(f.end_byte <= pos for f in funcs[max(0, index - 3) : index + 1]):
            break
        index -= 1
    return None


class _Collector:
    """Per-file hotspot accumulator with (rule, line) de-duplication."""

    def __init__(self, label: str, src: IndexedSource) -> None:
        self.label = label
        self.src = src
        self.out: dict[tuple[str, int], Hotspot] = {}

    def add(
        self, rule: str, severity: Severity, pos: int, detail: str, *, end_pos: int | None = None,
    ) -> None:
        line = self.src.line_of(pos)
        end_line = self.src.line_of(max(pos, end_pos - 1)) if end_pos is not None else line
        key = (rule, line)
        if key in self.out:
            return
        snippet = " ".join(self.src.slice_lines(line, line).split())[:120]
        self.out[key] = Hotspot(
            rule, severity, self.label, line, end_line, _enclosing(self.src.symbols, pos), detail, snippet
        )

    def result(self) -> tuple[Hotspot, ...]:
        return tuple(sorted(self.out.values(), key=lambda h: (h.line, h.rule)))


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

_DECISION: Final = re.compile(rb"\b(?:if|for|foreach|while|case|catch)\b|&&|\|\||\?(?![.?])")
_BITOP: Final = re.compile(rb"<<|>>|\^|~|(?<!&)&(?!&)|(?<!\|)\|(?!\|)")
_HEX_LITERAL: Final = re.compile(rb"\b0[xX]([0-9a-fA-F]{2,16})[uUlL]*\b")
_AES_SBOX: Final = re.compile(
    rb"0x63[uUlL]*\s*,\s*0x7c[uUlL]*\s*,\s*0x77[uUlL]*\s*,\s*0x7b", re.IGNORECASE
)
_STRING_LITERAL: Final = re.compile(rb"\"((?:\\.|[^\"\\\n]){%d,})\"|'((?:\\.|[^'\\\n]){%d,})'" % (ENTROPY_MIN_CHARS, ENTROPY_MIN_CHARS))
_BASE64ISH: Final = re.compile(rb"^[A-Za-z0-9+/_=-]+$")
_HEXISH: Final = re.compile(rb"^[0-9a-fA-F]+$")
_NUMBER: Final = re.compile(rb"(?<![\w.])(0[xX][0-9a-fA-F_]+|\d[\d_]*)(n?)(?![\w.])")

CRYPTO_CONSTANTS: Final[dict[str, str]] = {
    "6a09e667": "SHA-256/512 initial hash H0",
    "428a2f98": "SHA-256/512 round constant K0",
    "67452301": "MD5/SHA-1 initial state",
    "efcdab89": "MD5/SHA-1 initial state",
    "d76aa478": "MD5 round constant",
    "5a827999": "SHA-1 round constant",
    "edb88320": "CRC-32 reflected polynomial",
    "04c11db7": "CRC-32 polynomial",
    "61707865": "ChaCha/Salsa20 'expand 32-byte k'",
    "243f6a88": "Blowfish P-array (pi)",
    "9e3779b9": "TEA/XTEA delta",
    "c66363a5": "AES T-table Te0[0]",
    "b7e15163": "RC5/RC6 magic constant",
}

_COPY_HIGH: Final = (
    "gets", "strcpy", "strcat", "stpcpy", "sprintf", "vsprintf", "wcscpy", "wcscat", "lstrcpy", "lstrcat",
)
_COPY_LOW: Final = ("strncpy", "strncat", "strtok", "wcsncpy")
_SCANF: Final = ("scanf", "sscanf", "fscanf", "vscanf")
_MEMCOPY: Final = ("memcpy", "memmove", "bcopy")
_TEMP: Final = ("mktemp", "tmpnam", "tempnam")
_EXEC_C: Final = (
    "system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW", "WinExec",
    "CreateProcessA", "CreateProcessW", "CreateProcess", "eval", "execSync",
)
_FORMAT_ARG: Final[dict[str, int]] = {
    "printf": 0, "vprintf": 0, "fprintf": 1, "dprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1,
}


def _call_regex(names: tuple[str, ...]) -> re.Pattern[bytes]:
    alt = "|".join(sorted(map(re.escape, names), key=len, reverse=True)).encode()
    return re.compile(rb"\b(?:j_|_)?(" + alt + rb")\s*\(")


_CALL_COPY_HIGH: Final = _call_regex(_COPY_HIGH)
_CALL_COPY_LOW: Final = _call_regex(_COPY_LOW)
_CALL_SCANF: Final = _call_regex(_SCANF)
_CALL_MEMCOPY: Final = _call_regex(_MEMCOPY)
_CALL_TEMP: Final = _call_regex(_TEMP)
_CALL_EXEC: Final = _call_regex(_EXEC_C)
_CALL_ALLOCA: Final = _call_regex(("alloca",))
_CALL_FORMAT: Final = _call_regex(tuple(_FORMAT_ARG))
_JS_EXEC: Final = re.compile(
    rb"\bnew\s+Function\s*\(|\bchild_process\b\s*\.\s*(?:exec|execSync|spawn|spawnSync)\s*\("
    rb"|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
)
_CONST_SIZE: Final = re.compile(rb"^\s*(?:\(\s*\w+\s*\)\s*)?(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*$")


def call_args(masked: bytes, open_paren: int, limit: int = 800) -> tuple[tuple[int, int], ...] | None:
    """Byte spans of the top-level arguments of the call whose ``(`` is at ``open_paren``."""
    depth = 0
    spans: list[tuple[int, int]] = []
    start = open_paren + 1
    end_scan = min(len(masked), open_paren + limit)
    for pos in range(open_paren, end_scan):
        char = masked[pos : pos + 1]
        if char in {b"(", b"[", b"{"}:
            depth += 1
        elif char in {b")", b"]", b"}"}:
            depth -= 1
            if depth == 0:
                spans.append((start, pos))
                return tuple(spans)
        elif char == b"," and depth == 1:
            spans.append((start, pos))
            start = pos + 1
    return None


def _open_paren(masked: bytes, match: re.Match[bytes]) -> int:
    return match.end() - 1


def _scan_unsafe_c(col: _Collector, raw: bytes, masked: bytes) -> None:
    for match in _CALL_COPY_HIGH.finditer(masked):
        name = match.group(1).decode()
        col.add(f"unsafe.{name}", "high", match.start(), f"{name}() writes with no destination bound")
    for match in _CALL_COPY_LOW.finditer(masked):
        name = match.group(1).decode()
        col.add(f"unsafe.{name}", "low", match.start(), f"{name}() can leave the result unterminated or reuse hidden state")
    for match in _CALL_SCANF.finditer(masked):
        col.add("unsafe.scanf", "medium", match.start(), "scanf-family read into caller buffers; check field widths")
    for match in _CALL_TEMP.finditer(masked):
        col.add("unsafe.temp_name", "medium", match.start(), f"{match.group(1).decode()}() is race-prone")
    for match in _CALL_ALLOCA.finditer(masked):
        col.add("unsafe.alloca", "medium", match.start(), "alloca() size is attacker-controlled stack growth")
    for match in _CALL_MEMCOPY.finditer(masked):
        name = match.group(1).decode()
        args = call_args(masked, _open_paren(masked, match))
        size = masked[args[2][0] : args[2][1]] if args is not None and len(args) >= 3 else None
        if size is not None and (_CONST_SIZE.match(size) or b"sizeof" in size):
            col.add(f"unsafe.{name}", "info", match.start(), f"{name}() with a constant size")
        else:
            col.add(
                f"unsafe.{name}", "medium", match.start(),
                f"{name}() with a computed size; confirm it is bounded by the destination",
            )
    for match in _CALL_EXEC.finditer(masked):
        col.add(
            f"sink.exec.{match.group(1).decode()}", "high", match.start(),
            f"{match.group(1).decode()}() executes a command or code string",
        )
    for match in _JS_EXEC.finditer(masked):
        col.add("sink.exec.js", "high", match.start(), "dynamic code or process execution")
    for match in _CALL_FORMAT.finditer(masked):
        name = match.group(1).decode()
        args = call_args(masked, _open_paren(masked, match))
        index = _FORMAT_ARG[name]
        if args is None or len(args) <= index:
            continue
        original = raw[args[index][0] : args[index][1]].lstrip()
        if not re.match(rb"(?:L|u8|u|U)?\"", original):
            col.add(
                "format.non_literal", "medium", match.start(),
                f"{name}() format argument is not a string literal (format-string risk)",
            )


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _py_complexity(node: ast.AST) -> int:
    total = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.match_case)):
            total += 1
        elif isinstance(child, ast.BoolOp):
            total += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            total += len(child.ifs)
    return total


def _scan_python(col: _Collector, text: str) -> None:
    src = col.src
    try:
        tree = ast.parse(text, filename=PARSE_NAME)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cc = _py_complexity(node)
            _flag_complexity(col, node.name, cc, src.line_starts[node.lineno - 1] + node.col_offset, node.end_lineno)
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            pos = src.line_starts[node.lineno - 1] + node.col_offset
            shell = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if name in {"eval", "exec"}:
                col.add(f"sink.exec.{name}", "high", pos, f"{name}() executes a code string")
            elif name in {"os.system", "os.popen"} or (name.startswith("subprocess.") and shell):
                col.add(f"sink.exec.{name}", "high", pos, f"{name}() runs through a shell")
            elif name in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load"}:
                col.add(f"unsafe.{name}", "medium", pos, f"{name}() deserializes untrusted data into objects")


def _flag_complexity(col: _Collector, name: str, cc: int, pos: int, end_line: int | None) -> None:
    if cc < CC_LOW:
        return
    severity: Severity = "high" if cc >= CC_HIGH else "medium" if cc >= CC_MEDIUM else "low"
    end_pos = col.src.line_starts[end_line] if end_line is not None and end_line < col.src.line_count else None
    col.add("complexity.cyclomatic", severity, pos, f"{name}: cyclomatic complexity {cc}", end_pos=end_pos)


def _scan_c_like_structure(col: _Collector, masked: bytes) -> None:
    src = col.src
    for sym in src.symbols:
        if sym.kind not in {"function", "method"}:
            continue
        body = masked[sym.start_byte : sym.end_byte]
        cc = 1 + len(_DECISION.findall(body))
        _flag_complexity(col, sym.name, cc, sym.start_byte, sym.end_line)
        lines = max(1, sym.end_line - sym.start_line + 1)
        bitops = len(_BITOP.findall(body))
        if bitops >= BITOP_MIN and bitops / lines >= 1.0:
            col.add(
                "bitwise.dense", "medium" if bitops >= BITOP_HIGH else "low", sym.start_byte,
                f"{sym.name}: {bitops} bitwise operators in {lines} lines (cipher, hash or checksum shape)",
            )


def _scan_constants(col: _Collector, masked: bytes) -> None:
    line_hits: Counter[int] = Counter()
    for match in _HEX_LITERAL.finditer(masked):
        digits = match.group(1).decode().lower()
        line_hits[col.src.line_of(match.start())] += 1
        key = digits if len(digits) == 8 else digits[:8] if len(digits) == 16 else ""
        label = CRYPTO_CONSTANTS.get(key)
        if label is not None:
            col.add("crypto.constant", "medium", match.start(), f"0x{digits}: {label}")
    for match in _AES_SBOX.finditer(masked):
        col.add("crypto.constant", "medium", match.start(), "AES S-box prefix 63 7c 77 7b")
    if not line_hits:
        return
    hot: list[int] = []
    for first in sorted(line_hits):
        if sum(n for ln, n in line_hits.items() if first <= ln < first + TABLE_WINDOW_LINES) >= TABLE_MIN_LITERALS:
            hot.append(first)
    if not hot:
        return
    run_start = prev = hot[0]
    for line in [*hot[1:], -1]:
        if line == -1 or line > prev + 1:
            pos = col.src.line_starts[run_start - 1]
            end = prev + TABLE_WINDOW_LINES - 1
            col.add(
                "const.dense_table", "low", pos,
                f"dense hex-constant block near lines {run_start}-{min(end, col.src.line_count)} (lookup table or key schedule)",
                end_pos=col.src.line_starts[min(end, col.src.line_count) - 1],
            )
            run_start = line
        prev = line


def _scan_entropy(col: _Collector, raw: bytes) -> None:
    for match in _STRING_LITERAL.finditer(raw):
        body = match.group(1) or match.group(2)
        if _HEXISH.match(body) and len(body) >= 32:
            col.add("entropy.hex_blob", "info", match.start(), f"{len(body)}-char hex string (key, hash or blob?)")
        elif _BASE64ISH.match(body) and shannon_entropy(body) >= ENTROPY_THRESHOLD:
            col.add(
                "entropy.high_entropy_string", "medium" if len(body) >= 64 else "low", match.start(),
                f"{len(body)}-char literal at {shannon_entropy(body):.2f} bits/char (embedded key or encoded blob?)",
            )


def _scan_js_integers(col: _Collector, masked: bytes) -> None:
    for match in _NUMBER.finditer(masked):
        if match.group(2):  # BigInt literal
            continue
        text = match.group(1).replace(b"_", b"").decode()
        value = int(text, 16) if text[:2].lower() == "0x" else int(text)
        if value > MAX_SAFE_INTEGER:
            col.add(
                "js.unsafe_integer", "medium", match.start(),
                f"integer literal {text[:24]} exceeds 2**53-1 and loses precision as a JS number",
            )


def scan_bytes(label: str, suffix: str, data: bytes) -> FileScan:
    """Analyze one file's bytes. Never raises for hostile content: problems become findings or a skip."""
    digest = blake3(data).hexdigest()
    language = language_for(suffix)
    try:
        src = index_source(label, data, language or "c_like")
    except SourceSkipped as skip:
        if skip.reason == "malformed_utf8":
            first_bad = int(skip.detail.rsplit(" ", 1)[-1])
            line = data.count(b"\n", 0, first_bad) + 1
            hotspot = Hotspot(
                "encoding.malformed_utf8", "medium", label, line, line, None,
                f"{skip.detail}; the file was not analyzed further", "",
            )
            return FileScan((hotspot,), SkippedFile(label, skip.reason, skip.detail), digest)
        detail = skip.detail
        if skip.reason == "binary":
            detail = f"{skip.detail}; entropy {shannon_entropy(data[:65_536]):.2f} bits/byte"
        return FileScan((), SkippedFile(label, skip.reason, detail), digest)
    col = _Collector(label, src)
    text = data.decode("utf-8")
    if suffix == ".json":
        _scan_js_integers(col, mask_code(data))
    elif language == "python":
        _scan_python(col, text)
        _scan_entropy(col, data)
        _scan_constants(col, data)
    else:
        masked = mask_code(data)
        _scan_c_like_structure(col, masked)
        _scan_unsafe_c(col, data, masked)
        _scan_constants(col, masked)
        _scan_entropy(col, data)
        if suffix in JS_SUFFIXES:
            _scan_js_integers(col, masked)
    return FileScan(col.result(), None, digest)


def scan_text(label: str, text: str) -> FileScan:
    """Decompiler pseudocode (C-like)."""
    index_text(label, text)  # validates size/NUL the same way as files
    return scan_bytes(label, ".c", text.encode("utf-8", errors="backslashreplace"))


# --------------------------------------------------------------------------- #
# Tree walking
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class TreeFile:
    rel: str
    path: Path
    size: int
    mtime_ns: int


@dataclass(frozen=True, slots=True)
class TreeListing:
    files: tuple[TreeFile, ...]
    unsupported: int
    not_examined: int
    walk_truncated: bool
    symlinks: int
    too_deep: int

    @property
    def fingerprint(self) -> str:
        h = blake3()
        for f in self.files:
            h.update(f"{f.rel}|{f.size}|{f.mtime_ns}\n".encode())
        h.update(f"{self.unsupported}|{self.not_examined}|{self.walk_truncated}|{self.symlinks}|{self.too_deep}".encode())
        return h.hexdigest()


def list_tree(root: Path, max_files: int) -> TreeListing:
    """Deterministic, symlink-free listing of scannable files below ``root`` (already root-checked)."""
    found: list[TreeFile] = []
    unsupported = symlinks = too_deep = visited = 0
    truncated = False
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            truncated = True
            continue
        for entry in entries:
            visited += 1
            if visited > MAX_WALK_ENTRIES:
                return _listing(found, max_files, unsupported, True, symlinks, too_deep, root)
            if entry_is_link(entry):
                symlinks += 1
            elif entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS:
                    continue
                if depth + 1 > MAX_WALK_DEPTH:
                    too_deep += 1
                else:
                    stack.append((Path(entry.path), depth + 1))
            elif entry.is_file(follow_symlinks=False):
                if Path(entry.name).suffix.lower() not in SCAN_SUFFIXES:
                    unsupported += 1
                    continue
                info = entry.stat(follow_symlinks=False)
                found.append(TreeFile(Path(entry.path).relative_to(root).as_posix(), Path(entry.path), info.st_size, info.st_mtime_ns))
    return _listing(found, max_files, unsupported, truncated, symlinks, too_deep, root)


def _listing(
    found: list[TreeFile], max_files: int, unsupported: int, truncated: bool,
    symlinks: int, too_deep: int, root: Path,
) -> TreeListing:
    ordered = sorted(found, key=lambda f: f.rel)
    return TreeListing(tuple(ordered[:max_files]), unsupported, max(0, len(ordered) - max_files), truncated, symlinks, too_deep)


def single_file_listing(path: Path, label: str) -> TreeListing:
    try:
        info = path.stat()
    except OSError:
        return TreeListing((), 0, 0, True, 0, 0)
    return TreeListing((TreeFile(label, path, info.st_size, info.st_mtime_ns),), 0, 0, False, 0, 0)


def scan_listing(label: str, listing: TreeListing, min_severity: Severity) -> ScanReport:
    floor = SEVERITY_RANK[min_severity]
    hotspots: list[Hotspot] = []
    skipped: list[SkippedFile] = []
    skipped_total = scanned = 0
    spent = 0
    digest = blake3()
    for entry in listing.files:
        if spent + entry.size > MAX_TOTAL_BYTES:
            skipped_total += 1
            if len(skipped) < MAX_SKIP_DETAILS:
                skipped.append(SkippedFile(entry.rel, "byte_budget", f"scan byte budget {MAX_TOTAL_BYTES} reached"))
            continue
        try:
            data = read_capped(entry.path)
        except SourceSkipped as skip:
            skipped_total += 1
            if len(skipped) < MAX_SKIP_DETAILS:
                skipped.append(SkippedFile(entry.rel, skip.reason, skip.detail))
            digest.update(f"{entry.rel}|{skip.reason}\n".encode())
            continue
        spent += len(data)
        result = scan_bytes(entry.rel, entry.path.suffix.lower(), data)
        digest.update(f"{entry.rel}|{result.content_hash}\n".encode())
        if result.skipped is not None:
            skipped_total += 1
            if len(skipped) < MAX_SKIP_DETAILS:
                skipped.append(result.skipped)
        else:
            scanned += 1
        hotspots.extend(h for h in result.hotspots if SEVERITY_RANK[h.severity] >= floor)
    digest.update(listing.fingerprint.encode())
    return ScanReport(
        label=label, digest=digest.hexdigest(), files_scanned=scanned, hotspots=tuple(hotspots),
        skipped=tuple(skipped), skipped_total=skipped_total, unsupported=listing.unsupported,
        not_examined=listing.not_examined, walk_truncated=listing.walk_truncated,
        symlinks=listing.symlinks, too_deep=listing.too_deep,
    )


def scan_pseudocode(label: str, text: str, min_severity: Severity) -> ScanReport:
    result = scan_text(label, text)
    floor = SEVERITY_RANK[min_severity]
    skipped = (result.skipped,) if result.skipped is not None else ()
    return ScanReport(
        label=label, digest=result.content_hash, files_scanned=0 if skipped else 1,
        hotspots=tuple(h for h in result.hotspots if SEVERITY_RANK[h.severity] >= floor),
        skipped=skipped, skipped_total=len(skipped), unsupported=0, not_examined=0,
        walk_truncated=False, symlinks=0, too_deep=0,
    )


def order_hotspots(report: ScanReport) -> tuple[Hotspot, ...]:
    """Files by their worst severity, then path; within a file by severity then line."""
    worst: dict[str, int] = {}
    for h in report.hotspots:
        worst[h.path] = max(worst.get(h.path, 0), SEVERITY_RANK[h.severity])
    return tuple(sorted(
        report.hotspots, key=lambda h: (-worst[h.path], h.path, -SEVERITY_RANK[h.severity], h.line, h.rule)
    ))


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 importer (offline)
# --------------------------------------------------------------------------- #

MAX_SARIF_BYTES: Final = 16 * 1024 * 1024
_MESSAGE_CHARS: Final = 400


class SarifRejected(Exception):
    """The whole report is unusable (not SARIF 2.1.0, unreadable, too deep)."""


class _Reject(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Loose(BaseModel):
    """External tool output: unknown fields are ignored, known fields are type-checked."""

    model_config = ConfigDict(extra="ignore", frozen=True)


class _Message(_Loose):
    text: str | None = None
    markdown: str | None = None


class _ArtifactLocation(_Loose):
    uri: str | None = None


class _Region(_Loose):
    startLine: int | None = Field(default=None, ge=1, le=MAX_SAFE_INTEGER)
    endLine: int | None = Field(default=None, ge=1, le=MAX_SAFE_INTEGER)


class _Physical(_Loose):
    artifactLocation: _ArtifactLocation | None = None
    region: _Region | None = None


class _Location(_Loose):
    physicalLocation: _Physical | None = None


class _RuleRef(_Loose):
    id: str | None = None


class _Result(_Loose):
    ruleId: str | None = None
    ruleIndex: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    rule: _RuleRef | None = None
    level: str | None = None
    message: _Message | None = None
    locations: list[_Location] = Field(default_factory=list)


class _Driver(_Loose):
    name: str | None = None
    rules: list[_RuleRef] = Field(default_factory=list)


class _Tool(_Loose):
    driver: _Driver | None = None


class _Run(_Loose):
    tool: _Tool | None = None
    results: list[object] = Field(default_factory=list)


class _Log(_Loose):
    version: str | None = None
    runs: list[_Run] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SarifFinding:
    record_hash: str
    claim: str
    tool: str
    rule: str
    level: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class SarifBatch:
    tool: str
    file_hash: str
    seen: int
    findings: tuple[SarifFinding, ...]
    rejected: tuple[tuple[str, int], ...]
    duplicates: int
    truncated: int


def _tidy(text: str, limit: int) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(cleaned.split())[:limit]


def resolve_sarif_uri(uri: str, source_root: Path, roots: tuple[Path, ...]) -> Path:
    """Map a SARIF artifact URI to a local path under the allowed roots, or reject it.

    Only relative references and ``file:`` URIs without a remote host are accepted. Anything else
    (http, https, ftp, Windows drive letters, UNC hosts) is rejected without being contacted.
    """
    if not uri or len(uri) > 2_048 or any(ord(ch) < 32 or ord(ch) == 127 for ch in uri):
        raise _Reject("invalid_uri")
    parts = urlsplit(uri)
    if parts.scheme and parts.scheme.lower() != "file":
        raise _Reject("external_uri")
    if parts.scheme and parts.netloc not in {"", "localhost"}:
        raise _Reject("external_uri")
    if not parts.scheme and parts.netloc:
        raise _Reject("external_uri")  # '//host/share' network-path reference
    path_text = unquote(parts.path)
    if "\x00" in path_text or "\\" in path_text:
        raise _Reject("invalid_path")
    if ".." in path_text.split("/"):
        raise _Reject("path_traversal")
    candidate = Path(path_text)
    relative_form = not parts.scheme and not candidate.is_absolute()
    resolved = (source_root / candidate if relative_form else candidate).resolve(strict=False)
    if relative_form and not resolved.is_relative_to(source_root):
        raise _Reject("outside_roots")
    if not any(resolved.is_relative_to(root) for root in roots):
        raise _Reject("outside_roots")
    return resolved


def _line_count(path: Path, cache: dict[Path, int | None]) -> int | None:
    if path not in cache:
        try:
            cache[path] = read_capped(path).count(b"\n") + 1
        except SourceSkipped:
            cache[path] = None
    return cache[path]


def parse_sarif(
    data: bytes, *, source_root: Path, roots: tuple[Path, ...], max_results: int
) -> SarifBatch:
    if len(data) > MAX_SARIF_BYTES:
        raise SarifRejected(f"SARIF file exceeds {MAX_SARIF_BYTES} bytes")
    try:
        log = _Log.model_validate_json(data)
    except ValidationError as exc:
        raise SarifRejected(f"not parseable as SARIF ({exc.error_count()} schema problems)") from exc
    if log.version != "2.1.0":
        raise SarifRejected(f"only SARIF 2.1.0 is supported (got {log.version!r})")
    if not log.runs:
        raise SarifRejected("SARIF report has no runs")

    findings: list[SarifFinding] = []
    rejected: Counter[str] = Counter()
    seen_hashes: set[str] = set()
    duplicates = truncated = seen = 0
    tools: list[str] = []
    line_counts: dict[Path, int | None] = {}
    for run in log.runs:
        driver = run.tool.driver if run.tool is not None and run.tool.driver is not None else _Driver()
        tool = _tidy(driver.name or "unknown-tool", 64)
        if tool not in tools:
            tools.append(tool)
        for item in run.results:
            seen += 1
            if len(findings) >= max_results:
                truncated += 1
                continue
            try:
                finding = _one_result(item, tool, driver, source_root, roots, line_counts)
            except _Reject as bad:
                rejected[bad.reason] += 1
                continue
            if finding.record_hash in seen_hashes:
                duplicates += 1
                continue
            seen_hashes.add(finding.record_hash)
            findings.append(finding)
    return SarifBatch(
        tool=", ".join(tools)[:200], file_hash=blake3(data).hexdigest(), seen=seen,
        findings=tuple(findings), rejected=tuple(sorted(rejected.items())), duplicates=duplicates,
        truncated=truncated,
    )


def _one_result(
    item: object, tool: str, driver: _Driver, source_root: Path, roots: tuple[Path, ...],
    line_counts: dict[Path, int | None],
) -> SarifFinding:
    try:
        result = _Result.model_validate(item)
        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (ValidationError, ValueError, RecursionError) as exc:
        raise _Reject("invalid_result") from exc
    location = next(
        (
            loc.physicalLocation for loc in result.locations
            if loc.physicalLocation is not None and loc.physicalLocation.artifactLocation is not None
            and loc.physicalLocation.artifactLocation.uri
        ),
        None,
    )
    if location is None or location.artifactLocation is None or location.artifactLocation.uri is None:
        raise _Reject("no_location")
    path = resolve_sarif_uri(location.artifactLocation.uri, source_root, roots)
    line = location.region.startLine if location.region is not None and location.region.startLine else 1
    if path.is_file():
        count = _line_count(path, line_counts)
        if count is not None and line > count:
            raise _Reject("region_outside_file")
    rule = result.ruleId or (result.rule.id if result.rule is not None else None)
    if rule is None and result.ruleIndex is not None and result.ruleIndex < len(driver.rules):
        rule = driver.rules[result.ruleIndex].id
    rule_text = _tidy(rule or "unknown-rule", 100)
    level = result.level if result.level in {"error", "warning", "note", "none"} else "warning"
    message = ""
    if result.message is not None:
        message = _tidy(result.message.text or result.message.markdown or "", _MESSAGE_CHARS)
    shown = path.relative_to(source_root).as_posix() if path.is_relative_to(source_root) else path.as_posix()
    claim = f"{tool} reports {rule_text} [{level}] at {_tidy(shown, 200)}:{line}" + (f": {message}" if message else "")
    return SarifFinding(
        record_hash=blake3(canonical.encode()).hexdigest(), claim=claim[:1_000], tool=tool,
        rule=rule_text, level=level, path=shown, line=line,
    )


