"""Token-lean source and symbol indexer (the ``morluto/leantoken`` discovery pattern).

Read-only. Gives the model a file's skeleton (symbol names, kinds, line and byte ranges) for a few
dozen tokens, then range-bounded slices on demand. Content is addressed by BLAKE3: the whole-file
``content_hash`` is the provenance of an index, and the router hashes every slice it returns, so
repeats become ``{hash, tokens_saved}`` stubs and ``expected_hash`` short-circuits to
``not_modified``. A changed file changes ``content_hash``; the engine bumps its generation and the
router's cursors and receipts for it go stale.

The C-family outline is a heuristic scanner, not a parser: it masks comments, strings and
preprocessor lines, then reads top-level ``{}`` blocks. It is meant for source trees and decompiler
pseudocode (flat, mostly one function per block), and always reports what it could not understand.
Python uses ``ast``. Text must be valid UTF-8 and free of NUL (smokinggun: reject, never replace).
"""

from __future__ import annotations

import ast
import bisect
import os
import re
import stat
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from blake3 import blake3

from rea_mcp.core.fsafe import open_nofollow

# Hostile Python can raise SyntaxWarning while parsing; it is data, not a problem with this server.
PARSE_NAME: Final = "<rea-source>"
warnings.filterwarnings("ignore", category=SyntaxWarning, module=re.escape(PARSE_NAME))
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_SYMBOLS: Final = 20_000
C_LIKE_SUFFIXES: Final = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".java", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".go", ".rs", ".m", ".mm", ".kt", ".swift", ".php",
})
SOURCE_SUFFIXES: Final = C_LIKE_SUFFIXES | {".py"}

SymbolKind = Literal[
    "function", "method", "struct", "class", "enum", "union", "interface", "trait",
    "namespace", "global", "macro",
]
Language = Literal["c_like", "python"]

_MASK: Final = re.compile(
    rb"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`[^`]*`", re.DOTALL
)
_DIRECTIVE: Final = re.compile(rb"(?m)^[ \t]*#(?:\\\n|[^\n])*")
_DEFINE: Final = re.compile(rb"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)")
_TOKENS: Final = re.compile(rb"[{}();]")
_TRANSPARENT: Final = re.compile(r"^\s*(?:extern\b[^=]*|namespace\b[^=;]*|)\s*$")
_TYPE_KW: Final = re.compile(
    r"\b(struct|union|enum|class|interface|trait|namespace)\b\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)"
)
_FUNC_NAME: Final = re.compile(r"([A-Za-z_~][\w:~$.<>]*)\s*\(")
_CONTROL: Final = frozenset({"if", "for", "while", "switch", "else", "do", "try", "catch", "return", "sizeof"})
_DECL_SKIP: Final = ("typedef", "using", "return", "import", "package", "goto", "break", "continue")
_IDENT: Final = re.compile(r"[A-Za-z_]\w*", re.ASCII)
_RUST_TYPED: Final = re.compile(r"([A-Za-z_]\w*)\s*:(?!:)")


_CONTROL_WORDS: Final = frozenset({"if", "for", "while", "switch", "else", "do", "try", "catch"})
_Emit = Callable[[str, SymbolKind, int, int, str], None]
_TYPE_KINDS: Final[dict[str, SymbolKind]] = {
    "struct": "struct", "union": "union", "enum": "enum", "class": "class",
    "interface": "interface", "trait": "trait", "namespace": "namespace",
}


class SourceSkipped(Exception):
    """A file or text that cannot be indexed. ``reason`` is a stable code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    kind: SymbolKind
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    signature: str


@dataclass(frozen=True, slots=True)
class IndexedSource:
    label: str
    data: bytes
    content_hash: str
    language: Language
    symbols: tuple[Symbol, ...]
    line_starts: tuple[int, ...]
    notes: tuple[str, ...]

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def line_of(self, byte_offset: int) -> int:
        return bisect.bisect_right(self.line_starts, byte_offset)

    def slice_lines(self, first: int, last: int) -> str:
        """1-based inclusive lines, clamped to the file."""
        first = max(1, first)
        last = min(self.line_count, last)
        if first > last:
            return ""
        end = self.line_starts[last] if last < self.line_count else len(self.data)
        return self.data[self.line_starts[first - 1] : end].decode("utf-8").rstrip("\n")

    def find(self, name: str) -> Symbol | None:
        return next((s for s in self.symbols if s.name == name), None)


def mask_c_like(data: bytes) -> bytes:
    """Same length as ``data``: comments, string/char literals and directives become spaces."""

    def blank(match: re.Match[bytes]) -> bytes:
        return re.sub(rb"[^\n]", b" ", match.group(0))

    return _MASK.sub(blank, data)


def mask_code(data: bytes) -> bytes:
    """``mask_c_like`` plus preprocessor directives: what is left is code only (same length)."""
    return _DIRECTIVE.sub(lambda m: re.sub(rb"[^\n]", b" ", m.group(0)), mask_c_like(data))


def read_capped(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a regular file without following a final symlink; never more than ``limit`` bytes."""
    try:
        fd = open_nofollow(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise SourceSkipped("unreadable", f"cannot open: {exc.strerror or 'error'}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SourceSkipped("not_regular", "not a regular file")
        if info.st_size > limit:
            raise SourceSkipped("too_large", f"{info.st_size} bytes exceeds {limit}")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise SourceSkipped("unreadable", f"cannot read: {exc.strerror or 'error'}") from exc
    finally:
        os.close(fd)
    if len(data) > limit:
        raise SourceSkipped("too_large", f"exceeds {limit} bytes")
    return data


def language_for(suffix: str) -> Language | None:
    if suffix == ".py":
        return "python"
    return "c_like" if suffix in C_LIKE_SUFFIXES else None


def _line_starts(data: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(i + 1 for i, byte in enumerate(data) if byte == 10 and i + 1 < len(data))
    return tuple(starts)


def index_source(label: str, data: bytes, language: Language) -> IndexedSource:
    if len(data) > MAX_FILE_BYTES:
        raise SourceSkipped("too_large", f"{len(data)} bytes exceeds {MAX_FILE_BYTES}")
    if b"\x00" in data:
        raise SourceSkipped("binary", "contains NUL bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceSkipped("malformed_utf8", f"invalid UTF-8 at byte {exc.start}") from exc
    starts = _line_starts(data)
    notes: list[str] = []
    symbols = _outline_python(text, data, starts, notes) if language == "python" else _outline_c_like(data, starts)
    if len(symbols) > MAX_SYMBOLS:
        notes.append(f"symbol list truncated at {MAX_SYMBOLS}")
        symbols = symbols[:MAX_SYMBOLS]
    return IndexedSource(
        label=label, data=data, content_hash=blake3(data).hexdigest(), language=language,
        symbols=tuple(sorted(symbols, key=lambda s: s.start_byte)), line_starts=starts, notes=tuple(notes),
    )


def index_text(label: str, text: str) -> IndexedSource:
    """Decompiler pseudocode (C-like)."""
    return index_source(label, text.encode("utf-8", errors="backslashreplace"), "c_like")


# --------------------------------------------------------------------------- #
# Python (ast)
# --------------------------------------------------------------------------- #


def _outline_python(text: str, data: bytes, starts: tuple[int, ...], notes: list[str]) -> list[Symbol]:
    try:
        tree = ast.parse(text, filename=PARSE_NAME)
    except SyntaxError as exc:
        notes.append(f"python syntax error at line {exc.lineno}: outline unavailable")
        return []
    out: list[Symbol] = []

    def offset(line: int, col: int) -> int:
        return starts[line - 1] + col

    def add(node: ast.AST, name: str, kind: SymbolKind, header: str) -> None:
        line, col = getattr(node, "lineno", 1), getattr(node, "col_offset", 0)
        end_line, end_col = getattr(node, "end_lineno", line), getattr(node, "end_col_offset", col)
        out.append(Symbol(name, kind, line, end_line, offset(line, col), offset(end_line, end_col), header[:120]))

    def line_text(node: ast.AST) -> str:
        line = getattr(node, "lineno", 1)
        return data[starts[line - 1] : starts[line] if line < len(starts) else len(data)].decode("utf-8").strip()

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(node, node.name, "function", line_text(node))
        elif isinstance(node, ast.ClassDef):
            add(node, node.name, "class", line_text(node))
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    add(child, f"{node.name}.{child.name}", "method", line_text(child))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    add(node, target.id, "global", line_text(node))
    return out


# --------------------------------------------------------------------------- #
# C family (heuristic)
# --------------------------------------------------------------------------- #


def _collapse(raw: bytes) -> str:
    return " ".join(raw.decode("latin-1").split())


def _outline_c_like(data: bytes, starts: tuple[int, ...]) -> list[Symbol]:
    masked = mask_c_like(data)  # directives stay visible until #define names are collected
    out: list[Symbol] = []

    def line_of(pos: int) -> int:
        return bisect.bisect_right(starts, pos)

    def emit(name: str, kind: SymbolKind, begin: int, end: int, header: str) -> None:
        out.append(Symbol(name, kind, line_of(begin), line_of(max(begin, end - 1)), begin, end, header[:120]))

    for directive in _DIRECTIVE.finditer(masked):
        define = _DEFINE.match(directive.group(0))
        if define is not None:
            emit(define.group(1).decode("ascii"), "macro", directive.start(), directive.end(), _collapse(directive.group(0)))
    masked = _DIRECTIVE.sub(lambda m: re.sub(rb"[^\n]", b" ", m.group(0)), masked)

    stack: list[bool] = []  # True = transparent wrapper (extern "C", namespace)
    opaque = 0
    paren = 0
    stmt = 0
    block: tuple[int, bytes] | None = None
    for token in _TOKENS.finditer(masked):
        char, pos = token.group(), token.start()
        if char == b"(":
            paren += 1
        elif char == b")":
            paren = max(0, paren - 1)
        elif char == b"{":
            if opaque == 0 and paren == 0:
                header = masked[stmt:pos]
                if _TRANSPARENT.match(header.decode("latin-1")):
                    stack.append(True)
                    stmt = pos + 1
                    continue
                block = (stmt, header)
            stack.append(False)
            opaque += 1
        elif char == b"}":
            if not stack:
                continue
            if stack.pop():
                stmt = pos + 1
                continue
            opaque -= 1
            if opaque == 0 and block is not None:
                begin, header = block
                block = None
                if header.rstrip().endswith(b"="):
                    continue  # initializer: the following ';' emits the global
                _emit_block(emit, masked, begin, header, pos + 1)
                stmt = pos + 1
        elif char == b";" and opaque == 0 and paren == 0:
            _emit_decl(emit, masked[stmt:pos], stmt)
            stmt = pos + 1
    return out


def _lead(masked: bytes, begin: int, header: bytes) -> int:
    return begin + (len(header) - len(header.lstrip()))


def _emit_block(emit: _Emit, masked: bytes, begin: int, header: bytes, end: int) -> None:
    text = _collapse(header)
    start = _lead(masked, begin, header)
    first_word = text.split(" ", 1)[0] if text else ""
    if "(" in text and first_word not in _CONTROL_WORDS:
        for match in _FUNC_NAME.finditer(text):
            if match.group(1) not in _CONTROL:
                emit(match.group(1), "function", start, end, text)
                return
    kw = _TYPE_KW.search(text)
    if kw is not None and "(" not in text[: kw.start()]:
        name = kw.group(2)
        emit(name, _TYPE_KINDS[kw.group(1)], start, end, text)
        return
    bare = re.match(r"^(?:typedef\s+)?(struct|union|enum)\b\s*$", text)
    if bare is not None:
        trailer = re.match(rb"\s*([A-Za-z_]\w*)\s*[;,]", masked[end : end + 80])
        name = trailer.group(1).decode("ascii") if trailer is not None else "<anonymous>"
        emit(name, _TYPE_KINDS[bare.group(1)], start, end, text)




def _emit_decl(emit: _Emit, header: bytes, begin: int) -> None:
    text = _collapse(header)
    if not text or text.startswith(_DECL_SKIP) or "(" in text.split("=", 1)[0]:
        return
    before = text.split("=", 1)[0]
    typed = _RUST_TYPED.search(before)
    idents = _IDENT.findall(before)
    if typed is not None:
        name = typed.group(1)
    elif len(idents) >= 2 or ("=" in text and idents):
        name = idents[-1]
    else:
        return
    if name in _CONTROL:
        return
    start = begin + (len(header) - len(header.lstrip()))
    emit(name, "global", start, begin + len(header) + 1, text)
