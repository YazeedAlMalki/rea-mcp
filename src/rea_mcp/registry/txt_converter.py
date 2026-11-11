"""Deterministic ``.txt`` to ``.md`` conversion for the reference corpus.

The registry indexes Markdown only. This module turns stray plain-text notes into Markdown so nothing
useful is left unindexed, and removes the boilerplate text files that every repository carries
(``requirements.txt``, ``LICENSE.txt`` and friends). It runs inside ``rea-mcp-bootstrap`` and on its own::

    rea-mcp-convert-txt ~/workspace/rea-data/knowledge
    rea-mcp-convert-txt notes/idea.txt

Per file, in order:

* boilerplate names (see :data:`BOILERPLATE`) are deleted unread;
* symlinks (never followed), non-regular files, files over 2 MiB, files containing a NUL byte and files that
  are not strictly valid UTF-8 are rejected, never repaired (the smokinggun rule: reject, never replace);
* a file that looks like a raw disassembly or hex dump is kept verbatim inside a fenced ``text`` block;
* anything else keeps its content, gets a ``# Title`` taken from the file name when it has no top-level
  heading, and has an unclosed code fence closed so it cannot swallow the rest of a rendered page or
  confuse section chunking;
* the result is written atomically with mode ``0600`` to ``<stem>.md`` (``<stem>_txt.md`` when that name is
  taken, then ``<stem>_txt_2.md`` ...) and only then is the original deleted.

Markdown files named ``.markdown`` or ``.MD`` are renamed to ``.md`` the same collision-safe way.
Nothing here reads from or writes to the network.
"""

from __future__ import annotations

import argparse
import errno
import fnmatch
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from rea_mcp.core.fsafe import is_link_stat, open_nofollow, path_is_link, unlink_force

MAX_TXT_BYTES: Final = 2 * 1024 * 1024
BOILERPLATE: Final[tuple[str, ...]] = (
    "requirements*.txt", "constraints*.txt", "license*.txt", "copying*.txt", "notice*.txt",
    "authors*.txt", "version*.txt", "robots.txt", "cmakelists.txt", "manifest.txt", "indexnow*.txt",
)
MAX_NAME_ATTEMPTS: Final = 1000

Kind = Literal["converted", "renamed", "unchanged", "boilerplate", "empty", "rejected", "failed", "ignored"]


class Rejected(Exception):
    """The file must not be converted (unsafe or not text)."""


class ConvertError(Exception):
    """A filesystem problem while converting; the original is left untouched."""


@dataclass(frozen=True, slots=True)
class Outcome:
    kind: Kind
    source: Path
    result: Path | None = None
    detail: str = ""
    removed: bool = False  # the source file no longer exists


@dataclass(frozen=True, slots=True)
class Tally:
    converted: int = 0
    renamed: int = 0
    unchanged: int = 0
    boilerplate: int = 0
    empty: int = 0
    rejected: int = 0
    failed: int = 0

    @classmethod
    def of(cls, outcomes: Sequence[Outcome]) -> Tally:
        def count(kind: Kind) -> int:
            return sum(1 for o in outcomes if o.kind == kind)

        return cls(
            count("converted"), count("renamed"), count("unchanged"), count("boilerplate"),
            count("empty"), count("rejected"), count("failed"),
        )

    def __add__(self, other: Tally) -> Tally:
        return Tally(
            self.converted + other.converted, self.renamed + other.renamed, self.unchanged + other.unchanged,
            self.boilerplate + other.boilerplate, self.empty + other.empty, self.rejected + other.rejected,
            self.failed + other.failed,
        )

    @property
    def markdown_kept(self) -> int:
        """Markdown documents that exist after the run because of, or despite, this pass."""
        return self.converted + self.renamed + self.unchanged

    def summary(self) -> str:
        text = (
            f"{self.converted} converted to Markdown, {self.boilerplate} dropped as boilerplate, "
            f"{self.empty} dropped as empty, {self.rejected} rejected, {self.failed} failed"
        )
        return f"{text}, {self.renamed} renamed to .md" if self.renamed else text


# --------------------------------------------------------------------------- #
# Reading (strict)
# --------------------------------------------------------------------------- #


def is_boilerplate(name: str) -> bool:
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in BOILERPLATE)


def read_text_strict(path: Path) -> str:
    """Return the file's text, or raise :class:`Rejected` with the reason. Never follows a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        if is_link_stat(path.lstat()):
            raise Rejected("symlink")
        fd = open_nofollow(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Rejected("symlink") from exc
        raise Rejected(f"cannot open ({exc.strerror})") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Rejected("not a regular file")
        if info.st_size > MAX_TXT_BYTES:
            raise Rejected("larger than 2 MiB")
        handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        data = handle.read(MAX_TXT_BYTES + 1)
    if len(data) > MAX_TXT_BYTES:
        raise Rejected("larger than 2 MiB")
    if b"\0" in data:
        raise Rejected("binary content (NUL byte)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Rejected("not valid UTF-8") from exc
    return text.removeprefix("\ufeff")


# --------------------------------------------------------------------------- #
# Markdown promotion
# --------------------------------------------------------------------------- #

_FENCE: Final = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_ATX_H1: Final = re.compile(r"^ {0,3}#[ \t]+\S")
_SETEXT_H1: Final = re.compile(r"^ {0,3}=+[ \t]*$")
_TITLE_NOISE: Final = re.compile(r"[`*<>\[\]|\\#]+")
_DUMP_LINE: Final = re.compile(
    r"""^\s*(?:
        (?:0x)?[0-9a-f]{4,16}:?[ \t]+(?:[0-9a-f]{2}[ \t]+){4,}          # objdump / hexdump row
      | [.\w]+:[0-9a-f]{4,16}\b                                          # IDA listing: .text:00401000
      | (?:0x)?[0-9a-f]{6,16}:[ \t]+(?:[0-9a-f]{2}[ \t]+)*[a-z]{2,8}\b   # 00401000: push ebp
      | [\w.$@?]+[ \t]+(?:proc|endp)\b                                   # sub_401000 proc near
      | (?:[0-9a-f]{2}[ \t]+){8,}[0-9a-f]{2}\b                           # bare byte row
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def title_from_stem(stem: str) -> str:
    """``ida_notes-v2`` becomes ``Ida Notes V2``; words that already carry capitals are kept as written."""
    words = [w for w in re.split(r"[\s_\-.]+", _TITLE_NOISE.sub(" ", stem)) if w]
    if not words:
        return "Untitled"
    return " ".join(w if any(c.isupper() for c in w) else w[:1].upper() + w[1:] for w in words)


def fence_state(lines: Sequence[str]) -> tuple[list[bool], str]:
    """Per line: is it inside (or part of) a fenced block; and the fence still open at the end, or ``""``."""
    inside: list[bool] = []
    marker = ""
    for line in lines:
        found = _FENCE.match(line)
        if marker:
            inside.append(True)
            if found and found.group(1)[0] == marker[0] and len(found.group(1)) >= len(marker) and not found.group(2).strip():
                marker = ""
        elif found and not (found.group(1)[0] == "`" and "`" in found.group(2)):
            marker = found.group(1)
            inside.append(True)
        else:
            inside.append(False)
    return inside, marker


def has_h1(lines: Sequence[str], inside: Sequence[bool]) -> bool:
    for index, line in enumerate(lines):
        if inside[index]:
            continue
        if _ATX_H1.match(line):
            return True
        following = index + 1
        if (
            following < len(lines) and not inside[following] and line.strip()
            and not line.startswith(("    ", "\t")) and _SETEXT_H1.match(lines[following])
        ):
            return True
    return False


def looks_like_dump(lines: Sequence[str]) -> bool:
    body = [line for line in lines if line.strip()]
    hits = sum(1 for line in body if _DUMP_LINE.match(line))
    return hits >= 3 and hits * 2 >= len(body)


def render_markdown(text: str, stem: str) -> str | None:
    """Markdown for ``text``, or ``None`` when the text is blank."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return None
    title = title_from_stem(stem)
    if looks_like_dump(lines):
        longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
        fence = "`" * max(3, longest + 1)
        return f"# {title}\n\n{fence}text\n" + "\n".join(lines) + f"\n{fence}\n"
    inside, open_fence = fence_state(lines)
    out: list[str] = []
    if not has_h1(lines, inside):
        out += [f"# {title}", ""]
    out += lines
    if open_fence:
        out.append(open_fence)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Collision-safe atomic placement
# --------------------------------------------------------------------------- #


def _candidates(directory: Path, stem: str, tag: str) -> Iterator[Path]:
    yield directory / f"{stem}.md"
    yield directory / f"{stem}_{tag}.md"
    for number in range(2, MAX_NAME_ATTEMPTS):
        yield directory / f"{stem}_{tag}_{number}.md"


def _claim(source: Path, directory: Path, stem: str, tag: str) -> Path:
    """Hard-link ``source`` to the first free ``.md`` name. ``link`` fails if the name exists, so nothing is overwritten."""
    for candidate in _candidates(directory, stem, tag):
        try:
            os.link(source, candidate)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ConvertError(f"cannot create {candidate.name} ({exc.strerror})") from exc
        return candidate
    raise ConvertError("no free file name")


def write_markdown(directory: Path, stem: str, content: str) -> Path:
    temporary = directory / f".rea-convert-{secrets.token_hex(6)}.tmp"
    try:
        fd = open_nofollow(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        return _claim(temporary, directory, stem, "txt")
    except OSError as exc:
        raise ConvertError(f"cannot write Markdown ({exc.strerror})") from exc
    finally:
        temporary.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Per-file processing
# --------------------------------------------------------------------------- #


def _remove(path: Path) -> bool:
    try:
        unlink_force(path)
    except OSError:
        return False
    return True


def _convert_txt(path: Path, discard_rejected: bool) -> Outcome:
    if is_boilerplate(path.name):
        if _remove(path):
            return Outcome("boilerplate", path, detail="boilerplate file", removed=True)
        return Outcome("failed", path, detail="boilerplate file could not be deleted")
    try:
        text = read_text_strict(path)
    except Rejected as exc:
        removed = discard_rejected and _remove(path)
        return Outcome("rejected", path, detail=str(exc), removed=removed)
    rendered = render_markdown(text, path.stem)
    if rendered is None:
        if _remove(path):
            return Outcome("empty", path, detail="no content", removed=True)
        return Outcome("failed", path, detail="empty file could not be deleted")
    try:
        written = write_markdown(path.parent, path.stem, rendered)
    except ConvertError as exc:
        return Outcome("failed", path, detail=str(exc))
    if not _remove(path):
        return Outcome("failed", path, written, "converted, but the original could not be deleted")
    return Outcome("converted", path, written, removed=True)


def _normalize_markdown(path: Path, discard_rejected: bool) -> Outcome:
    if not stat.S_ISREG(path.lstat().st_mode):  # lstat: a symlink is not a regular file
        removed = discard_rejected and _remove(path)
        return Outcome("rejected", path, detail="symlink or not a regular file", removed=removed)
    if path.suffix == ".md":
        return Outcome("unchanged", path, path)
    try:
        renamed = _claim(path, path.parent, path.stem, path.suffix.lstrip(".").lower())
    except ConvertError as exc:
        return Outcome("failed", path, detail=str(exc))
    renamed.chmod(0o600)
    if not _remove(path):
        return Outcome("failed", path, renamed, "renamed, but the original name could not be removed")
    return Outcome("renamed", path, renamed, removed=True)


def process_file(path: Path, *, discard_rejected: bool) -> Outcome:
    """Convert one ``.txt`` file, or normalize one Markdown file name. Other files are ignored."""
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _convert_txt(path, discard_rejected)
    if suffix in {".md", ".markdown"}:
        return _normalize_markdown(path, discard_rejected)
    return Outcome("ignored", path, detail="not a .txt or Markdown file")


def convert_tree(root: Path, *, discard_rejected: bool) -> list[Outcome]:
    """Process every ``.txt``/Markdown file under ``root``. Symlinked and hidden directories are not entered."""
    outcomes: list[Outcome] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        dirnames[:] = sorted(n for n in dirnames if not n.startswith(".") and not path_is_link(here / n))
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            outcome = process_file(here / name, discard_rejected=discard_rejected)
            if outcome.kind != "ignored":
                outcomes.append(outcome)
    return outcomes


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rea-mcp-convert-txt",
        description="Convert .txt notes to Markdown (the registry indexes .md only) and drop boilerplate text files.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="a .txt file or a folder to convert in place")
    parser.add_argument(
        "--delete-rejected", action="store_true",
        help="also delete .txt files that are unsafe or not text (default: leave them and report)",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, emit: Callable[[str], None] = print) -> int:
    args = build_parser().parse_args(argv)
    outcomes: list[Outcome] = []
    for given in args.paths:
        if path_is_link(given) or not given.exists():
            print(f"rea-mcp-convert-txt: {given}: not found (or a symlink, which is never followed)", file=sys.stderr)
            return 2
        if given.is_dir():
            outcomes += convert_tree(given, discard_rejected=args.delete_rejected)
        elif given.suffix.lower() == ".txt":
            outcomes.append(process_file(given, discard_rejected=args.delete_rejected))
        else:
            print(f"rea-mcp-convert-txt: {given}: not a .txt file or a folder", file=sys.stderr)
            return 2
    for outcome in outcomes:
        if outcome.kind == "converted" and outcome.result is not None:
            emit(f"  converted  {outcome.source} -> {outcome.result.name}")
        elif outcome.kind == "renamed" and outcome.result is not None:
            emit(f"  renamed    {outcome.source} -> {outcome.result.name}")
        elif outcome.kind in {"boilerplate", "empty"}:
            emit(f"  dropped    {outcome.source} ({outcome.detail})")
        elif outcome.kind in {"rejected", "failed"}:
            state = "deleted" if outcome.removed else "left in place"
            emit(f"  {outcome.kind:<10} {outcome.source}: {outcome.detail} ({state})")
    tally = Tally.of(outcomes)
    emit(tally.summary())
    return 1 if any(o.kind in {"rejected", "failed"} and not o.removed for o in outcomes) else 0
