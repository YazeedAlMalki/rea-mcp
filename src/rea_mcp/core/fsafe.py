"""Portable "never follow a link" file access.

POSIX has ``O_NOFOLLOW``. Windows does not, so there a file is opened only after ``lstat`` shows the
name is not a link, and the opened handle is then checked to be the same file that ``lstat`` saw (so a
link swapped in between is caught, and nothing is read or written through it). A Windows *junction* is
a link too: ``Path.is_symlink`` is False for it, so every walk here also asks ``is_junction``.

Everything that opens an untrusted path goes through :func:`open_nofollow`; everything that decides
whether to descend into a directory entry goes through :func:`entry_is_link` / :func:`path_is_link`.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from pathlib import Path
from typing import Protocol

_LINK_TAGS = (
    getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C),
    getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003),
)


def binary_flag() -> int:
    """``O_BINARY`` on Windows (no newline translation, no Ctrl-Z end of file), 0 elsewhere."""
    return int(getattr(os, "O_BINARY", 0))


class _HasMode(Protocol):
    @property
    def st_mode(self) -> int: ...


def is_link_stat(info: _HasMode) -> bool:
    """True for a symlink, and on Windows for a junction (mount point)."""
    if stat.S_ISLNK(info.st_mode):
        return True
    tag = getattr(info, "st_reparse_tag", 0)
    return isinstance(tag, int) and tag in _LINK_TAGS


def path_is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def entry_is_link(entry: os.DirEntry[str]) -> bool:
    return entry.is_symlink() or entry.is_junction()


class _Retry(Protocol):
    def __call__(self, target: str, /) -> object: ...


def _make_writable_and_retry(function: _Retry, target: str, error: BaseException) -> None:
    """``shutil.rmtree`` hook: Windows refuses to delete read-only files (git packfiles are)."""
    del error
    try:
        os.chmod(target, stat.S_IWRITE)
        function(target)
    except OSError:
        pass


def rmtree_force(path: Path) -> None:
    """Delete a tree, including read-only files. Never follows links out of it; errors are ignored."""
    shutil.rmtree(path, onexc=_make_writable_and_retry)


def unlink_force(path: Path) -> None:
    """Delete one file, clearing the read-only attribute first if the platform insists."""
    try:
        path.unlink()
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        path.unlink()


def remove_link(path: Path) -> None:
    """Delete a symlink or junction itself (a Windows directory link needs ``rmdir``), never its target."""
    try:
        path.unlink()
    except (IsADirectoryError, PermissionError):
        os.rmdir(path)


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_ino, a.st_dev) == (b.st_ino, b.st_dev)


def _refuse(path: str | os.PathLike[str]) -> OSError:
    return OSError(errno.ELOOP, "refusing to follow a link", os.fspath(path))


def open_nofollow(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
    """``os.open`` that raises ``OSError(ELOOP)`` when the final component is a link."""
    flags |= binary_flag()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if isinstance(nofollow, int):
        return os.open(path, flags | nofollow, mode)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        before = None
    if before is not None and is_link_stat(before):
        raise _refuse(path)
    fd = os.open(path, flags, mode)
    try:
        opened = os.fstat(fd)
        after = os.lstat(path)
        if is_link_stat(after) or not _same_file(opened, after):
            raise _refuse(path)
        if before is not None and not _same_file(before, opened):
            raise _refuse(path)
    except BaseException:
        os.close(fd)
        raise
    return fd
