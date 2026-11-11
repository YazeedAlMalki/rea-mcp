"""Windows portability: the no-follow open, link detection and read-only deletes.

Windows has no ``O_NOFOLLOW``. These tests remove it from ``os`` so the Windows branch of
``open_nofollow`` runs on Linux against real symlinks, and use stand-ins for what Linux cannot create
(a junction, a read-only file Windows refuses to delete).
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from rea_mcp.core import fsafe
from rea_mcp.core.fsafe import (
    binary_flag,
    is_link_stat,
    open_nofollow,
    path_is_link,
    remove_link,
    rmtree_force,
    unlink_force,
)
from rea_mcp.evidence.leantoken_index import SourceSkipped, read_capped
from rea_mcp.registry.catalog import RegistryError, _read_bounded
from rea_mcp.registry.txt_converter import Rejected, read_text_strict


@pytest.fixture
def windows_like(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, "O_NOFOLLOW")


@dataclass(frozen=True)
class FakeStat:
    st_mode: int
    st_reparse_tag: int = 0


def test_regular_file_opens_without_the_posix_flag(tmp_path: Path, windows_like: None) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    fd = open_nofollow(target, os.O_RDONLY)
    try:
        assert os.read(fd, 10) == b"hello"
    finally:
        os.close(fd)


def test_symlink_is_refused_without_the_posix_flag(tmp_path: Path, windows_like: None) -> None:
    real = tmp_path / "real.txt"
    real.write_bytes(b"secret")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(OSError) as raised:
        open_nofollow(link, os.O_RDONLY)
    assert raised.value.errno == errno.ELOOP


def test_dangling_symlink_is_not_created_through(tmp_path: Path, windows_like: None) -> None:
    link = tmp_path / "journal.jsonl"
    link.symlink_to(tmp_path / "victim.txt")
    with pytest.raises(OSError):
        open_nofollow(link, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    assert not (tmp_path / "victim.txt").exists()


def test_append_through_a_symlink_never_touches_the_target(tmp_path: Path, windows_like: None) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"original")
    link = tmp_path / "journal.jsonl"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        open_nofollow(link, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    assert victim.read_bytes() == b"original"


def test_a_file_swapped_in_after_the_open_is_refused(
    tmp_path: Path, windows_like: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"first")
    real_open = os.open
    opened: list[int] = []

    def swapping_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        fd = real_open(path, flags, mode)
        opened.append(fd)
        replacement = Path(path).with_name("replacement.txt")
        replacement.write_bytes(b"second")  # new file, new identity, same name
        os.replace(replacement, path)
        return fd

    monkeypatch.setattr(os, "open", swapping_open)
    with pytest.raises(OSError) as raised:
        open_nofollow(target, os.O_RDONLY)
    assert raised.value.errno == errno.ELOOP
    with pytest.raises(OSError):  # the descriptor was closed, not leaked
        os.fstat(opened[0])


def test_a_file_swapped_in_between_the_check_and_the_open_is_refused(
    tmp_path: Path, windows_like: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"first")
    real_open = os.open

    def swap_then_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        replacement = Path(path).with_name("replacement.txt")
        replacement.write_bytes(b"second")  # allocated while the first file still exists: a new identity
        os.replace(replacement, path)  # replaced after lstat saw the first file
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", swap_then_open)
    with pytest.raises(OSError) as raised:
        open_nofollow(target, os.O_RDONLY)
    assert raised.value.errno == errno.ELOOP


def test_created_file_gets_the_requested_mode(tmp_path: Path, windows_like: None) -> None:
    target = tmp_path / "new.jsonl"
    fd = open_nofollow(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_posix_branch_uses_the_kernel_flag(tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_bytes(b"x")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(OSError) as raised:
        open_nofollow(link, os.O_RDONLY)
    assert raised.value.errno == errno.ELOOP


def test_binary_flag_is_applied_when_the_platform_has_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert binary_flag() == 0
    monkeypatch.setattr(os, "O_BINARY", 0x8000, raising=False)
    assert binary_flag() == 0x8000
    seen: list[int] = []
    real_open = os.open

    def recording_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        seen.append(flags)
        return real_open(path, flags & ~0x8000, mode)

    monkeypatch.setattr(os, "open", recording_open)
    target = tmp_path / "a.txt"
    target.write_bytes(b"x")
    os.close(open_nofollow(target, os.O_RDONLY))
    assert seen and seen[0] & 0x8000


def test_a_junction_counts_as_a_link() -> None:
    mount_point = 0xA0000003
    assert is_link_stat(FakeStat(stat.S_IFDIR | 0o755, st_reparse_tag=mount_point))
    assert is_link_stat(FakeStat(stat.S_IFLNK | 0o777))
    assert not is_link_stat(FakeStat(stat.S_IFDIR | 0o755))
    cloud_placeholder = 0x9000001A  # OneDrive file on demand: a reparse point, but not a link
    assert not is_link_stat(FakeStat(stat.S_IFREG | 0o644, st_reparse_tag=cloud_placeholder))


def test_path_is_link_sees_symlinks_and_junctions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "d"
    folder.mkdir()
    link = tmp_path / "l"
    link.symlink_to(folder)
    assert path_is_link(link)
    assert not path_is_link(folder)
    monkeypatch.setattr(Path, "is_junction", lambda self: self == folder)
    assert path_is_link(folder)


def test_remove_link_deletes_the_link_and_keeps_the_target(tmp_path: Path) -> None:
    folder = tmp_path / "d"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep")
    link = tmp_path / "l"
    link.symlink_to(folder, target_is_directory=True)
    remove_link(link)
    assert not link.is_symlink()
    assert (folder / "keep.txt").read_text() == "keep"


def test_unlink_force_clears_the_read_only_attribute_when_the_first_try_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "pack.idx"
    target.write_text("x")
    real_unlink = Path.unlink
    calls: list[str] = []

    def refuse_once(self: Path, missing_ok: bool = False) -> None:
        calls.append(self.name)
        if len(calls) == 1:
            raise PermissionError(errno.EACCES, "read-only")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse_once)
    unlink_force(target)
    assert calls == ["pack.idx", "pack.idx"]
    assert not target.exists()


def test_rmtree_force_retries_after_making_the_path_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / ".git"
    (root / "objects").mkdir(parents=True)
    pack = root / "objects" / "pack.pack"
    pack.write_text("x")
    real_unlink = os.unlink
    refused: list[str] = []

    def refuse_pack_once(path: str | os.PathLike[str], *args: int, **kwargs: int) -> None:
        if str(path).endswith("pack.pack") and not refused:
            refused.append(str(path))
            raise PermissionError(errno.EACCES, "read-only")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", refuse_pack_once)
    rmtree_force(root)
    assert refused
    assert not root.exists()


def test_corpus_and_source_readers_still_refuse_symlinks_on_windows(tmp_path: Path, windows_like: None) -> None:
    real = tmp_path / "real.c"
    real.write_text("int a;\n")
    link = tmp_path / "link.c"
    link.symlink_to(real)
    with pytest.raises(SourceSkipped):
        read_capped(link)
    assert read_capped(real) == b"int a;\n"
    with pytest.raises(Rejected):
        read_text_strict(link)
    assert read_text_strict(real) == "int a;\n"
    notes = tmp_path / "n.md"
    notes.write_text("# hi\n")
    note_link = tmp_path / "nl.md"
    note_link.symlink_to(notes)
    assert _read_bounded(notes, tmp_path.resolve(), 1000) == b"# hi\n"
    with pytest.raises(RegistryError):
        _read_bounded(note_link, tmp_path.resolve(), 1000)
