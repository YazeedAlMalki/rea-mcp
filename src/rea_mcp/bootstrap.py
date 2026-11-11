"""``rea-mcp-bootstrap``: one command that prepares a local rea-mcp workspace.

    rea-mcp-bootstrap --workspace ~/workspace/rea-data

What it does, in order:

1. Creates ``targets/``, ``knowledge/`` and ``ledger/`` under the workspace, all mode ``0700``.
2. Shallow-clones the reference repositories into ``knowledge/`` (skipping any already present), then
   strips everything the registry does not read: ``.git``, hidden directories, symlinks, and every file
   that is not Markdown or plain text. Plain-text notes are converted to Markdown and boilerplate text
   files (``requirements.txt``, ``LICENSE.txt``...) are dropped (see ``registry/txt_converter.py``), so
   ``knowledge/`` ends up holding ``.md`` files only. Clones run with hooks disabled, symlinks disabled,
   only HTTPS allowed, no submodules and no credentials, into a private temporary directory that is
   renamed into place only after it has been cleaned. The cloned text stays untrusted reference material.
   ``--convert-txt`` runs the same conversion over everything already in ``knowledge/``.
3. If rootless Podman is installed: pulls the sandbox image and runs the live isolation check.
4. Writes ``mcp.host.json`` with the absolute paths of the workspace.

All process execution goes through ``CommandRunner`` so the logic is testable without git or podman.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Final, Protocol

from rea_mcp import hostconfig
from rea_mcp.adapters.podman_runner import DEFAULT_IMAGE, PodmanScriptRunner
from rea_mcp.core.fsafe import (
    binary_flag,
    is_link_stat,
    path_is_link,
    remove_link,
    rmtree_force,
    unlink_force,
)
from rea_mcp.core.security import (
    AUDIT_ENV,
    LEDGER_DIR_ENV,
    ROOTS_ENV,
    SecurityDenied,
    assert_loopback_url,
)
from rea_mcp.registry.catalog import KNOWLEDGE_DIR_ENV, Catalog, KnowledgeConfigError
from rea_mcp.registry.txt_converter import Outcome, Tally, convert_tree, process_file
from rea_mcp.sandbox_check import Check, verify_sandbox

KEEP_SUFFIXES: Final = frozenset({".md", ".markdown", ".txt"})  # converted to .md on the way in
CLONE_TIMEOUT_S: Final = 300.0
PULL_TIMEOUT_S: Final = 900.0
PROBE_TIMEOUT_S: Final = 30.0
PROVENANCE_NAME: Final = "bootstrap.json"
LEGACY_PROVENANCE_NAME: Final = ".bootstrap.json"
DEFAULT_IDA_PRO_URL: Final = "http://127.0.0.1:13337"
DEFAULT_GHIDRA_URL: Final = "http://127.0.0.1:8080"
IDA_PRO_URL_ENV: Final = "REA_IDA_PRO_URL"
IDA_FREE_URL_ENV: Final = "REA_IDA_FREE_URL"
GHIDRA_URL_ENV: Final = "REA_GHIDRA_URL"
_PASSTHROUGH_ENV: Final = (
    "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TMPDIR", "TEMP", "LANG", "LC_ALL",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE",
)  # deliberately no tokens, no SSH agent, no credential helpers


@dataclass(frozen=True, slots=True)
class RepoSpec:
    owner: str
    name: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"


REPOSITORIES: Final[tuple[RepoSpec, ...]] = tuple(
    RepoSpec(*slug.split("/", 1))
    for slug in (
        "JoasASantos/REA-Prompts",
        "reacher-z/Awesome-REA",
        "morluto/awesome-reverse-engineering",
        "bbylw/rea-cn",
        "AIshihzong/awesome-reverse-engineer-anything",
        "N0zoM1z0/touhou-reverse-engineering",
        "sqwu/rea-gems",
        "miles990/rea-case-rankings",
        "DiscoverBox/awesome-ai-reverse-engineering",
        "kaixinbaba/awesome-rea",
        "zhuyansen/awesome-ai-reverse-engineering",
        "songshikang0111/awesome-REA-cases",
        "heaven-hm/awesome-reverse-engineered-games",
        "aicodeking/leanrea",
        "Fanqi89/dsh-rea",
    )
)


def directory_names(repos: Sequence[RepoSpec] = REPOSITORIES) -> dict[str, str]:
    """Slug -> directory (and so ``rea://cases/`` category). Repo name alone, ``owner__name`` on a clash."""
    counts: dict[str, int] = {}
    for repo in repos:
        counts[repo.name.lower()] = counts.get(repo.name.lower(), 0) + 1
    return {
        repo.slug: f"{repo.owner}__{repo.name}" if counts[repo.name.lower()] > 1 else repo.name
        for repo in repos
    }


# --------------------------------------------------------------------------- #
# Process execution seam
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None, timeout_s: float) -> CommandResult: ...


class SubprocessCommands:
    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None, timeout_s: float) -> CommandResult:
        try:
            done = subprocess.run(  # noqa: S603  (argv is a fixed list built here; no shell)
                list(argv), capture_output=True, text=True, timeout=timeout_s, check=False,
                env=None if env is None else dict(env), stdin=subprocess.DEVNULL, errors="replace",
            )
        except FileNotFoundError:
            return CommandResult(127, "", "command not found")
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"timed out after {int(timeout_s)}s")
        except OSError as exc:
            return CommandResult(126, "", f"cannot execute: {type(exc).__name__}")
        return CommandResult(done.returncode, done.stdout, done.stderr)


def _first_line(text: str, limit: int = 200) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:limit]
    return "no output"


def git_environment(source: Mapping[str, str]) -> dict[str, str]:
    env = {key: source[key] for key in _PASSTHROUGH_ENV if key in source}
    env.update({
        "GIT_TERMINAL_PROMPT": "0",          # never wait for a password
        "GIT_LFS_SKIP_SMUDGE": "1",          # never download LFS payloads
        "GIT_CONFIG_GLOBAL": os.devnull,     # ignore the user's url rewrites, hooks and helpers
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
    })
    return env


def clone_argv(git: str, repo: RepoSpec, destination: Path) -> tuple[str, ...]:
    return (
        git,
        "-c", "core.symlinks=false",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "init.templateDir=",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "transfer.fsckObjects=true",
        "clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules", "--quiet",
        "--", repo.url, str(destination),
    )


# --------------------------------------------------------------------------- #
# Workspace layout
# --------------------------------------------------------------------------- #


class BootstrapError(Exception):
    """A problem that stops the bootstrap (bad path, unsafe permissions)."""


@dataclass(frozen=True, slots=True)
class Layout:
    root: Path
    targets: Path
    knowledge: Path
    ledger: Path

    @property
    def audit_log(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def host_config(self) -> Path:
        return self.root / hostconfig.HOST_CONFIG_NAME

    @property
    def provenance(self) -> Path:
        return self.root / PROVENANCE_NAME  # outside knowledge/, which holds Markdown only


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if is_link_stat(info) or not stat.S_ISDIR(info.st_mode):
        raise BootstrapError(f"{path}: expected a real directory")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and info.st_uid != geteuid():
        raise BootstrapError(f"{path}: owned by another user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        path.chmod(0o700)


def create_layout(workspace: Path) -> Layout:
    root = workspace.expanduser().resolve()
    if root == Path(root.anchor) or root == Path.home().resolve():
        raise BootstrapError("choose a dedicated directory (not the filesystem root or your home folder)")
    if root.exists() and not root.is_dir():
        raise BootstrapError(f"{root}: exists and is not a directory")
    layout = Layout(root, root / "targets", root / "knowledge", root / "ledger")
    for directory in (layout.root, layout.targets, layout.knowledge, layout.ledger):
        _private_dir(directory)
    return layout


# --------------------------------------------------------------------------- #
# Cloning and sanitizing
# --------------------------------------------------------------------------- #


def sanitize_tree(root: Path) -> Tally:
    """Reduce a cloned tree to Markdown documents.

    Removes ``.git``, hidden directories and files, symlinks, and every file that is neither Markdown nor
    ``.txt``. Text files are converted to ``.md`` (boilerplate dropped, unsafe ones deleted), ``.markdown``
    and ``.MD`` are renamed to ``.md``. Never follows a symlink. Directories become ``0700``, files ``0600``.
    """
    outcomes: list[Outcome] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        here = Path(current)
        for name in list(dirnames):
            child = here / name
            if path_is_link(child):
                remove_link(child)
                dirnames.remove(name)
            elif name.startswith("."):
                rmtree_force(child)
                dirnames.remove(name)
        for name in sorted(filenames):
            child = here / name
            regular = stat.S_ISREG(child.lstat().st_mode)
            if regular and not name.startswith(".") and child.suffix.lower() in KEEP_SUFFIXES:
                outcome = process_file(child, discard_rejected=True)
                outcomes.append(outcome)
                if outcome.result is not None:
                    outcome.result.chmod(0o600)
            else:
                unlink_force(child)
    for current, _dirnames, _filenames in os.walk(root, topdown=False, followlinks=False):
        here = Path(current)
        if here != root and not any(here.iterdir()):
            here.rmdir()
        else:
            here.chmod(0o700)
    return Tally.of([o for o in outcomes if o.kind != "ignored"])


@dataclass(frozen=True, slots=True)
class RepoOutcome:
    repo: RepoSpec
    directory: str
    status: str  # "cloned" | "skipped" | "failed"
    detail: str
    files: int = 0
    commit: str = ""
    tally: Tally = Tally()


def acquire(
    repo: RepoSpec, directory: str, knowledge: Path, git: str, commands: CommandRunner, env: Mapping[str, str]
) -> RepoOutcome:
    final = knowledge / directory
    if final.exists() and any(final.iterdir()):
        return RepoOutcome(repo, directory, "skipped", "already present")
    staging = knowledge / f".tmp-{secrets.token_hex(6)}"
    try:
        cloned = commands.run(clone_argv(git, repo, staging), env=env, timeout_s=CLONE_TIMEOUT_S)
        if cloned.returncode != 0:
            return RepoOutcome(repo, directory, "failed", f"git clone failed: {_first_line(cloned.stderr)}")
        head = commands.run((git, "-C", str(staging), "rev-parse", "HEAD"), env=env, timeout_s=PROBE_TIMEOUT_S)
        commit = head.stdout.strip() if head.returncode == 0 else ""
        tally = sanitize_tree(staging)
        kept = tally.markdown_kept
        if kept == 0:
            return RepoOutcome(repo, directory, "failed", "no Markdown or text files in the repository", tally=tally)
        if final.exists():
            final.rmdir()  # an empty leftover directory
        os.replace(staging, final)
        note = f"{kept} files"
        if tally.converted or tally.boilerplate:
            note += f" ({tally.converted} txt converted, {tally.boilerplate} boilerplate dropped)"
        return RepoOutcome(repo, directory, "cloned", note, kept, commit[:40], tally)
    finally:
        rmtree_force(staging)


def clean_stale_staging(knowledge: Path) -> None:
    for leftover in knowledge.glob(".tmp-*"):
        rmtree_force(leftover)


def migrate_legacy_provenance(layout: Layout) -> None:
    """Earlier versions kept the provenance file inside ``knowledge/``; it belongs outside (Markdown only there)."""
    legacy = layout.knowledge / LEGACY_PROVENANCE_NAME
    if path_is_link(legacy):
        remove_link(legacy)
    elif legacy.is_file():
        if layout.provenance.exists():
            legacy.unlink()
        else:
            os.replace(legacy, layout.provenance)


def write_provenance(layout: Layout, outcomes: Sequence[RepoOutcome], now: datetime) -> None:
    path = layout.provenance
    previous: dict[str, object] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                previous = {k: v for k, v in loaded.items() if isinstance(k, str)}
        except (OSError, ValueError):
            previous = {}
    for outcome in outcomes:
        if outcome.status == "cloned":
            previous[outcome.repo.slug] = {
                "directory": outcome.directory, "commit": outcome.commit, "files": outcome.files,
                "txt_converted": outcome.tally.converted, "boilerplate_dropped": outcome.tally.boilerplate,
                "fetched_at": now.isoformat(timespec="seconds"),
            }
    _write_private(path, json.dumps(previous, indent=2, sort_keys=True) + "\n")


def audit_knowledge(knowledge: Path) -> tuple[str, ...]:
    """Relative paths of everything under ``knowledge/`` that is not a regular ``.md`` file."""
    stray: list[str] = []
    for current, _dirnames, filenames in os.walk(knowledge, followlinks=False):
        here = Path(current)
        for name in filenames:
            child = here / name
            if child.suffix != ".md" or not stat.S_ISREG(child.lstat().st_mode):
                stray.append(child.relative_to(knowledge).as_posix())
    return tuple(sorted(stray))


def _write_private(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_flag(), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Podman
# --------------------------------------------------------------------------- #

SandboxVerifier = Callable[[str, str], Sequence[Check]]


def live_sandbox_verifier(podman: str, image: str) -> Sequence[Check]:
    return asyncio.run(verify_sandbox(PodmanScriptRunner(image=image, podman_path=podman)))


@dataclass(frozen=True, slots=True)
class PodmanReport:
    available: bool
    ok: bool
    lines: tuple[str, ...]


def check_podman(
    commands: CommandRunner,
    which: Callable[[str], str | None],
    image: str,
    verifier: SandboxVerifier,
    env: Mapping[str, str],
) -> PodmanReport:
    podman = which("podman")
    if podman is None:
        return PodmanReport(False, True, ("podman not installed: script_eval stays unavailable (everything else works)",))
    info = commands.run((podman, "info", "--format", "{{.Host.Security.Rootless}}"), env=env, timeout_s=PROBE_TIMEOUT_S)
    if info.returncode != 0:
        return PodmanReport(True, False, (f"podman is installed but not usable: {_first_line(info.stderr)}",))
    if info.stdout.strip().lower() != "true":
        return PodmanReport(True, False, ("podman is not running rootless; rea-mcp refuses a rootful sandbox",))
    lines = ["rootless podman found"]
    present = commands.run((podman, "image", "exists", image), env=env, timeout_s=PROBE_TIMEOUT_S)
    if present.returncode == 0:
        lines.append(f"image {image} already present")
    else:
        pulled = commands.run((podman, "pull", "--quiet", image), env=env, timeout_s=PULL_TIMEOUT_S)
        if pulled.returncode != 0:
            return PodmanReport(True, False, (*lines, f"could not pull {image}: {_first_line(pulled.stderr)}"))
        lines.append(f"pulled {image}")
    checks = verifier(podman, image)
    lines += [f"{'ok  ' if c.ok else 'FAIL'} {c.name}: {c.detail}" for c in checks]
    return PodmanReport(True, all(c.ok for c in checks), tuple(lines))


# --------------------------------------------------------------------------- #
# Host config
# --------------------------------------------------------------------------- #


def _installed() -> bool:
    try:
        metadata.version("rea-mcp")
    except metadata.PackageNotFoundError:
        return False
    return True


def build_host_server(
    layout: Layout, urls: Mapping[str, str], python: str, *, installed: bool, source_root: Path
) -> hostconfig.HostServer:
    env = {
        ROOTS_ENV: os.pathsep.join([str(layout.targets), str(layout.knowledge)]),
        KNOWLEDGE_DIR_ENV: str(layout.knowledge),
        LEDGER_DIR_ENV: str(layout.ledger),
        AUDIT_ENV: str(layout.audit_log),
        **urls,
    }
    if not installed:  # running from a source checkout: let the host find the package too
        env["PYTHONPATH"] = str(source_root)
    return hostconfig.HostServer(command=python, args=("-m", "rea_mcp"), env=env)


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #


def _url(value: str) -> str:
    """argparse type: a loopback URL, or ``none`` to leave that backend unconfigured."""
    if value.lower() == "none":
        return ""
    try:
        return assert_loopback_url(value)
    except SecurityDenied as exc:
        raise argparse.ArgumentTypeError(exc.message) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rea-mcp-bootstrap",
        description="Prepare a local rea-mcp workspace: folders, reference corpus, sandbox image, host config.",
    )
    parser.add_argument("--workspace", type=Path, required=True, help="directory to create/use, e.g. ~/workspace/rea-data")
    parser.add_argument("--ida-pro-url", type=_url, default=DEFAULT_IDA_PRO_URL, help=f"default {DEFAULT_IDA_PRO_URL}; 'none' to omit")
    parser.add_argument("--ida-free-url", type=_url, default="none", help="IDA Free bridge URL (off by default; shares port 13337 with IDA Pro)")
    parser.add_argument("--ghidra-url", type=_url, default=DEFAULT_GHIDRA_URL, help=f"default {DEFAULT_GHIDRA_URL}; 'none' to omit")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help=f"sandbox image (default {DEFAULT_IMAGE})")
    parser.add_argument("--only", nargs="+", metavar="REPO", help="clone only these repositories (by name or owner/name)")
    parser.add_argument("--skip-clone", action="store_true", help="do not touch the knowledge corpus")
    parser.add_argument(
        "--convert-txt", action="store_true",
        help="also convert every .txt already in knowledge/ to Markdown (and drop boilerplate text files)",
    )
    parser.add_argument("--skip-podman", action="store_true", help="do not check Podman or pull the image")
    parser.add_argument("--git", default=None, help="path to git (default: first on PATH)")
    return parser


def select_repositories(only: Sequence[str] | None) -> tuple[RepoSpec, ...]:
    if not only:
        return REPOSITORIES
    wanted = {item.lower() for item in only}
    chosen = tuple(r for r in REPOSITORIES if r.slug.lower() in wanted or r.name.lower() in wanted)
    known = {r.slug.lower() for r in chosen} | {r.name.lower() for r in chosen}
    unknown = sorted(wanted - known)
    if unknown:
        raise BootstrapError(f"unknown repositories: {', '.join(unknown)}")
    return chosen


def run_bootstrap(
    args: argparse.Namespace,
    *,
    commands: CommandRunner,
    which: Callable[[str], str | None],
    verifier: SandboxVerifier,
    emit: Callable[[str], None],
    environ: Mapping[str, str],
    now: datetime,
) -> int:
    repos = select_repositories(args.only)
    layout = create_layout(args.workspace)
    emit(f"workspace   {layout.root}  (targets/, knowledge/, ledger/ created with mode 0700)")
    migrate_legacy_provenance(layout)
    failures = 0
    text_tally = Tally()

    if args.skip_clone:
        emit("knowledge   clone step skipped (--skip-clone)")
    else:
        git = args.git or which("git")
        if git is None:
            raise BootstrapError("git was not found on PATH (install it, or use --git PATH, or --skip-clone)")
        clean_stale_staging(layout.knowledge)
        names = directory_names()
        env = git_environment(environ)
        outcomes: list[RepoOutcome] = []
        for repo in repos:
            outcome = acquire(repo, names[repo.slug], layout.knowledge, git, commands, env)
            outcomes.append(outcome)
            tag = {"cloned": "ok  ", "skipped": "skip", "failed": "FAIL"}[outcome.status]
            emit(f"  [{tag}] {repo.slug:<48} {outcome.detail}")
        failures += sum(1 for o in outcomes if o.status == "failed")
        for outcome in outcomes:
            text_tally += outcome.tally
        write_provenance(layout, outcomes, now)

    if args.convert_txt:
        swept = Tally.of(convert_tree(layout.knowledge, discard_rejected=True))
        emit(f"txt sweep   knowledge/: {swept.summary()}")
        text_tally += swept
    if not args.skip_clone or args.convert_txt:
        emit(f"txt         {text_tally.summary()}")

    stray = audit_knowledge(layout.knowledge)
    if stray:
        emit(f"corpus      FAIL: {len(stray)} file(s) in knowledge/ are not Markdown, e.g. {stray[0]}"
             " (run again with --convert-txt)")
        failures += 1
    else:
        emit("corpus      audit OK: every file in knowledge/ is a .md file")

    try:
        catalog = Catalog.build(layout.knowledge, [layout.knowledge], lambda text: text)
        emit(f"corpus      indexed OK: {catalog.document_count()} documents in {len(catalog.local_categories())} categories"
             f" ({len(catalog.skipped())} files skipped)")
        if catalog.document_count() == 0 and not args.skip_clone:
            emit("corpus      FAIL: nothing was indexed")
            failures += 1
    except KnowledgeConfigError as exc:
        emit(f"corpus      FAIL: {exc}")
        failures += 1

    if args.skip_podman:
        emit("sandbox     podman step skipped (--skip-podman)")
    elif os.name == "nt":
        emit("sandbox     podman step skipped (the rootless sandbox is Linux-only; script_eval stays disabled on Windows)")
    else:
        report = check_podman(commands, which, args.image, verifier, environ)
        for number, line in enumerate(report.lines):
            emit(("sandbox     " if number == 0 else "            ") + line)
        if report.available and not report.ok:
            failures += 1

    urls = {
        name: value
        for name, value in ((IDA_PRO_URL_ENV, args.ida_pro_url), (IDA_FREE_URL_ENV, args.ida_free_url), (GHIDRA_URL_ENV, args.ghidra_url))
        if value
    }
    server = build_host_server(
        layout, urls, sys.executable, installed=_installed(), source_root=Path(__file__).resolve().parent.parent
    )
    _write_private(layout.host_config, hostconfig.render(server))
    emit(f"host config {layout.host_config}")
    emit("")
    emit(f"next: rea-mcp-doctor --host-config {layout.host_config}")
    emit(f"then import {layout.host_config} into your MCP host (it is the standard mcpServers format).")
    return 1 if failures else 0


def main(
    argv: Sequence[str] | None = None,
    *,
    commands: CommandRunner | None = None,
    which: Callable[[str], str | None] = shutil.which,
    verifier: SandboxVerifier = live_sandbox_verifier,
    emit: Callable[[str], None] = print,
    environ: Mapping[str, str] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_bootstrap(
            args,
            commands=commands if commands is not None else SubprocessCommands(),
            which=which,
            verifier=verifier,
            emit=emit,
            environ=os.environ if environ is None else environ,
            now=now(),
        )
    except BootstrapError as exc:
        print(f"rea-mcp-bootstrap: {exc}", file=sys.stderr)
        return 2
