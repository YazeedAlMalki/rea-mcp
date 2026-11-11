"""Phase 5: turnkey bootstrap (git/podman mocked) and the live doctor (bridges faked over httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Protocol

import httpx
import pytest
from test_phase2 import README_TOOLS, SPEC_TOOLS, FakeGhidra, FakeMcp, mcp_client, text

from rea_mcp import bootstrap, doctor, hostconfig
from rea_mcp.adapters.base import LoopbackHttp, McpHttpClient
from rea_mcp.adapters.ghidra import GhidraBackend
from rea_mcp.adapters.ida_free import IdaFreeBackend
from rea_mcp.adapters.ida_pro import IdaProBackend
from rea_mcp.bootstrap import CommandResult, RepoSpec
from rea_mcp.core.models import BackendItem, BackendResult
from rea_mcp.core.router import BackendError, ScriptFile
from rea_mcp.registry import txt_converter
from rea_mcp.registry.catalog import Catalog
from rea_mcp.sandbox_check import Check, SandboxFacts, evaluate, verify_sandbox

NOW = datetime(2026, 11, 7, tzinfo=UTC)
GIT = "/usr/bin/git"
PODMAN = "/usr/bin/podman"
IMAGE = "docker.io/library/python:3.12-slim"


# --------------------------------------------------------------------------- #
# Fake git / podman
# --------------------------------------------------------------------------- #


class FakeCommands:
    """Stands in for ``subprocess``: records argv, materialises clones, answers podman queries."""

    def __init__(
        self,
        *,
        fail_clone: Sequence[str] = (),
        rootless: str = "true",
        image_present: bool = False,
        pull_ok: bool = True,
        info_ok: bool = True,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.envs: list[Mapping[str, str] | None] = []
        self.fail_clone = tuple(fail_clone)
        self.rootless = rootless
        self.image_present = image_present
        self.pull_ok = pull_ok
        self.info_ok = info_ok

    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None, timeout_s: float) -> CommandResult:
        call = tuple(argv)
        self.calls.append(call)
        self.envs.append(env)
        if call[0] == GIT:
            return self._git(call)
        if call[0] == PODMAN:
            return self._podman(call)
        return CommandResult(127, "", "command not found")

    def _git(self, call: tuple[str, ...]) -> CommandResult:
        if "clone" in call:
            url, destination = call[-2], Path(call[-1])
            if any(url.endswith(f"/{slug}.git") for slug in self.fail_clone):
                return CommandResult(128, "", "fatal: repository not found\nhint: x")
            destination.mkdir(parents=True)
            (destination / ".git").mkdir()
            (destination / ".git" / "config").write_text("[core]\n")
            (destination / "README.md").write_text(f"# {url}\n\nreverse engineering notes\n")
            (destination / "notes").mkdir()
            (destination / "notes" / "case.txt").write_text("a case study\n")
            (destination / "requirements.txt").write_text("httpx==0.27\n")
            (destination / "LICENSE.txt").write_text("Apache License\n")
            (destination / "binary.txt").write_bytes(b"ab\0cd")
            (destination / "latin1.txt").write_bytes(b"caf\xe9")
            (destination / "logo.png").write_bytes(b"\x89PNG")
            (destination / "run.sh").write_text("#!/bin/sh\n")
            (destination / "escape.md").symlink_to("/etc/passwd")
            (destination / "linked").symlink_to("/etc")
            (destination / ".github").mkdir()
            (destination / ".github" / "ci.md").write_text("hidden\n")
            return CommandResult(0, "", "")
        if "rev-parse" in call:
            return CommandResult(0, "a" * 40 + "\n", "")
        return CommandResult(1, "", "unexpected git call")

    def _podman(self, call: tuple[str, ...]) -> CommandResult:
        if call[1] == "info":
            return CommandResult(0 if self.info_ok else 125, self.rootless + "\n", "" if self.info_ok else "cannot connect")
        if call[1:3] == ("image", "exists"):
            return CommandResult(0 if self.image_present else 1, "", "")
        if call[1] == "pull":
            return CommandResult(0 if self.pull_ok else 125, "", "" if self.pull_ok else "network unreachable")
        return CommandResult(1, "", "unexpected podman call")

    def clones(self) -> list[tuple[str, ...]]:
        return [c for c in self.calls if "clone" in c]


def which_with(*present: str) -> Callable[[str], str | None]:
    paths = {"git": GIT, "podman": PODMAN}
    return lambda name: paths[name] if name in present else None


def verifier_ok(podman: str, image: str) -> Sequence[Check]:
    return (Check("sandbox starts", True, "probe ran"), Check("no network", True, "outbound blocked"))


def verifier_bad(podman: str, image: str) -> Sequence[Check]:
    return (Check("sandbox starts", True, "probe ran"), Check("no network", False, "outbound reachable"))


def run_main(
    workspace: Path,
    *extra: str,
    commands: FakeCommands | None = None,
    which: Callable[[str], str | None] | None = None,
    verifier: Callable[[str, str], Sequence[Check]] = verifier_ok,
    environ: Mapping[str, str] | None = None,
) -> tuple[int, list[str]]:
    lines: list[str] = []
    code = bootstrap.main(
        ["--workspace", str(workspace), *extra],
        commands=commands if commands is not None else FakeCommands(),
        which=which if which is not None else which_with("git"),
        verifier=verifier,
        emit=lines.append,
        environ=environ if environ is not None else {},
        now=lambda: NOW,
    )
    return code, lines


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# --------------------------------------------------------------------------- #
# Bootstrap: layout, repositories, sanitizing
# --------------------------------------------------------------------------- #


def test_fifteen_repositories_with_unique_directories() -> None:
    assert len(bootstrap.REPOSITORIES) == 15
    assert RepoSpec("JoasASantos", "REA-Prompts") in bootstrap.REPOSITORIES
    names = bootstrap.directory_names()
    assert len(set(names.values())) == 15
    assert all("/" not in n and not n.startswith(".") for n in names.values())
    assert all(r.url == f"https://github.com/{r.owner}/{r.name}.git" for r in bootstrap.REPOSITORIES)


def test_layout_is_created_private_and_tightens_loose_directories(tmp_path: Path) -> None:
    root = tmp_path / "rea-data"
    (root / "ledger").mkdir(parents=True, mode=0o755)
    (root / "ledger").chmod(0o755)
    layout = bootstrap.create_layout(root)
    for directory in (layout.root, layout.targets, layout.knowledge, layout.ledger):
        assert directory.is_dir() and mode(directory) == 0o700


def test_layout_refuses_filesystem_root_home_files_and_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.create_layout(Path("/"))
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.create_layout(tmp_path)
    afile = tmp_path / "file"
    afile.write_text("x")
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.create_layout(afile)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "ws"
    link.mkdir()
    (link / "targets").symlink_to(real)
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.create_layout(link)


def test_sanitize_keeps_only_regular_markdown_and_text(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref")
    (root / "docs" / "deep").mkdir(parents=True)
    (root / "docs" / "deep" / "a.MD").write_text("a")
    (root / "docs" / "b.markdown").write_text("b")
    (root / "docs" / "c.txt").write_text("c")
    (root / "docs" / "d.py").write_text("print()")
    (root / "docs" / "e.md").write_text("already markdown")
    (root / "docs" / "e.md").chmod(0o644)
    (root / "docs" / "e.png").write_bytes(b"\x89PNG")
    (root / ".hidden").mkdir()
    (root / ".hidden" / "x.md").write_text("x")
    (root / ".dot.md").write_text("hidden file")
    (root / "empty" / "only-binary").mkdir(parents=True)
    (root / "empty" / "only-binary" / "f.bin").write_bytes(b"\0")
    outside = tmp_path / "outside.md"
    outside.write_text("secret")
    (root / "link.md").symlink_to(outside)
    (root / "linkdir").symlink_to(tmp_path)

    tally = bootstrap.sanitize_tree(root)

    survivors = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() or p.is_symlink())
    assert survivors == ["docs/b.md", "docs/c.md", "docs/deep/a.md", "docs/e.md"]
    assert (tally.markdown_kept, tally.converted, tally.renamed, tally.unchanged) == (4, 1, 2, 1)
    assert (root / "docs" / "c.md").read_text() == "# C\n\nc\n" and (root / "docs" / "b.md").read_text() == "b"
    assert not (root / ".git").exists() and not (root / ".hidden").exists() and not (root / "empty").exists()
    assert outside.read_text() == "secret"  # symlink target untouched
    assert {mode(p) for p in root.rglob("*.md")} == {0o600}
    assert mode(root / "docs") == 0o700


def test_clone_argv_is_hardened_and_env_has_no_secrets(tmp_path: Path) -> None:
    argv = bootstrap.clone_argv(GIT, RepoSpec("o", "r"), tmp_path / "dest")
    joined = " ".join(argv)
    for flag in ("--depth 1", "--no-tags", "--no-recurse-submodules", "--single-branch", "core.symlinks=false",
                 "protocol.allow=never", "protocol.https.allow=always", "transfer.fsckObjects=true"):
        assert flag in joined
    assert argv[-3:] == ("--", "https://github.com/o/r.git", str(tmp_path / "dest"))
    env = bootstrap.git_environment({
        "PATH": "/bin", "HTTPS_PROXY": "http://127.0.0.1:3128", "GITHUB_TOKEN": "ghp_secret", "GIT_SSH_COMMAND": "evil",
        "AWS_SECRET_ACCESS_KEY": "k", "HOME": "/home/u",
    })
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:3128"
    assert not any("secret" in v or "evil" in v for v in env.values())
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env and "GIT_SSH_COMMAND" not in env


# --------------------------------------------------------------------------- #
# Bootstrap: end to end with fakes
# --------------------------------------------------------------------------- #


def test_bootstrap_end_to_end_then_idempotent_rerun(tmp_path: Path) -> None:
    ws = tmp_path / "rea-data"
    fake = FakeCommands()
    code, lines = run_main(ws, commands=fake)
    assert code == 0, lines
    assert len(fake.clones()) == 15
    for name in bootstrap.directory_names().values():
        repo = ws / "knowledge" / name
        assert (repo / "README.md").is_file() and (repo / "notes" / "case.md").is_file()
        assert not list(repo.rglob("*.txt"))
        assert not any(p.name in {".git", ".github", "logo.png", "run.sh", "escape.md", "linked"} for p in repo.rglob("*"))
        assert not any(p.is_symlink() for p in repo.rglob("*"))
    assert not list((ws / "knowledge").glob(".tmp-*"))
    assert all(mode(ws / d) == 0o700 for d in ("", "targets", "knowledge", "ledger"))
    provenance = json.loads((ws / "bootstrap.json").read_text())
    assert "a" * 40 in json.dumps(provenance) and mode(ws / "bootstrap.json") == 0o600
    assert any("indexed OK: 30 documents in 15 categories" in line for line in lines)
    assert any("txt         15 converted to Markdown, 30 dropped as boilerplate, 0 dropped as empty, 30 rejected, 0 failed" in line for line in lines)
    assert any("audit OK" in line for line in lines)
    assert [p for p in (ws / "knowledge").rglob("*") if p.is_file() and p.suffix != ".md"] == []
    assert {mode(p) for p in (ws / "knowledge").rglob("*") if p.is_file()} == {0o600}
    assert {mode(p) for p in (ws / "knowledge").rglob("*") if p.is_dir()} == {0o700}

    again = FakeCommands()
    code, lines = run_main(ws, commands=again)
    assert code == 0 and again.clones() == []
    assert sum("skip" in line and "already present" in line for line in lines) == 15


def test_clone_env_and_git_discovery(tmp_path: Path) -> None:
    fake = FakeCommands()
    run_main(tmp_path / "ws", "--only", "REA-Prompts", commands=fake, environ={"GITHUB_TOKEN": "t", "HTTPS_PROXY": "http://127.0.0.1:1"})
    assert len(fake.clones()) == 1
    env = next(e for e in fake.envs if e is not None)
    assert "GITHUB_TOKEN" not in env and env["HTTPS_PROXY"] == "http://127.0.0.1:1"
    code, _ = run_main(tmp_path / "ws2", "--only", "REA-Prompts", which=which_with())
    assert code == 2  # git not on PATH
    code, _ = run_main(tmp_path / "ws3", "--only", "nope/nothing")
    assert code == 2


def test_clone_failure_is_reported_and_does_not_stop_the_rest(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    code, lines = run_main(ws, commands=FakeCommands(fail_clone=["morluto/awesome-reverse-engineering"]))
    assert code == 1
    assert any("FAIL" in line and "morluto/awesome-reverse-engineering" in line and "repository not found" in line for line in lines)
    assert not (ws / "knowledge" / "awesome-reverse-engineering").exists()
    assert len([d for d in (ws / "knowledge").iterdir() if d.is_dir()]) == 14
    rerun = FakeCommands()
    code, _ = run_main(ws, commands=rerun)
    assert code == 0 and len(rerun.clones()) == 1  # only the missing one is retried


def test_stale_staging_directories_are_removed(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "knowledge" / ".tmp-deadbeef").mkdir(parents=True)
    (ws / "knowledge" / ".tmp-deadbeef" / "x.md").write_text("x")
    code, _ = run_main(ws, "--only", "REA-Prompts")
    assert code == 0 and not (ws / "knowledge" / ".tmp-deadbeef").exists()


def test_repository_without_text_files_fails_closed(tmp_path: Path) -> None:
    class BinaryOnly(FakeCommands):
        def _git(self, call: tuple[str, ...]) -> CommandResult:
            if "clone" in call:
                dest = Path(call[-1])
                dest.mkdir(parents=True)
                (dest / "a.bin").write_bytes(b"\0")
                return CommandResult(0, "", "")
            return super()._git(call)

    ws = tmp_path / "ws"
    code, lines = run_main(ws, "--only", "REA-Prompts", commands=BinaryOnly())
    assert code == 1 and any("no Markdown or text files" in line for line in lines)
    assert not (ws / "knowledge" / "REA-Prompts").exists()


def test_skip_clone_and_skip_podman(tmp_path: Path) -> None:
    fake = FakeCommands()
    code, lines = run_main(tmp_path / "ws", "--skip-clone", "--skip-podman", commands=fake, which=which_with("git", "podman"))
    assert code == 0 and fake.calls == []
    assert any("skipped (--skip-clone)" in line for line in lines) and any("skipped (--skip-podman)" in line for line in lines)


# --------------------------------------------------------------------------- #
# Bootstrap: Podman
# --------------------------------------------------------------------------- #


def podman_run(tmp_path: Path, fake: FakeCommands, verifier: Callable[[str, str], Sequence[Check]] = verifier_ok) -> tuple[int, list[str]]:
    return run_main(tmp_path / "ws", "--skip-clone", commands=fake, which=which_with("git", "podman"), verifier=verifier)


def test_podman_absent_is_a_note_not_a_failure(tmp_path: Path) -> None:
    code, lines = run_main(tmp_path / "ws", "--skip-clone")
    assert code == 0 and any("podman not installed" in line for line in lines)


def test_rootless_podman_pulls_image_and_runs_verification(tmp_path: Path) -> None:
    fake = FakeCommands(image_present=False)
    seen: list[tuple[str, str]] = []

    def spy(podman: str, image: str) -> Sequence[Check]:
        seen.append((podman, image))
        return verifier_ok(podman, image)

    code, lines = podman_run(tmp_path, fake, spy)
    assert code == 0, lines
    assert (PODMAN, "pull", "--quiet", IMAGE) in fake.calls
    assert (PODMAN, "info", "--format", "{{.Host.Security.Rootless}}") in fake.calls
    assert seen == [(PODMAN, IMAGE)]
    assert any("pulled" in line for line in lines) and any("ok   no network" in line for line in lines)


def test_present_image_is_not_pulled(tmp_path: Path) -> None:
    fake = FakeCommands(image_present=True)
    code, lines = podman_run(tmp_path, fake)
    assert code == 0 and not any(c[1:2] == ("pull",) for c in fake.calls)
    assert any("already present" in line for line in lines)


@pytest.mark.parametrize(
    ("fake", "needle"),
    [
        (FakeCommands(rootless="false"), "not running rootless"),
        (FakeCommands(info_ok=False), "not usable"),
        (FakeCommands(pull_ok=False), "could not pull"),
    ],
)
def test_podman_problems_fail_the_bootstrap(tmp_path: Path, fake: FakeCommands, needle: str) -> None:
    ran: list[str] = []

    def never(podman: str, image: str) -> Sequence[Check]:
        ran.append("verifier")
        return verifier_ok(podman, image)

    code, lines = podman_run(tmp_path, fake, never)
    assert code == 1 and any(needle in line for line in lines)
    assert ran == []  # the sandbox is not exercised when the prerequisites are wrong


def test_failed_sandbox_verification_fails_the_bootstrap(tmp_path: Path) -> None:
    code, lines = podman_run(tmp_path, FakeCommands(image_present=True), verifier_bad)
    assert code == 1 and any("FAIL no network: outbound reachable" in line for line in lines)


def test_custom_image_is_used(tmp_path: Path) -> None:
    fake = FakeCommands()
    run_main(tmp_path / "ws", "--skip-clone", "--image", "registry.example/py:1", commands=fake, which=which_with("git", "podman"))
    assert (PODMAN, "pull", "--quiet", "registry.example/py:1") in fake.calls


# --------------------------------------------------------------------------- #
# Bootstrap: host config
# --------------------------------------------------------------------------- #


def test_host_config_has_exact_absolute_paths_and_round_trips(tmp_path: Path) -> None:
    ws = tmp_path / "rea-data"
    code, _ = run_main(ws, "--skip-clone", "--skip-podman")
    assert code == 0
    path = ws / "mcp.host.json"
    assert mode(path) == 0o600
    raw = json.loads(path.read_text())
    server = raw["mcpServers"]["rea"]
    root = ws.resolve()
    assert server["args"] == ["-m", "rea_mcp"] and Path(server["command"]).is_absolute()
    env = server["env"]
    assert env["REA_ALLOWED_ROOTS"] == os.pathsep.join([str(root / "targets"), str(root / "knowledge")])
    assert env["REA_KNOWLEDGE_DIR"] == str(root / "knowledge")
    assert env["REA_LEDGER_DIR"] == str(root / "ledger") and env["REA_AUDIT_LOG"] == str(root / "audit.jsonl")
    assert env["REA_IDA_PRO_URL"] == "http://127.0.0.1:13337" and env["REA_GHIDRA_URL"] == "http://127.0.0.1:8080"
    assert "REA_IDA_FREE_URL" not in env
    assert all(Path(v).is_absolute() for k, v in env.items() if k in {"REA_KNOWLEDGE_DIR", "REA_LEDGER_DIR", "REA_AUDIT_LOG"})
    assert not any(k.startswith(("GITHUB", "AWS", "ANTHROPIC")) for k in env)
    assert hostconfig.load(path).env == env


def test_host_config_url_options(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    run_main(ws, "--skip-clone", "--skip-podman", "--ida-pro-url", "none", "--ida-free-url", "https://127.0.0.1:13338", "--ghidra-url", "none")
    env = hostconfig.load(ws / "mcp.host.json").env
    assert env["REA_IDA_FREE_URL"] == "https://127.0.0.1:13338" and "REA_IDA_PRO_URL" not in env and "REA_GHIDRA_URL" not in env


@pytest.mark.parametrize("bad", ["http://example.com:8080", "http://192.168.1.10:13337", "file:///etc/passwd", "ftp://127.0.0.1"])
def test_non_loopback_backend_urls_are_rejected(tmp_path: Path, bad: str) -> None:
    with pytest.raises(SystemExit):
        bootstrap.build_parser().parse_args(["--workspace", str(tmp_path), "--ghidra-url", bad])


def test_pythonpath_only_when_not_installed(tmp_path: Path) -> None:
    layout = bootstrap.create_layout(tmp_path / "ws")
    src = tmp_path / "src"
    loose = bootstrap.build_host_server(layout, {}, "/usr/bin/python3", installed=False, source_root=src)
    packaged = bootstrap.build_host_server(layout, {}, "/usr/bin/python3", installed=True, source_root=src)
    assert loose.env["PYTHONPATH"] == str(src) and "PYTHONPATH" not in packaged.env


def test_host_config_loader_is_strict(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    for body in ("not json", "{}", '{"mcpServers": {}}', '{"mcpServers": {"rea": {"command": "", "env": {}}}}',
                 '{"mcpServers": {"rea": {"command": "x", "env": {}, "extra": 1}}}'):
        path.write_text(body)
        with pytest.raises(hostconfig.HostConfigError):
            hostconfig.load(path)
    with pytest.raises(hostconfig.HostConfigError):
        hostconfig.load(tmp_path / "missing.json")
    path.write_text("x" * (hostconfig.MAX_HOST_CONFIG_BYTES + 1))
    with pytest.raises(hostconfig.HostConfigError):
        hostconfig.load(path)


def test_script_shim_runs_the_same_entry_point(tmp_path: Path) -> None:
    import subprocess
    import sys

    shim = Path(__file__).resolve().parent.parent / "scripts" / "bootstrap.py"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(shim), "--workspace", str(tmp_path / "ws"), "--skip-clone", "--skip-podman"],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "ws" / "mcp.host.json").is_file()


# --------------------------------------------------------------------------- #
# Sandbox verification (the previously skipped Podman check, logic only)
# --------------------------------------------------------------------------- #


class FakeRunner:
    def __init__(self, result: BackendResult | Exception) -> None:
        self.result = result
        self.scripts: list[str] = []

    async def run(self, code: str, files: Sequence[ScriptFile], timeout_s: float) -> BackendResult:
        self.scripts.append(code)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def probe_result(facts: Mapping[str, object] | str, exit_code: int = 0) -> BackendResult:
    stdout = facts if isinstance(facts, str) else json.dumps(facts)
    return BackendResult(
        items=(BackendItem(label="stdout", text=stdout), BackendItem(label="stderr", text="boom\n"),
               BackendItem(label="exit_code", text=str(exit_code))),
        generation=0,
    )


GOOD_FACTS: dict[str, object] = {"uid": 65534, "network": "blocked", "rootfs": "read-only", "input_dir": "read-only", "interfaces": ["lo"]}


def test_sandbox_facts_evaluation() -> None:
    assert all(c.ok for c in evaluate(SandboxFacts.model_validate_json(json.dumps(GOOD_FACTS))))
    for key, value, failing in (
        ("uid", 0, "unprivileged user"), ("network", "reachable", "no network"), ("interfaces", ["lo", "eth0"], "no network"),
        ("rootfs", "writable", "read-only root filesystem"), ("input_dir", "writable", "read-only input mount"),
    ):
        checks = evaluate(SandboxFacts.model_validate_json(json.dumps({**GOOD_FACTS, key: value})))
        assert [c.name for c in checks if not c.ok] == [failing]


def test_verify_sandbox_paths() -> None:
    from rea_mcp.core.router import SandboxUnavailableError

    good = asyncio.run(verify_sandbox(FakeRunner(probe_result(GOOD_FACTS))))
    assert all(c.ok for c in good) and len(good) == 5
    leaky = asyncio.run(verify_sandbox(FakeRunner(probe_result({**GOOD_FACTS, "network": "reachable"}))))
    assert [c.name for c in leaky if not c.ok] == ["no network"]
    for result in (probe_result(GOOD_FACTS, exit_code=1), probe_result("not json"), SandboxUnavailableError("no podman"),
                   BackendError("sandbox timed out")):
        checks = asyncio.run(verify_sandbox(FakeRunner(result)))
        assert len(checks) == 1 and checks[0].name == "sandbox starts" and not checks[0].ok


# --------------------------------------------------------------------------- #
# Doctor
# --------------------------------------------------------------------------- #


def ida_pro_factory(fake: FakeMcp) -> Callable[[str], IdaProBackend]:
    return lambda url: IdaProBackend(mcp_client(fake))


def ida_free_factory(fake: FakeMcp) -> Callable[[str], IdaFreeBackend]:
    return lambda url: IdaFreeBackend(mcp_client(fake))


def dead_transport(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


def dead_ida(url: str) -> IdaProBackend:
    return IdaProBackend(McpHttpClient(LoopbackHttp("http://127.0.0.1:13337", transport=httpx.MockTransport(dead_transport))))


def dead_ida_free(url: str) -> IdaFreeBackend:
    return IdaFreeBackend(McpHttpClient(LoopbackHttp("http://127.0.0.1:13337", transport=httpx.MockTransport(dead_transport))))


def dead_ghidra(url: str) -> GhidraBackend:
    return GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=httpx.MockTransport(dead_transport)))


def live_ghidra_factory(fake: FakeGhidra) -> Callable[[str], GhidraBackend]:
    return lambda url: GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=fake.transport()))


def healthy_ghidra() -> FakeGhidra:
    fake = FakeGhidra()
    for route in ("/methods", "/segments", "/imports", "/exports", "/strings", "/data", "/namespaces", "/classes", "/symbols"):
        fake.routes[("GET", route)] = lambda p: text("item_one")
    return fake


async def never_catch_all(url: str) -> bool:
    return False


def factories(
    *,
    ida_pro: Callable[[str], doctor.IdaLike] = dead_ida,
    ida_free: Callable[[str], doctor.IdaLike] = dead_ida_free,
    ghidra: Callable[[str], doctor.GhidraLike] = dead_ghidra,
    ghidra_catch_all: Callable[[str], Awaitable[bool]] = never_catch_all,
) -> doctor.Factories:
    """Every doctor test injects all four seams, so none of them can reach the real machine's loopback."""
    return doctor.Factories(ida_pro, ida_free, ghidra, ghidra_catch_all)


def no_sandbox() -> Sequence[Check]:
    raise AssertionError("the sandbox check must only run with --sandbox")


def run_doctor(
    tmp_path: Path, *args: str, env: Mapping[str, str] | None = None, fx: doctor.Factories | None = None,
    sandbox: Callable[[], Sequence[Check]] = no_sandbox, knowledge: bool = False,
) -> tuple[int, str]:
    lines: list[str] = []
    base: dict[str, str] = {"REA_ALLOWED_ROOTS": str(tmp_path), "REA_LEDGER_DIR": str(tmp_path / "ledger")}
    if knowledge:
        corpus = tmp_path / "knowledge" / "repo"
        corpus.mkdir(parents=True, exist_ok=True)
        (corpus / "intro.md").write_text("# Reverse engineering primer\n\nStart with triage and strings.\n")
        base["REA_KNOWLEDGE_DIR"] = str(tmp_path / "knowledge")
    code = doctor.main(
        list(args), emit=lines.append, environ={**base, **(env or {})},
        factories=fx if fx is not None else factories(),
        sandbox=sandbox,
    )
    return code, "\n".join(lines)


def test_ida_pro_profile_is_negotiated_with_unsupported_reasons(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fake.replies["list_funcs"] = "[]"
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    code, out = run_doctor(tmp_path, env={"REA_IDA_PRO_URL": "http://127.0.0.1:13337"}, fx=fxs, knowledge=True)
    assert code == 0, out
    assert "live; negotiated ida-pro-mcp" in out
    assert "11 capabilities active" in out and "0 capabilities active" in out  # ida-pro vs ida-free fit
    assert "callees" in out and "<- not exposed by the server" in out
    assert "live read probe: list_functions(limit=1) answered" in out
    assert "[ok] rea_capabilities" in out and "[ok] corpus index: 1 documents" in out and "HEALTHY" in out


def test_doctor_only_issues_a_single_paged_read_call(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    code, _ = run_doctor(tmp_path, env={"REA_IDA_PRO_URL": "http://127.0.0.1:13337"}, fx=fxs)
    assert code == 0
    assert fake.calls, "the live read probe should have called the bridge"
    assert {name for name, _ in fake.calls} == {"list_functions"}  # only the one read-only listing tool, never a mutator
    assert len(fake.calls) == 1 and fake.calls[0][1]["offset"] == 0  # the single winning profile, first page only


def test_ida_free_profile_is_negotiated(tmp_path: Path) -> None:
    fake = FakeMcp(README_TOOLS)
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    code, out = run_doctor(tmp_path, env={"REA_IDA_FREE_URL": "http://127.0.0.1:13337"}, fx=fxs)
    assert code == 0, out
    assert "fit equally" in out  # identical capability sets: both profiles are reported, none is invented


def test_role_mismatch_warns(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)  # speaks the ida-pro-mcp tool names
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    code, out = run_doctor(tmp_path, env={"REA_IDA_FREE_URL": "http://127.0.0.1:13337"}, fx=fxs)
    assert "configured as ida-free" in out and "ida-pro-mcp fits better" in out
    assert code == 1 and "no configured backend is live and usable" in out  # the configured role resolves nothing


def test_verbose_lists_tools(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    env = {"REA_IDA_PRO_URL": "http://127.0.0.1:13337"}
    _, quiet = run_doctor(tmp_path, env=env, fx=fxs)
    _, loud = run_doctor(tmp_path, "--verbose", env=env, fx=fxs)
    assert "tools (describe_tools):" not in quiet and "tools (describe_tools):" in loud


def test_unreachable_configured_backend_is_unhealthy(tmp_path: Path) -> None:
    code, out = run_doctor(tmp_path, env={"REA_IDA_PRO_URL": "http://127.0.0.1:13337", "REA_GHIDRA_URL": "http://127.0.0.1:8080"})
    assert code == 1 and "not reachable" in out and "UNHEALTHY" in out
    assert "no configured backend is live and usable" in out
    assert "[ok] rea_capabilities" in out  # the smoke test still ran and passed


def test_ghidra_probe_reports_routes_and_failures(tmp_path: Path) -> None:
    fake = healthy_ghidra()
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=live_ghidra_factory(fake))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"}, fx=fxs)
    assert code == 0, out
    assert "live; GhidraMCP" in out and "7/7 read-only listing routes answered" in out
    assert all(method == "GET" for method, _, _ in fake.log)  # never a POST, so nothing is renamed or commented

    partial = healthy_ghidra()
    del partial.routes[("GET", "/imports")]
    partial.routes[("GET", "/segments")] = lambda p: httpx.Response(500, text="boom")
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"},
                           fx=factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=live_ghidra_factory(partial)))
    assert code == 0 and "5/7 read-only listing routes answered" in out and "list_imports  <- " in out
    assert "list_segments" in out


def test_capabilities_are_labelled_probed_live_or_static(tmp_path: Path) -> None:
    fake = healthy_ghidra()
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=live_ghidra_factory(fake))
    _, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"}, fx=fxs)
    assert "7 PROBED_LIVE / 11 STATIC_ROUTE_TABLE / 19 unsupported" in out
    live_block = out.split("PROBED_LIVE (called read-only, answered):")[1].split("STATIC_ROUTE_TABLE")[0]
    static_block = out.split("(matched from the route table; mutating routes are never fired):")[1].split("unsupported:")[0]
    for name in ("list_functions", "list_segments", "list_imports", "list_exports", "list_strings", "list_globals", "list_namespaces"):
        assert name in live_block and name not in static_block
    for name in ("rename_symbol", "set_comment", "set_function_prototype", "decompile"):
        assert name in static_block and name not in live_block
    assert {method for method, _, _ in fake.log} == {"GET"}  # static means "not fired": no POST ever reaches Ghidra

    ida = FakeMcp(SPEC_TOOLS)
    both = factories(ida_pro=ida_pro_factory(ida), ida_free=ida_free_factory(ida), ghidra=dead_ghidra)
    _, out = run_doctor(tmp_path, env={"REA_IDA_PRO_URL": "http://127.0.0.1:13337"}, fx=both)
    assert "1 PROBED_LIVE / 10 TOOL_LIST_MATCH /" in out and "TOOL_LIST_MATCH (matched from the server's tool list; not called):" in out


PAGE = "<!doctype html><html><head><title>My dashboard</title></head><body>app</body></html>"


def catch_all_app(content_type: str, body: str) -> httpx.MockTransport:
    """A web app that answers 200 to every path, like a single-page app behind uvicorn."""
    return httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": content_type}, text=body))


def ghidra_over(transport: httpx.MockTransport) -> Callable[[str], GhidraBackend]:
    return lambda url: GhidraBackend(LoopbackHttp("http://127.0.0.1:8080", transport=transport))


def test_a_web_app_that_serves_html_everywhere_is_not_reported_as_ghidra(tmp_path: Path) -> None:
    fxs = factories(ghidra=ghidra_over(catch_all_app("text/html", PAGE)))  # control says "no catch-all": only the HTML check can catch it
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"}, fx=fxs)
    assert code == 1, out
    assert "something answers, but it is not GhidraMCP (it serves HTML pages)" in out
    assert "live; GhidraMCP" not in out and "PROBED_LIVE" not in out and "no configured backend is live and usable" in out


def test_a_json_catch_all_is_caught_by_the_nonexistent_route_control(tmp_path: Path) -> None:
    transport = catch_all_app("application/json", '["a", "b"]')
    fxs = factories(ghidra=ghidra_over(transport), ghidra_catch_all=lambda url: doctor.live_catch_all(url, transport=transport))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"}, fx=fxs)
    assert code == 1, out
    assert "it returns 200 for routes that do not exist" in out and "live; GhidraMCP" not in out


def test_a_real_looking_ghidra_still_passes_with_the_real_control(tmp_path: Path) -> None:
    fake = healthy_ghidra()  # unknown routes are 404, as in GhidraMCP
    fxs = factories(ghidra=live_ghidra_factory(fake), ghidra_catch_all=lambda url: doctor.live_catch_all(url, transport=fake.transport()))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:8080"}, fx=fxs)
    assert code == 0 and "live; GhidraMCP" in out and "7/7 read-only listing routes answered" in out
    control = [path for method, path, _ in fake.log if path.startswith("/rea-doctor-")]
    assert len(control) == 1 and {method for method, _, _ in fake.log} == {"GET"}


def timing_out_transport(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("no answer", request=request)  # what Windows does for a closed loopback port, to a short limit


def test_a_port_where_every_probe_times_out_is_not_live_and_not_healthy(tmp_path: Path) -> None:
    fxs = factories(ghidra=ghidra_over(httpx.MockTransport(timing_out_transport)))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:18080"}, fx=fxs)
    assert code == 1, out
    assert "no response (every probe timed out: nothing is listening, or it hangs)" in out
    assert "live;" not in out and "STATIC_ROUTE_TABLE (" not in out and "HEALTHY" not in out.replace("UNHEALTHY", "")
    assert "no configured backend is live and usable" in out


def test_something_listening_that_answers_no_ghidra_route_is_not_usable(tmp_path: Path) -> None:
    fake = FakeGhidra()  # every route is a 404 and the control sees no catch-all
    fxs = factories(ghidra=live_ghidra_factory(fake))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:18080"}, fx=fxs)
    assert code == 1, out
    assert "something is listening, but no GhidraMCP listing route answered" in out
    assert "STATIC_ROUTE_TABLE (" not in out and "no configured backend is live and usable" in out


def test_one_timed_out_route_does_not_hide_a_working_ghidra(tmp_path: Path) -> None:
    fake = healthy_ghidra()
    fake.routes[("GET", "/strings")] = lambda p: (_ for _ in ()).throw(httpx.ReadTimeout("slow"))
    fxs = factories(ghidra=live_ghidra_factory(fake))
    code, out = run_doctor(tmp_path, env={"REA_GHIDRA_URL": "http://127.0.0.1:18080"}, fx=fxs)
    assert code == 0 and "live; GhidraMCP" in out and "6/7 read-only listing routes answered" in out


def test_connect_limit_outlasts_the_windows_refusal_delay() -> None:
    from rea_mcp.adapters.base import CONNECT_TIMEOUT_S

    assert CONNECT_TIMEOUT_S >= 3.0  # Windows needs about 2 s to refuse a closed loopback port


def test_catch_all_control_semantics() -> None:
    def verdict(transport: httpx.AsyncBaseTransport) -> bool:
        return asyncio.run(doctor.live_catch_all("http://127.0.0.1:8080/", transport=transport))

    assert verdict(httpx.MockTransport(lambda r: httpx.Response(404))) is False
    assert verdict(httpx.MockTransport(lambda r: httpx.Response(500))) is False
    assert verdict(httpx.MockTransport(lambda r: httpx.Response(200, text="x"))) is True
    assert verdict(httpx.MockTransport(dead_transport)) is False  # nothing listening is not "a catch-all"
    seen: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(404)

    verdict(httpx.MockTransport(record))
    verdict(httpx.MockTransport(record))
    assert len(seen) == 2 and seen[0] != seen[1] and all(p.startswith("/rea-doctor-") for p in seen)


def test_require_all_demands_every_configured_backend(tmp_path: Path) -> None:
    fake = FakeMcp(SPEC_TOOLS)
    fxs = factories(ida_pro=ida_pro_factory(fake), ida_free=ida_free_factory(fake), ghidra=dead_ghidra)
    env = {"REA_IDA_PRO_URL": "http://127.0.0.1:13337", "REA_GHIDRA_URL": "http://127.0.0.1:8080"}
    code, out = run_doctor(tmp_path, env=env, fx=fxs)
    assert code == 0, out  # one live backend is enough by default
    code, out = run_doctor(tmp_path, "--require-all", env=env, fx=fxs)
    assert code == 1 and "not every configured backend is live and usable" in out


def test_no_backend_configured_probes_defaults_informationally(tmp_path: Path) -> None:
    code, out = run_doctor(tmp_path)
    assert code == 0, out
    assert "default probe (not configured)" in out and "No backend URL is configured" in out and "HEALTHY" in out


def test_smoke_test_failures_make_the_doctor_unhealthy(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out = run_doctor(tmp_path, env={"REA_KNOWLEDGE_DIR": str(empty), "REA_ALLOWED_ROOTS": f"{tmp_path}"})
    assert code == 1 and "[FAIL] corpus index" in out


def test_configuration_errors_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = run_doctor(tmp_path, env={"REA_KNOWLEDGE_DIR": str(tmp_path / "outside-of-roots"), "REA_ALLOWED_ROOTS": str(tmp_path / "a")})
    assert code in {1, 2}
    code, _ = run_doctor(tmp_path, "--host-config", str(tmp_path / "missing.json"))
    assert code == 2 and "rea-mcp-doctor" in capsys.readouterr().err


def test_host_config_feeds_the_doctor(tmp_path: Path) -> None:
    ws = tmp_path / "rea-data"
    code, _ = run_main(ws, "--skip-podman", "--only", "REA-Prompts", "--ida-pro-url", "none", "--ghidra-url", "http://127.0.0.1:8080")
    assert code == 0
    lines: list[str] = []
    fxs = factories(ida_pro=dead_ida, ida_free=dead_ida_free, ghidra=live_ghidra_factory(healthy_ghidra()))
    code = doctor.main(["--host-config", str(ws / "mcp.host.json")], emit=lines.append, environ={"REA_ALLOWED_ROOTS": "/nonexistent-override"},
                       factories=fxs, sandbox=no_sandbox)
    out = "\n".join(lines)
    assert code == 0, out
    assert "corpus index: 2 documents" in out  # REA_KNOWLEDGE_DIR came from the host config, overriding the environment
    assert "Ghidra at http://127.0.0.1:8080" in out


def test_sandbox_flag_runs_the_live_check_and_gates_health(tmp_path: Path) -> None:
    code, out = run_doctor(tmp_path, "--sandbox", sandbox=lambda: (Check("sandbox starts", True, "probe ran"),))
    assert code == 0 and "[ok] sandbox: sandbox starts" in out
    code, out = run_doctor(tmp_path, "--sandbox", sandbox=lambda: (Check("no network", False, "outbound reachable"),))
    assert code == 1 and "[FAIL] sandbox: no network" in out


def test_endpoints_from_environment_groups_ida_roles() -> None:
    same = doctor.endpoints_from({"REA_IDA_PRO_URL": "http://127.0.0.1:13337/", "REA_IDA_FREE_URL": "http://127.0.0.1:13337"})
    assert len(same) == 1 and same[0].roles == ("ida-pro", "ida-free")
    mixed = doctor.endpoints_from({"REA_IDA_PRO_URL": "http://127.0.0.1:13337", "REA_GHIDRA_URL": "http://127.0.0.1:8080"})
    assert [e.family for e in mixed] == ["ida", "ghidra"]
    default = doctor.endpoints_from({})
    assert [e.hostport for e in default] == ["127.0.0.1:13337", "127.0.0.1:8080"] and not any(e.configured for e in default)


def test_table_alignment() -> None:
    rows = doctor.table(["A", "Bee"], [["long cell", "x"], ["y", "z"]])
    assert rows[0] == "A          Bee"
    assert set(rows[1].replace(" ", "")) == {"-"}
    assert rows[2] == "long cell  x" and rows[3] == "y          z"


# --------------------------------------------------------------------------- #
# .txt to .md converter
# --------------------------------------------------------------------------- #

MAX = txt_converter.MAX_TXT_BYTES


def put(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def convert(path: Path, *, discard: bool = True) -> txt_converter.Outcome:
    return txt_converter.process_file(path, discard_rejected=discard)


@pytest.mark.parametrize(
    "name",
    ["requirements.txt", "requirements-dev.txt", "Requirements_test.TXT", "constraints.txt", "constraints-3.12.txt",
     "LICENSE.txt", "license-mit.txt", "COPYING.txt", "NOTICE.txt", "AUTHORS.txt", "authors-list.txt",
     "VERSION.txt", "version_info.txt", "robots.txt", "CMakeLists.txt", "MANIFEST.txt", "indexnow.txt", "IndexNow-key.TXT"],
)
def test_boilerplate_text_files_are_deleted_unread(tmp_path: Path, name: str) -> None:
    path = put(tmp_path / name, b"\xff\0 not even text")
    outcome = convert(path)
    assert outcome.kind == "boilerplate" and outcome.removed and not path.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", ["my_requirements.txt", "license-notes-for-ida.md.txt", "readme.txt", "manifest-notes.txt", "versions.md.txt"])
def test_similar_names_are_not_boilerplate(tmp_path: Path, name: str) -> None:
    if name.startswith(("license", "versions")):
        assert txt_converter.is_boilerplate(name) == name.startswith(("license", "version"))
    else:
        outcome = convert(put(tmp_path / name, "real notes"))
        assert outcome.kind == "converted"


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    secret = put(tmp_path / "outside" / "secret.txt", "TOP SECRET")
    link = tmp_path / "notes" / "link.txt"
    link.parent.mkdir()
    link.symlink_to(secret)
    kept = convert(link, discard=False)
    assert (kept.kind, kept.detail, kept.removed) == ("rejected", "symlink", False) and link.is_symlink()
    assert list((tmp_path / "notes").iterdir()) == [link]  # nothing was written from the target
    dropped = convert(link, discard=True)
    assert dropped.removed and not link.exists() and secret.read_text() == "TOP SECRET"
    dangling = tmp_path / "notes" / "dangling.txt"
    dangling.symlink_to(tmp_path / "nowhere")
    assert convert(dangling, discard=True).kind == "rejected" and not dangling.exists()


def test_fifos_and_directories_are_rejected_without_hanging(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.txt"
    os.mkfifo(fifo)
    outcome = convert(fifo, discard=False)
    assert outcome.kind == "rejected" and outcome.detail == "not a regular file" and fifo.exists()
    (tmp_path / "dir.txt").mkdir()
    assert convert(tmp_path / "dir.txt", discard=False).kind == "rejected"


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"ab\0cd", "binary content (NUL byte)"),
        (b"caf\xe9", "not valid UTF-8"),
        (b"\xed\xa0\x80 lone surrogate", "not valid UTF-8"),
        (b"\xff\xfe\x00h\x00i", "binary content (NUL byte)"),  # UTF-16 text is not UTF-8
        (b"a" * (MAX + 1), "larger than 2 MiB"),
    ],
)
def test_unsafe_text_is_rejected_never_repaired(tmp_path: Path, data: bytes, reason: str) -> None:
    path = put(tmp_path / "note.txt", data)
    kept = convert(path, discard=False)
    assert (kept.kind, kept.detail, kept.removed) == ("rejected", reason, False)
    assert path.read_bytes() == data and [p.name for p in tmp_path.iterdir()] == ["note.txt"]
    assert convert(path, discard=True).removed and not path.exists() and list(tmp_path.iterdir()) == []


def test_exactly_two_mib_is_accepted_and_bom_is_stripped(tmp_path: Path) -> None:
    big = put(tmp_path / "big.txt", b"x" * MAX)
    assert convert(big).kind == "converted"
    bom = put(tmp_path / "bom.txt", b"\xef\xbb\xbfhello")
    assert convert(bom).result == tmp_path / "bom.md"
    assert (tmp_path / "bom.md").read_text(encoding="utf-8") == "# Bom\n\nhello\n"


@pytest.mark.parametrize(
    ("stem", "title"),
    [("ida_notes", "Ida Notes"), ("my-crackme.v2", "My Crackme V2"), ("README", "README"), ("IDA pro tips", "IDA Pro Tips"),
     ("---", "Untitled"), ("", "Untitled"), ("a#b`c", "A B C"), ("café_notes", "Café Notes")],
)
def test_title_comes_from_the_file_name(stem: str, title: str) -> None:
    assert txt_converter.title_from_stem(stem) == title


def test_heading_is_synthesized_only_when_there_is_no_top_level_heading() -> None:
    render = txt_converter.render_markdown
    assert render("plain text", "ida_notes") == "# Ida Notes\n\nplain text\n"
    assert render("# Mine\n\nbody\n", "x") == "# Mine\n\nbody\n"
    assert render("Setext Title\n============\nbody", "x") == "Setext Title\n============\nbody\n"
    assert render("## only a subsection", "x") == "# X\n\n## only a subsection\n"
    assert render("#!/bin/sh\necho", "x") == "# X\n\n#!/bin/sh\necho\n"  # a shebang is not a heading
    assert render("```\n# not a heading\n```\n", "snip") == "# Snip\n\n```\n# not a heading\n```\n"
    assert render("\n\n  \n\n", "x") is None and render("", "x") is None


def test_line_endings_and_surrounding_blank_lines_are_normalized() -> None:
    assert txt_converter.render_markdown("\r\n\r\na\r\nb\rc\r\n\r\n", "n") == "# N\n\na\nb\nc\n"
    assert txt_converter.render_markdown("    indented first line\nnext", "n") == "# N\n\n    indented first line\nnext\n"


def test_unclosed_fences_are_closed_and_closed_ones_are_left_alone() -> None:
    render = txt_converter.render_markdown
    assert render("# T\n```c\nint x;", "x") == "# T\n```c\nint x;\n```\n"
    assert render("# T\n~~~~\nraw", "x") == "# T\n~~~~\nraw\n~~~~\n"
    assert render("# T\n```\ncode\n```\nafter", "x") == "# T\n```\ncode\n```\nafter\n"
    # a shorter fence inside a longer one does not close it; the repair uses the opener's length
    assert render("# T\n````\n```\ninner", "x") == "# T\n````\n```\ninner\n````\n"
    # an info string with backticks is not a fence at all
    assert render("# T\n``` not `a` fence\ntext", "x") == "# T\n``` not `a` fence\ntext\n"
    fenced = render("```\nopen", "x")
    assert fenced is not None and fenced.count("```") == 2 and fenced.startswith("# X\n\n```")


OBJDUMP = """\
00401000  55 8b ec 83 ec 10 53 56  57 8b 7d 08 33 f6 89 75
00401010  fc 85 ff 74 2a 8b 07 83  f8 ff 74 23 50 e8 d4 03
00401020  00 00 83 c4 04 85 c0 75  0e 6a 00 ff 75 fc ff 15
"""
IDA_LISTING = """\
.text:00401000 sub_401000      proc near
.text:00401000                 push    ebp
.text:00401001                 mov     ebp, esp
.text:00401003                 sub     esp, 10h
.text:00401006 sub_401000      endp
"""


def test_raw_dumps_are_preserved_verbatim_inside_a_text_fence() -> None:
    for dump in (OBJDUMP, IDA_LISTING, "00401000: push ebp\n00401001: mov ebp, esp\n00401003: sub esp, 0x10\n"):
        rendered = txt_converter.render_markdown(dump, "firmware_dump")
        assert rendered == f"# Firmware Dump\n\n```text\n{dump.rstrip()}\n```\n"
    # a dump that itself contains a code fence gets a longer fence, so it cannot break out
    nasty = OBJDUMP + "```\nnot a fence\n"
    out = txt_converter.render_markdown(nasty, "d")
    assert out is not None and out.startswith("# D\n\n````text\n") and out.endswith("\n````\n")
    # a few address-like lines inside prose are not a dump
    prose = "Notes on the loader.\n00401000  55 8b ec 83 ec 10\nIt then calls the entry point.\nMore thoughts here.\nEven more.\n"
    assert txt_converter.render_markdown(prose, "p") == "# P\n\n" + prose


def test_conversion_is_atomic_collision_safe_private_and_deletes_the_original(tmp_path: Path) -> None:
    mine = put(tmp_path / "a.md", "# mine\n")
    first = convert(put(tmp_path / "a.txt", "note one"))
    assert first.kind == "converted" and first.result == tmp_path / "a_txt.md" and first.removed
    assert not (tmp_path / "a.txt").exists() and mine.read_text() == "# mine\n"
    second = convert(put(tmp_path / "a.txt", "note two"))
    assert second.result == tmp_path / "a_txt_2.md" and (tmp_path / "a_txt.md").read_text() == "# A\n\nnote one\n"
    plain = convert(put(tmp_path / "b.TXT", "free name"))
    assert plain.result == tmp_path / "b.md" and stat.S_IMODE((tmp_path / "b.md").stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.md", "a_txt.md", "a_txt_2.md", "b.md"]  # no temp files left


def test_conversion_never_overwrites_a_symlinked_name(tmp_path: Path) -> None:
    victim = put(tmp_path / "victim.md", "keep me")
    (tmp_path / "n.md").symlink_to(victim)
    outcome = convert(put(tmp_path / "n.txt", "note"))
    assert outcome.result == tmp_path / "n_txt.md" and victim.read_text() == "keep me" and (tmp_path / "n.md").is_symlink()


def test_conversion_is_deterministic(tmp_path: Path) -> None:
    body = "line one\n```py\nunclosed\n"
    first = convert(put(tmp_path / "x" / "same.txt", body)).result
    second = convert(put(tmp_path / "y" / "same.txt", body)).result
    assert first is not None and second is not None and first.read_bytes() == second.read_bytes()


def test_empty_text_files_are_dropped(tmp_path: Path) -> None:
    outcome = convert(put(tmp_path / "blank.txt", " \n\t\n"))
    assert outcome.kind == "empty" and outcome.removed and list(tmp_path.iterdir()) == []


def test_markdown_names_are_normalized_to_lowercase_md(tmp_path: Path) -> None:
    renamed = convert(put(tmp_path / "gem.markdown", "# Gem"))
    assert renamed.kind == "renamed" and renamed.result == tmp_path / "gem.md" and not (tmp_path / "gem.markdown").exists()
    upper = convert(put(tmp_path / "UP.MD", "# Up"))
    assert upper.result == tmp_path / "UP.md"
    put(tmp_path / "dup.md", "first")
    clash = convert(put(tmp_path / "dup.markdown", "second"))
    assert clash.result == tmp_path / "dup_markdown.md" and (tmp_path / "dup.md").read_text() == "first"
    assert convert(tmp_path / "dup.md").kind == "unchanged"
    assert convert(put(tmp_path / "code.py", "x")).kind == "ignored"


def test_convert_tree_skips_hidden_and_symlinked_directories(tmp_path: Path) -> None:
    root = tmp_path / "kb"
    put(root / "a" / "note.txt", "one")
    put(root / ".hidden" / "x.txt", "hidden")
    put(root / ".dot.txt", "hidden file")
    put(root / "requirements.txt", "pkg")
    outside = put(tmp_path / "elsewhere" / "far.txt", "far")
    (root / "linked").symlink_to(outside.parent)
    outcomes = txt_converter.convert_tree(root, discard_rejected=True)
    assert sorted((o.kind, o.source.name) for o in outcomes) == [("boilerplate", "requirements.txt"), ("converted", "note.txt")]
    assert outside.exists() and (root / ".hidden" / "x.txt").exists() and (root / ".dot.txt").exists()
    assert txt_converter.Tally.of(outcomes).summary() == "1 converted to Markdown, 1 dropped as boilerplate, 0 dropped as empty, 0 rejected, 0 failed"
    assert txt_converter.Tally(renamed=2).summary().endswith(", 2 renamed to .md")


def test_cli_converts_folders_and_files_and_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    put(tmp_path / "notes" / "idea.txt", "an idea")
    put(tmp_path / "notes" / "bad.txt", b"x\0")
    put(tmp_path / "single.txt", "solo")
    lines: list[str] = []
    assert txt_converter.main([str(tmp_path / "notes")], emit=lines.append) == 1  # a rejected file is a non-zero exit
    assert (tmp_path / "notes" / "bad.txt").exists() and (tmp_path / "notes" / "idea.md").is_file()
    assert any("rejected" in line and "bad.txt" in line and "left in place" in line for line in lines)
    assert lines[-1] == "1 converted to Markdown, 0 dropped as boilerplate, 0 dropped as empty, 1 rejected, 0 failed"
    assert txt_converter.main(["--delete-rejected", str(tmp_path / "notes")], emit=lines.append) == 0 and not (tmp_path / "notes" / "bad.txt").exists()
    assert txt_converter.main([str(tmp_path / "single.txt")], emit=lines.append) == 0 and (tmp_path / "single.md").is_file()
    assert txt_converter.main([str(tmp_path / "missing")], emit=lines.append) == 2
    assert txt_converter.main([str(tmp_path / "single.md")], emit=lines.append) == 2
    (tmp_path / "ln").symlink_to(tmp_path / "notes")
    assert txt_converter.main([str(tmp_path / "ln")], emit=lines.append) == 2
    assert "never followed" in capsys.readouterr().err


def test_catalog_indexes_markdown_only(tmp_path: Path) -> None:
    put(tmp_path / "repo" / "a.md", "# A\n\nindexed")
    put(tmp_path / "repo" / "b.markdown", "# B\n\nnot indexed")
    put(tmp_path / "repo" / "c.txt", "not indexed")
    catalog = Catalog.build(tmp_path, [tmp_path], lambda text: text)
    assert catalog.document_count() == 1


# --------------------------------------------------------------------------- #
# Bootstrap integration of the converter
# --------------------------------------------------------------------------- #


def test_stray_text_in_the_corpus_fails_the_audit_until_convert_txt_runs(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    assert run_main(ws, "--skip-clone", "--skip-podman")[0] == 0
    put(ws / "knowledge" / "mine" / "idea.txt", "an idea about unpacking")
    put(ws / "knowledge" / "mine" / "requirements.txt", "pkg")
    put(ws / "knowledge" / "mine" / "weird.txt", b"\xff\xfe\x00")
    code, lines = run_main(ws, "--skip-clone", "--skip-podman")
    assert code == 1 and any("3 file(s) in knowledge/ are not Markdown" in line and "--convert-txt" in line for line in lines)
    code, lines = run_main(ws, "--skip-clone", "--skip-podman", "--convert-txt")
    assert code == 0, lines
    assert any(line == "txt sweep   knowledge/: 1 converted to Markdown, 1 dropped as boilerplate, 0 dropped as empty, 1 rejected, 0 failed" for line in lines)
    assert any("audit OK" in line for line in lines) and any("indexed OK: 1 documents" in line for line in lines)
    assert [p.name for p in (ws / "knowledge" / "mine").iterdir()] == ["idea.md"]


def test_a_symlinked_markdown_file_fails_the_audit_and_is_removed_by_the_sweep(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    assert run_main(ws, "--skip-clone", "--skip-podman")[0] == 0
    secret = put(tmp_path / "secret.md", "# secret")
    link = ws / "knowledge" / "repo" / "sneaky.md"
    link.parent.mkdir()
    link.symlink_to(secret)
    code, lines = run_main(ws, "--skip-clone", "--skip-podman")
    assert code == 1 and any("not Markdown, e.g. repo/sneaky.md" in line for line in lines)
    code, _ = run_main(ws, "--skip-clone", "--skip-podman", "--convert-txt")
    assert code == 0 and not link.exists() and secret.read_text() == "# secret"


def test_convert_txt_upgrades_a_corpus_left_by_the_previous_version(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    assert run_main(ws, "--skip-clone", "--skip-podman")[0] == 0
    put(ws / "knowledge" / "old" / "README.md", "# Old")
    put(ws / "knowledge" / "old" / "notes.txt", "old note")
    put(ws / "knowledge" / "old" / "Gem.markdown", "# Gem")
    legacy = put(ws / "knowledge" / ".bootstrap.json", '{"x": 1}')
    legacy.chmod(0o600)
    code, lines = run_main(ws, "--skip-clone", "--skip-podman", "--convert-txt")
    assert code == 0, lines
    assert sorted(p.name for p in (ws / "knowledge" / "old").iterdir()) == ["Gem.md", "README.md", "notes.md"]
    assert not legacy.exists() and json.loads((ws / "bootstrap.json").read_text()) == {"x": 1}


def test_clone_pipeline_counts_conversions_per_repository(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    code, lines = run_main(ws, "--only", "REA-Prompts")
    assert code == 0, lines
    assert any("JoasASantos/REA-Prompts" in line and "2 files (1 txt converted, 2 boilerplate dropped)" in line for line in lines)
    record = json.loads((ws / "bootstrap.json").read_text())["JoasASantos/REA-Prompts"]
    assert record["txt_converted"] == 1 and record["boilerplate_dropped"] == 2


# --------------------------------------------------------------------------- #
# Mutation tests: every guard in the converter must be load-bearing
# --------------------------------------------------------------------------- #


class OutcomeLike(Protocol):
    kind: str
    result: Path | None
    removed: bool


class Processor(Protocol):
    def __call__(self, path: Path, *, discard_rejected: bool) -> OutcomeLike: ...


def exercise(module: ModuleType, base: Path) -> list[str]:
    """Run the converter's contract against ``module``; return the names of the checks that fail."""
    process: Processor = getattr(module, "process_file")
    render: Callable[[str, str], str | None] = getattr(module, "render_markdown")
    max_bytes: int = getattr(module, "MAX_TXT_BYTES")
    failures: list[str] = []
    counter = 0

    def case(name: str, body: Callable[[Path], bool]) -> None:
        nonlocal counter
        counter += 1
        directory = base / f"case{counter}"
        directory.mkdir()
        try:
            ok = body(directory)
        except Exception:  # a mutant may crash; that also counts as caught
            ok = False
        if not ok:
            failures.append(name)

    def boilerplate(d: Path) -> bool:
        outcome = process(put(d / "requirements.txt", "pkg"), discard_rejected=True)
        return outcome.kind == "boilerplate" and not (d / "requirements.txt").exists()

    def symlink(d: Path) -> bool:
        target = put(d / "target.txt", "secret")
        link = d / "link.txt"
        link.symlink_to(target)
        kept = process(link, discard_rejected=False)
        dropped = process(link, discard_rejected=True)
        return kept.kind == "rejected" and not kept.removed and dropped.removed and target.read_text() == "secret"

    def nul(d: Path) -> bool:
        return process(put(d / "n.txt", b"a\0b"), discard_rejected=False).kind == "rejected"

    def oversized(d: Path) -> bool:
        return process(put(d / "n.txt", b"a" * (max_bytes + 1)), discard_rejected=False).kind == "rejected"

    def malformed(d: Path) -> bool:
        return process(put(d / "n.txt", b"caf\xe9"), discard_rejected=False).kind == "rejected"

    def bom(d: Path) -> bool:
        process(put(d / "b.txt", b"\xef\xbb\xbfhi"), discard_rejected=True)
        return (d / "b.md").read_bytes() == b"# B\n\nhi\n"

    def synthesized(d: Path) -> bool:
        return render("text", "ida_notes") == "# Ida Notes\n\ntext\n"

    def kept_heading(d: Path) -> bool:
        return render("# Mine\n\nbody", "x") == "# Mine\n\nbody\n"

    def fenced_heading(d: Path) -> bool:
        return render("```\n# inside\n```", "snip") == "# Snip\n\n```\n# inside\n```\n"

    def repaired_fence(d: Path) -> bool:
        return render("# T\n```c\nint x;", "x") == "# T\n```c\nint x;\n```\n"

    def dump(d: Path) -> bool:
        return render(OBJDUMP, "d") == f"# D\n\n```text\n{OBJDUMP.rstrip()}\n```\n"

    def dump_fence(d: Path) -> bool:
        out = render(OBJDUMP + "```\n", "d")
        return out is not None and out.startswith("# D\n\n````text\n")

    def collision(d: Path) -> bool:
        put(d / "a.md", "mine")
        outcome = process(put(d / "a.txt", "note"), discard_rejected=True)
        return outcome.result == d / "a_txt.md" and (d / "a.md").read_text() == "mine"

    def private(d: Path) -> bool:
        process(put(d / "p.txt", "x"), discard_rejected=True)
        return stat.S_IMODE((d / "p.md").stat().st_mode) == 0o600

    def original_deleted(d: Path) -> bool:
        process(put(d / "o.txt", "x"), discard_rejected=True)
        return not (d / "o.txt").exists() and (d / "o.md").exists()

    def empty(d: Path) -> bool:
        outcome = process(put(d / "e.txt", "  \n"), discard_rejected=True)
        return outcome.kind == "empty" and list(d.iterdir()) == []

    def untitled(d: Path) -> bool:
        return render("x", "---") == "# Untitled\n\nx\n"

    def crlf(d: Path) -> bool:
        return render("a\r\nb", "n") == "# N\n\na\nb\n"

    def left_in_place(d: Path) -> bool:
        path = put(d / "keep.txt", b"\0")
        process(path, discard_rejected=False)
        return path.exists()

    for name, body in (
        ("boilerplate", boilerplate), ("symlink", symlink), ("nul", nul), ("oversized", oversized), ("malformed", malformed),
        ("bom", bom), ("synthesized", synthesized), ("kept_heading", kept_heading), ("fenced_heading", fenced_heading),
        ("repaired_fence", repaired_fence), ("dump", dump), ("dump_fence", dump_fence), ("collision", collision),
        ("private", private), ("original_deleted", original_deleted), ("empty", empty), ("untitled", untitled),
        ("crlf", crlf), ("left_in_place", left_in_place),
    ):
        case(name, body)
    return failures


def load_variant(label: str, replacements: Sequence[tuple[str, str]]) -> ModuleType:
    source = Path(txt_converter.__file__).read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in source, f"mutation target not found: {old!r}"
        source = source.replace(old, new)
    name = f"rea_mcp.registry._mutant_{label}"
    module = ModuleType(name)
    sys.modules[name] = module  # dataclasses look their module up here while the class body runs
    exec(compile(source, name, "exec"), module.__dict__)
    return module


MUTANTS: dict[str, tuple[tuple[str, str], ...]] = {
    "symlink-followed": (
        ('if is_link_stat(path.lstat()):\n            raise Rejected("symlink")', 'if False:\n            raise Rejected("symlink")'),
        ("fd = open_nofollow(path, flags)", "fd = os.open(path, flags)"),
    ),
    "nul-allowed": (('if b"\\0" in data:', "if False:"),),
    "size-unchecked": (("if info.st_size > MAX_TXT_BYTES:", "if False:"), ("if len(data) > MAX_TXT_BYTES:", "if False:")),
    "utf8-repaired": (('data.decode("utf-8")', 'data.decode("utf-8", errors="replace")'),),
    "boilerplate-kept": (("return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in BOILERPLATE)", "return False"),),
    "heading-always-added": (("if not has_h1(lines, inside):", "if True:"),),
    "heading-in-fence-counts": (("        if inside[index]:\n            continue", "        if False:\n            continue"),),
    "fence-left-open": (("    if open_fence:\n", "    if False:\n"),),
    "dump-never": (("return hits >= 3 and hits * 2 >= len(body)", "return False"),),
    "dump-fence-short": (("fence = \"`\" * max(3, longest + 1)", "fence = \"`\" * 3"),),
    "overwrite": (("os.link(source, candidate)", "os.replace(source, candidate)"),),
    "wrong-collision-name": (('yield directory / f"{stem}_{tag}.md"', 'yield directory / f"{stem}_{tag}_x.md"'),),
    "world-readable": (("os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)"),),
    "original-kept": (("    if not _remove(path):\n        return Outcome(\"failed\", path, written,", "    if False:\n        return Outcome(\"failed\", path, written,"),),
    "empty-converted": (("    if rendered is None:\n", "    if False:\n"),),
    "no-untitled": (('return "Untitled"', 'return ""'),),
    "bom-kept": (('return text.removeprefix("\\ufeff")', "return text"),),
    "crlf-kept": (('text.replace("\\r\\n", "\\n").replace("\\r", "\\n")', "text"),),
    "rejected-always-deleted": (("removed = discard_rejected and _remove(path)\n        return Outcome(\"rejected\", path, detail=str(exc)", "removed = _remove(path)\n        return Outcome(\"rejected\", path, detail=str(exc)"),),
}


def test_the_converter_contract_holds_for_the_real_module(tmp_path: Path) -> None:
    assert exercise(txt_converter, tmp_path) == []


@pytest.mark.parametrize("label", sorted(MUTANTS))
def test_every_mutation_of_the_converter_is_caught(tmp_path: Path, label: str) -> None:
    variant = load_variant(label.replace("-", "_"), MUTANTS[label])
    assert exercise(variant, tmp_path) != [], f"mutant {label!r} survived"


# --------------------------------------------------------------------------- #
# Documentation and manifests stay in step with the code
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent.parent


def test_readme_documents_every_env_var_tool_and_command() -> None:
    from rea_mcp.server import KNOWN_ENV, TOOL_NAMES

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in sorted(KNOWN_ENV):
        assert f"`{name}" in readme, f"README does not document {name}"
    for tool in TOOL_NAMES:
        assert f"`{tool}`" in readme, f"README does not document {tool}"
    scripts = {
        line.split("=")[0].strip()
        for line in (ROOT / "pyproject.toml").read_text().split("[project.scripts]")[1].split("[", 1)[0].splitlines()
        if "=" in line
    }
    assert scripts == {"rea-mcp", "rea-mcp-bootstrap", "rea-mcp-doctor", "rea-mcp-convert-txt", "rea-mcp-register"}
    skill = (ROOT / "skills" / "rea-mcp" / "SKILL.md").read_text(encoding="utf-8")
    for command in scripts:
        assert f"`{command}" in readme, command
    for command in scripts - {"rea-mcp"}:
        assert command in skill, command
    for label in ("PROBED_LIVE", "STATIC_ROUTE_TABLE"):
        assert label in readme


def test_console_scripts_point_at_real_callables() -> None:
    import importlib

    for line in (ROOT / "pyproject.toml").read_text().split("[project.scripts]")[1].split("[", 1)[0].splitlines():
        if "=" not in line:
            continue
        target = line.split("=", 1)[1].strip().strip('"')
        module_name, function = target.split(":")
        assert callable(getattr(importlib.import_module(module_name), function)), target


def test_versions_agree_across_package_plugin_and_server() -> None:
    from rea_mcp.server import SERVER_VERSION

    declared = next(line for line in (ROOT / "pyproject.toml").read_text().splitlines() if line.startswith("version"))
    assert declared.split("=")[1].strip().strip('"') == SERVER_VERSION == json.loads((ROOT / "plugin.json").read_text())["version"]
