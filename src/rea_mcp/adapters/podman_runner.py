"""Rootless-Podman sandbox for ``script_eval`` (deobfuscation / crypto-solver scripts).

Threat model: the script is untrusted (model-written, driven by attacker-controlled binary
content). It gets a Python interpreter, the bytes/text the *router* fetched for it, and nothing
else: no network, no host mounts except one read-only input directory, no capabilities, no
privilege escalation, bounded memory/CPU/processes/output/time. It never talks to IDA or Ghidra,
and nothing here forwards to ``py_eval``.

Flags (the brief's set, plus ``--pull=never`` so the sandbox cannot fetch anything, ``--user``
nobody, a size-limited noexec ``/tmp``, a pids limit, swap == memory, and podman's own timeout):

    podman run --rm --name N --network=none --read-only --cap-drop=ALL
      --security-opt=no-new-privileges --memory=512m --memory-swap=512m --cpus=1 ...

The runner refuses to start as root: "rootless" is enforced, not assumed. The image must already
be present locally (``podman pull`` it once as the operator).
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from rea_mcp.core.models import BackendItem, BackendResult
from rea_mcp.core.router import (
    RESERVED_SCRIPT_NAME,
    BackendError,
    SandboxUnavailableError,
    ScriptFile,
)

DEFAULT_IMAGE: Final = "docker.io/library/python:3.12-slim"
_IMAGE_OK: Final = re.compile(r"^[a-z0-9][a-z0-9._/@:-]{0,200}$")
_FILE_NAME_OK: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PATH_OK: Final = re.compile(r"^[A-Za-z0-9_./-]+$")  # no ':' or ',' that would corrupt --volume
_ENV_ALLOWLIST: Final = (
    "PATH", "HOME", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
    "CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF",
)
_PODMAN_FAILURE_EXIT: Final = 125
_GRACE_S: Final = 3.0


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    memory: str = "512m"
    cpus: str = "1"
    pids: int = 128
    tmp_size: str = "64m"
    max_output_bytes: int = 65_536
    max_script_bytes: int = 64_000
    max_input_bytes: int = 2_097_152


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool


class ProcessLauncher(Protocol):
    async def run(
        self, argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, max_output: int
    ) -> ProcessOutput: ...


class SubprocessLauncher:
    async def run(
        self, argv: Sequence[str], *, env: Mapping[str, str], timeout_s: float, max_output: int
    ) -> ProcessOutput:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(env),
            )
        except OSError as exc:
            raise SandboxUnavailableError(f"cannot execute podman: {type(exc).__name__}") from exc
        assert proc.stdout is not None and proc.stderr is not None
        overflow = asyncio.Event()

        async def drain(stream: asyncio.StreamReader) -> bytes:
            kept = bytearray()
            while chunk := await stream.read(16_384):
                if len(kept) < max_output:
                    kept += chunk[: max_output - len(kept)]
                if len(kept) >= max_output and not overflow.is_set():
                    overflow.set()
                    proc.kill()  # stop a flood; the runner force-removes the container by name
            return bytes(kept)

        timed_out = False
        try:
            async with asyncio.timeout(timeout_s):
                out, err, _ = await asyncio.gather(drain(proc.stdout), drain(proc.stderr), proc.wait())
        except TimeoutError:
            timed_out = True
            proc.kill()
            out, err = b"", b""
            await proc.wait()
        return ProcessOutput(proc.returncode if proc.returncode is not None else -1, out, err, timed_out, overflow.is_set())


def build_podman_argv(
    *, podman: str, image: str, name: str, input_dir: Path, limits: SandboxLimits, timeout_s: int
) -> tuple[str, ...]:
    if not _IMAGE_OK.fullmatch(image):
        raise SandboxUnavailableError("invalid sandbox image reference")
    if not _PATH_OK.fullmatch(str(input_dir)):
        raise SandboxUnavailableError("temporary directory path is not mountable safely")
    return (
        podman, "run", "--rm", f"--name={name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--memory={limits.memory}", f"--memory-swap={limits.memory}", f"--cpus={limits.cpus}",
        f"--pids-limit={limits.pids}",
        "--pull=never",
        "--user=65534:65534",
        f"--timeout={timeout_s}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={limits.tmp_size}",
        f"--volume={input_dir}:/input:ro,Z",
        "--workdir=/tmp",
        "--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1", "--env=PYTHONUNBUFFERED=1",
        image,
        "python3", "-I", f"/input/{RESERVED_SCRIPT_NAME}",
    )


class PodmanScriptRunner:
    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        podman_path: str | None = None,
        limits: SandboxLimits = SandboxLimits(),
        launcher: ProcessLauncher | None = None,
        tmp_root: Path | None = None,
        environ: Mapping[str, str] | None = None,
        geteuid: Callable[[], int] = getattr(os, "geteuid", lambda: 1),  # Windows has no uid: never "root"
    ) -> None:
        self._image = image
        self._podman = podman_path or shutil.which("podman")
        self._limits = limits
        self._launcher: ProcessLauncher = launcher if launcher is not None else SubprocessLauncher()
        self._tmp_root = tmp_root
        source = os.environ if environ is None else environ
        self._env = {k: source[k] for k in _ENV_ALLOWLIST if k in source}  # never forward host secrets
        self._geteuid = geteuid

    async def run(self, code: str, files: Sequence[ScriptFile], timeout_s: float) -> BackendResult:
        if self._podman is None:
            raise SandboxUnavailableError("podman is not installed")
        if self._geteuid() == 0:
            raise SandboxUnavailableError("refusing to run as root: rootless podman is required")
        script = code.encode("utf-8")
        if len(script) > self._limits.max_script_bytes:
            raise BackendError("script is too large")
        if sum(len(f.data) for f in files) > self._limits.max_input_bytes:
            raise BackendError("script inputs are too large")

        workdir = Path(tempfile.mkdtemp(prefix="rea-sbx-", dir=self._tmp_root))
        name = f"rea-{secrets.token_hex(8)}"
        try:
            input_dir = workdir / "input"
            input_dir.mkdir(mode=0o755)
            self._write(input_dir / RESERVED_SCRIPT_NAME, script)
            for file in files:
                if not _FILE_NAME_OK.fullmatch(file.name) or file.name == RESERVED_SCRIPT_NAME:
                    raise BackendError("invalid sandbox input name")
                self._write(input_dir / file.name, file.data)
            effective = max(1, int(timeout_s - 2 * _GRACE_S))
            argv = build_podman_argv(
                podman=self._podman, image=self._image, name=name, input_dir=input_dir,
                limits=self._limits, timeout_s=effective,
            )
            output = await self._launcher.run(
                argv, env=self._env, timeout_s=effective + _GRACE_S, max_output=self._limits.max_output_bytes
            )
            return self._result(output)
        finally:
            await self._force_remove(name)
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        path.write_bytes(data)
        path.chmod(0o644)  # readable by uid 65534 inside the container, never writable

    def _result(self, output: ProcessOutput) -> BackendResult:
        if output.timed_out:
            raise BackendError("script exceeded the time limit")
        if output.exit_code == _PODMAN_FAILURE_EXIT:
            first = output.stderr.decode("utf-8", errors="replace").strip().splitlines()[:1]
            raise SandboxUnavailableError("podman failed: " + (first[0][:160] if first else "unknown"))
        note = " (output truncated)" if output.truncated else ""
        items = (
            BackendItem(label="stdout", text=output.stdout.decode("utf-8", errors="backslashreplace") + note),
            BackendItem(label="stderr", text=output.stderr.decode("utf-8", errors="backslashreplace")),
            BackendItem(label="exit_code", text=str(output.exit_code)),
        )
        return BackendResult(items=items, next_offset=None, generation=0)

    async def _force_remove(self, name: str) -> None:
        if self._podman is None:
            return
        try:
            await self._launcher.run(
                (self._podman, "rm", "-f", "-t", "0", name),
                env=self._env, timeout_s=10.0, max_output=4_096,
            )
        except (BackendError, OSError):
            pass  # best effort: --rm already removes it on a normal exit
