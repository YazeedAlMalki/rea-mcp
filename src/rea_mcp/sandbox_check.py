"""Live check of the rootless Podman sandbox behind ``script_eval``.

Runs one fixed probe script through the real :class:`PodmanScriptRunner` (so it exercises the exact
flags production uses: ``--network=none --read-only --cap-drop=ALL --user=65534``) and compares what
the script observes with what the sandbox promises. Nothing here is model-controlled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from pydantic import ValidationError

from rea_mcp.core.models import StrictModel
from rea_mcp.core.router import BackendError, IsolatedScriptRunner, SandboxUnavailableError

PROBE_TIMEOUT_S: Final = 40.0

PROBE_SCRIPT: Final = """\
import json, os, socket
facts = {"uid": os.getuid()}
try:
    socket.create_connection(("1.1.1.1", 53), timeout=2).close()
    facts["network"] = "reachable"
except OSError:
    facts["network"] = "blocked"
for key, path in (("rootfs", "/rea-probe"), ("input_dir", "/input/rea-probe")):
    try:
        open(path, "w").close()
        facts[key] = "writable"
    except OSError:
        facts[key] = "read-only"
try:
    facts["interfaces"] = sorted(os.listdir("/sys/class/net"))
except OSError:
    facts["interfaces"] = []
print(json.dumps(facts))
"""


class SandboxFacts(StrictModel):
    uid: int
    network: Literal["blocked", "reachable"]
    rootfs: Literal["read-only", "writable"]
    input_dir: Literal["read-only", "writable"]
    interfaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def evaluate(facts: SandboxFacts) -> tuple[Check, ...]:
    return (
        Check("unprivileged user", facts.uid == 65534, f"uid {facts.uid} (expected 65534)"),
        Check("no network", facts.network == "blocked" and set(facts.interfaces) <= {"lo"},
              f"outbound {facts.network}; interfaces {list(facts.interfaces) or 'none visible'}"),
        Check("read-only root filesystem", facts.rootfs == "read-only", facts.rootfs),
        Check("read-only input mount", facts.input_dir == "read-only", facts.input_dir),
    )


async def verify_sandbox(runner: IsolatedScriptRunner) -> tuple[Check, ...]:
    """Run the probe. A failure to run it is reported as one failed check, never raised."""
    try:
        result = await runner.run(PROBE_SCRIPT, [], PROBE_TIMEOUT_S)
    except SandboxUnavailableError as exc:
        return (Check("sandbox starts", False, str(exc)),)
    except BackendError as exc:
        return (Check("sandbox starts", False, str(exc)),)
    by_label = {item.label: item.text for item in result.items}
    if by_label.get("exit_code", "").strip() != "0":
        stderr = by_label.get("stderr", "").strip().splitlines()
        return (Check("sandbox starts", False, f"probe exited {by_label.get('exit_code', '?')}: {stderr[-1][:160] if stderr else 'no output'}"),)
    try:
        facts = SandboxFacts.model_validate_json(by_label.get("stdout", ""))
    except ValidationError:
        return (Check("sandbox starts", False, "probe printed unexpected output"),)
    return (Check("sandbox starts", True, "probe ran"), *evaluate(facts))
