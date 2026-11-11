"""``rea-mcp-doctor``: live diagnostics for a running rea-mcp setup.

    rea-mcp-doctor --host-config ~/workspace/rea-data/mcp.host.json

Run it while IDA Pro / IDA Free (default ``:13337``) or Ghidra with GhidraMCP (default ``:8080``) is open.
It prints, for every loopback endpoint it probes:

* whether anything answers, and which wire profile matched (``ida-pro-mcp``, ``ida-free-mcp`` or ``GhidraMCP``);
* which capabilities are active, and the adapter's own reason for each one it marked unsupported
  (``describe_tools()`` and ``diagnostics()`` for the IDA adapters; GhidraMCP has no tool list, so its
  read-only listing routes are probed instead).

Then it runs a read-only smoke test through the real server wiring (``rea_capabilities``, the evidence
engine, the ``rea://`` registry and the corpus index). It never writes to a database, a target or the
ledger, and it never calls a mutating or privileged capability.

Exit status: 0 healthy, 1 a problem was found, 2 unusable configuration.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import secrets
import sys
import textwrap
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urlsplit

import httpx
from mcp.client.client import Client

from rea_mcp import hostconfig
from rea_mcp.adapters.base import TIMED_OUT, UNREACHABLE
from rea_mcp.adapters.ghidra import Dialect, GhidraBackend
from rea_mcp.adapters.ghidra_v2 import Health
from rea_mcp.adapters.ida_free import IdaFreeBackend
from rea_mcp.adapters.ida_pro import IdaProBackend
from rea_mcp.adapters.podman_runner import DEFAULT_IMAGE, PodmanScriptRunner
from rea_mcp.core.models import (
    EVIDENCE_CAPABILITIES,
    BackendResult,
    Capability,
    CapabilityListing,
    PagedListArgs,
    SecurityTier,
    ToolResponse,
)
from rea_mcp.core.router import BackendCall, BackendError
from rea_mcp.core.security import tier_of
from rea_mcp.sandbox_check import Check, verify_sandbox
from rea_mcp.server import (
    GHIDRA_URL_ENV,
    IDA_FREE_URL_ENV,
    IDA_PRO_URL_ENV,
    ConfigError,
    build_app,
    load_config,
)

DEFAULT_IDA_URL: Final = "http://127.0.0.1:13337"
DEFAULT_GHIDRA_URL: Final = "http://127.0.0.1:8080"
PROFILE_IDA_PRO: Final = "ida-pro-mcp"
PROFILE_IDA_FREE: Final = "ida-free-mcp"
PROFILE_GHIDRA: Final = "GhidraMCP"
GHIDRA_PROBES: Final[tuple[Capability, ...]] = (
    Capability.LIST_FUNCTIONS, Capability.LIST_SEGMENTS, Capability.LIST_IMPORTS, Capability.LIST_EXPORTS,
    Capability.LIST_STRINGS, Capability.LIST_GLOBALS, Capability.LIST_NAMESPACES,
)
LABEL_LIVE: Final = "PROBED_LIVE"
LABEL_STATIC_GHIDRA: Final = "STATIC_ROUTE_TABLE"
LABEL_STATIC_IDA: Final = "TOOL_LIST_MATCH"
_HTML: Final = re.compile(r"\s*<(?:!doctype|html|head|body)\b", re.IGNORECASE)
_DIAGNOSTIC: Final = re.compile(r"^([a-z_]+)/([^:]*): (.*)$")
WIDTH: Final = 100


# --------------------------------------------------------------------------- #
# Seams (real adapters by default; tests inject fakes)
# --------------------------------------------------------------------------- #


class IdaLike(Protocol):
    async def start(self) -> None: ...
    def supports(self, capability: Capability) -> bool: ...
    def diagnostics(self) -> tuple[str, ...]: ...
    def describe_tools(self) -> str: ...
    async def execute(self, call: BackendCall) -> BackendResult: ...
    async def aclose(self) -> None: ...


class GhidraLike(Protocol):
    @property
    def dialect(self) -> Dialect | None: ...
    @property
    def health(self) -> Health | None: ...
    def describe(self) -> str: ...
    async def detect(self) -> Dialect: ...
    def supports(self, capability: Capability) -> bool: ...
    async def execute(self, call: BackendCall) -> BackendResult: ...
    async def aclose(self) -> None: ...


async def live_catch_all(url: str, transport: httpx.AsyncBaseTransport | None = None) -> bool:
    """True when the server answers 2xx for a path no real GhidraMCP serves: a web app, not a Ghidra bridge.

    A genuine GhidraMCP answers 404 for unknown routes. Environment proxies are ignored (loopback only).
    """
    probe = f"{url.rstrip('/')}/rea-doctor-{secrets.token_hex(6)}"
    async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False, transport=transport) as client:
        try:
            response = await client.get(probe)
        except httpx.HTTPError:
            return False
    return response.is_success


@dataclass(frozen=True, slots=True)
class Factories:
    ida_pro: Callable[[str], IdaLike] = IdaProBackend.connect_to
    ida_free: Callable[[str], IdaLike] = IdaFreeBackend.connect_to
    ghidra: Callable[[str], GhidraLike] = GhidraBackend.connect_to
    ghidra_catch_all: Callable[[str], Awaitable[bool]] = live_catch_all


# --------------------------------------------------------------------------- #
# Report model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Endpoint:
    url: str
    family: str  # "ida" | "ghidra"
    roles: tuple[str, ...]  # what the server config calls it: ida-pro, ida-free, ghidra; empty = default probe

    @property
    def configured(self) -> bool:
        return bool(self.roles)

    @property
    def label(self) -> str:
        return "IDA (Pro/Free)" if self.family == "ida" else "Ghidra"

    @property
    def hostport(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.hostname}:{parts.port}"


@dataclass(slots=True)
class ProfileView:
    """What one wire profile made of the live server."""

    name: str
    static_label: str = LABEL_STATIC_IDA
    active: tuple[Capability, ...] = ()
    live: tuple[Capability, ...] = ()
    unsupported: dict[Capability, str] = field(default_factory=dict)
    partial: dict[Capability, str] = field(default_factory=dict)
    tool_count: int = 0
    tools: str = ""
    probe: str = ""
    error: str = ""

    @property
    def static(self) -> tuple[Capability, ...]:
        """Active capabilities that were matched from the profile but never called."""
        return tuple(c for c in self.active if c not in self.live)

    def counts(self) -> str:
        return f"{len(self.live)} {LABEL_LIVE} / {len(self.static)} {self.static_label} / {len(self.unsupported)} unsupported"


@dataclass(slots=True)
class EndpointReport:
    endpoint: Endpoint
    reachable: bool = False
    status: str = "not reachable"
    views: list[ProfileView] = field(default_factory=list)
    negotiated: ProfileView | None = None
    warnings: list[str] = field(default_factory=list)

    def usable(self) -> bool:
        """True when a configured role resolves at least one capability on a live server."""
        wanted = {"ida-pro": PROFILE_IDA_PRO, "ida-free": PROFILE_IDA_FREE, "ghidra": PROFILE_GHIDRA}
        names = {wanted[r] for r in self.endpoint.roles}
        return self.reachable and any(v.name in names and v.active for v in self.views)


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #


def _paged_call(capability: Capability) -> BackendCall:
    args = PagedListArgs.model_validate({"capability": capability.value, "limit": 1})
    return BackendCall(database=None, capability=capability, args=args, offset=0, resolved_path=None)


async def _view_ida(name: str, backend: IdaLike, timeout_s: float) -> ProfileView:
    view = ProfileView(name=name)
    try:
        async with asyncio.timeout(timeout_s):
            await backend.start()
    except (BackendError, TimeoutError) as exc:
        view.error = str(exc) or "timed out"
        return view
    active = tuple(c for c in Capability if backend.supports(c))
    view.active = active
    reasons: dict[Capability, list[str]] = {}
    for line in backend.diagnostics():
        match = _DIAGNOSTIC.match(line)
        if match is None:
            continue
        try:
            capability = Capability(match.group(1))
        except ValueError:
            continue
        sub = "" if match.group(2) in {"", "-"} else f"[{match.group(2)}] "
        reason = match.group(3).removeprefix(f"{capability.value}: ")
        reasons.setdefault(capability, []).append(sub + reason[:200])
    for capability, texts in reasons.items():
        (view.partial if capability in active else view.unsupported)[capability] = "; ".join(texts)
    view.tools = backend.describe_tools()
    view.tool_count = len([line for line in view.tools.splitlines() if line.strip()])
    if Capability.LIST_FUNCTIONS in active:
        try:
            async with asyncio.timeout(timeout_s):
                result = await backend.execute(_paged_call(Capability.LIST_FUNCTIONS))
            view.live = (Capability.LIST_FUNCTIONS,)
            view.probe = f"list_functions(limit=1) answered ({len(result.items)} item)"
        except (BackendError, TimeoutError) as exc:
            view.probe = f"list_functions(limit=1) failed: {str(exc)[:160] or 'timed out'}"
    else:
        view.probe = "list_functions not supported by this profile"
    return view


async def probe_ida(endpoint: Endpoint, factories: Factories, timeout_s: float) -> EndpointReport:
    report = EndpointReport(endpoint)
    pro, free = factories.ida_pro(endpoint.url), factories.ida_free(endpoint.url)
    try:
        report.views = list(await asyncio.gather(
            _view_ida(PROFILE_IDA_PRO, pro, timeout_s), _view_ida(PROFILE_IDA_FREE, free, timeout_s)
        ))
    finally:
        await asyncio.gather(pro.aclose(), free.aclose())
    errors = {v.error for v in report.views if v.error}
    if len(errors) == len(report.views) or all(v.error for v in report.views):
        message = sorted(errors)[0] if errors else "no answer"
        report.status = "not reachable" if message == UNREACHABLE else f"no MCP handshake ({message[:80]})"
        return report
    report.reachable = True
    ranked = sorted(report.views, key=lambda v: len(v.active), reverse=True)
    best, runner_up = ranked[0], ranked[1]
    report.negotiated = best
    if not best.active:
        report.status = "live, but no capability matched either profile"
    elif len(best.active) == len(runner_up.active) and set(best.active) == set(runner_up.active):
        report.status = f"live; {PROFILE_IDA_PRO} and {PROFILE_IDA_FREE} fit equally"
    else:
        report.status = f"live; negotiated {best.name}"
    wanted = {"ida-pro": PROFILE_IDA_PRO, "ida-free": PROFILE_IDA_FREE}
    for role in endpoint.roles:
        configured = next((v for v in report.views if v.name == wanted.get(role)), None)
        if configured is not None and best.name != configured.name and len(best.active) > len(configured.active):
            report.warnings.append(
                f"configured as {role} ({len(configured.active)} capabilities) but {best.name} fits better "
                f"({len(best.active)}): consider {IDA_PRO_URL_ENV if best.name == PROFILE_IDA_PRO else IDA_FREE_URL_ENV}"
            )
    return report


async def probe_ghidra(endpoint: Endpoint, factories: Factories, timeout_s: float) -> EndpointReport:
    report = EndpointReport(endpoint)
    backend = factories.ghidra(endpoint.url)
    view = ProfileView(name=PROFILE_GHIDRA, static_label=LABEL_STATIC_GHIDRA)
    try:
        answered: list[Capability] = []
        html_seen = False
        attempted = timed_out = 0
        detect_error = ""
        try:  # picks the wire dialect (GhidraMCP 2.0 vs 1.x) from GET /health; a miss is retried per probe below
            async with asyncio.timeout(timeout_s):
                await backend.detect()
        except TimeoutError:
            pass
        except BackendError as exc:
            if str(exc) == UNREACHABLE:
                report.status = "not reachable"
                return report
            if str(exc) != TIMED_OUT:
                detect_error = str(exc)[:160]
        table = "GhidraMCP 2.0 table" if backend.dialect is Dialect.V2 else "GhidraMCP table"
        for capability in GHIDRA_PROBES:
            if not backend.supports(capability):
                view.unsupported[capability] = f"no route in the {table}"
                continue
            attempted += 1
            try:
                async with asyncio.timeout(timeout_s):
                    result = await backend.execute(_paged_call(capability))
            except TimeoutError:
                timed_out += 1
                view.unsupported[capability] = "timed out"
            except BackendError as exc:
                message = str(exc)
                if message == UNREACHABLE:
                    report.status = "not reachable"
                    return report
                if message == TIMED_OUT:
                    timed_out += 1
                view.unsupported[capability] = message[:160]
            else:
                if any(_HTML.match(item.text) for item in result.items):
                    view.unsupported[capability] = "returned an HTML page, not GhidraMCP text"
                    html_seen = True
                else:
                    answered.append(capability)
        if not answered and attempted and timed_out == attempted:
            report.status = "no response (every probe timed out: nothing is listening, or it hangs)"
            return report
        report.reachable = True
        if not answered and html_seen:
            report.status = "something answers, but it is not GhidraMCP (it serves HTML pages)"
            return report
        if not answered:
            health = backend.health
            if health is not None and health.program is None:
                report.status = f"GhidraMCP {health.version} is running, but no program is open in a CodeBrowser (open one, then rerun)"
            elif detect_error:
                report.status = f"something is listening, but {detect_error}"
            else:
                report.status = "something is listening, but no GhidraMCP listing route answered"
            return report
        if answered and await factories.ghidra_catch_all(endpoint.url):
            report.status = "something answers, but it is not GhidraMCP (it returns 200 for routes that do not exist)"
            return report
        probed = set(GHIDRA_PROBES)
        view.active = tuple(
            c for c in Capability
            if c not in view.unsupported and backend.supports(c) and (c in probed or tier_of(c) is not SecurityTier.PRIVILEGED_DANGEROUS)
        )
        for capability in Capability:
            if capability not in view.unsupported and capability not in view.active and capability not in EVIDENCE_CAPABILITIES \
                    and tier_of(capability) is not SecurityTier.PRIVILEGED_DANGEROUS and not backend.supports(capability):
                view.unsupported[capability] = f"no route in the {table}"
        view.live = tuple(answered)
        view.probe = f"{len(answered)}/{len(GHIDRA_PROBES)} read-only listing routes answered"
        if backend.dialect is Dialect.V2:
            view.probe += f" [{backend.describe()}]"  # names the open program, so "live" is never about a different binary
        view.tools = f"({backend.describe()}; GhidraMCP publishes no tool list, routes are fixed)"
        report.views = [view]
        report.negotiated = view
        version = backend.health.version if backend.health is not None else ""
        report.status = (f"live; GhidraMCP {version}".rstrip() if answered else "live, but no listing route answered")
    finally:
        await backend.aclose()
    return report


# --------------------------------------------------------------------------- #
# Smoke test (read-only, through the real server wiring)
# --------------------------------------------------------------------------- #


async def smoke_test(env: Mapping[str, str]) -> tuple[Check, ...]:
    try:
        config = load_config(env)
        app = build_app(env)
    except ConfigError as exc:
        return (Check("configuration", False, str(exc)),)
    checks = [Check("configuration", True, f"valid; {len(config.warnings)} warning(s)")]
    checks += [Check("  warning", True, warning) for warning in config.warnings]
    async with Client(app.server) as client:
        raw = await client.call_tool("rea_capabilities", {})
        listing = CapabilityListing.model_validate_json(_text(raw.content))
        enabled = [e for e in listing.entries if e.enabled]
        privileged = [e for e in enabled if e.tier is SecurityTier.PRIVILEGED_DANGEROUS]
        checks.append(Check(
            "rea_capabilities", len(listing.entries) == len(Capability) and not raw.is_error,
            f"{len(enabled)}/{len(listing.entries)} enabled; {len(privileged)} privileged enabled",
        ))
        summary = await client.call_tool("rea_query", {"args": {"capability": "ledger_summary"}})
        response = ToolResponse.model_validate_json(_text(summary.content))
        checks.append(Check("evidence engine (ledger_summary)", response.status == "ok", response.status))
        prompts = await client.list_prompts()
        playbook = await client.read_resource("rea://prompts/triage-binary")
        playbook_text = playbook.contents[0].text if playbook.contents and hasattr(playbook.contents[0], "text") else ""
        checks.append(Check(
            "registry (prompts + resources)", len(prompts.prompts) == 5 and "rea_query" in playbook_text,
            f"{len(prompts.prompts)} prompts, playbook readable",
        ))
    if app.config.knowledge_dir is None:
        checks.append(Check("corpus index", True, "REA_KNOWLEDGE_DIR not set: built-in catalog only"))
    else:
        count = app.catalog.document_count()
        async with Client(app.server) as client:
            hits = await client.read_resource("rea://search/reverse")
            found = bool(hits.contents) and "1. " in getattr(hits.contents[0], "text", "")
        skipped = len(app.catalog.skipped())
        checks.append(Check(
            "corpus index", count > 0 and found,
            f"{count} documents in {len(app.catalog.local_categories())} categories, {skipped} skipped; search answers",
        ))
    return tuple(checks)


def _text(content: Sequence[object]) -> str:
    for item in content:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            return text
    return ""


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i]) for i in range(len(headers))]
    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()
    return [line(headers), line(["-" * w for w in widths]), *(line(row) for row in rows)]


def _listing(header: str, items: Sequence[str]) -> list[str]:
    body = ", ".join(items) if items else "none"
    return [header, *textwrap.wrap(body, width=WIDTH, initial_indent="      ", subsequent_indent="      ")]


def render_endpoint(report: EndpointReport, *, verbose: bool) -> list[str]:
    out = [f"{report.endpoint.label} at {report.endpoint.url}: {report.status}"]
    for each in report.views:
        if report.endpoint.family == "ida":
            marker = "  <- negotiated" if each is report.negotiated else ""
            tail = f"error: {each.error}" if each.error else f"{len(each.active)} capabilities active, {each.tool_count} tools listed"
            out.append(f"  profile {each.name:<13} {tail}{marker}")
    view = report.negotiated
    if view is not None:
        out += _listing(f"  {LABEL_LIVE} (called read-only, answered):", [c.value for c in view.live])
        meaning = (
            "matched from the route table; mutating routes are never fired"
            if view.static_label == LABEL_STATIC_GHIDRA else "matched from the server's tool list; not called"
        )
        out += _listing(f"  {view.static_label} ({meaning}):", [c.value for c in view.static])
        for capability, reason in sorted(view.partial.items(), key=lambda kv: kv[0].value):
            out += textwrap.wrap(f"{capability.value}: {reason}", width=WIDTH, initial_indent="  partial: ", subsequent_indent="           ")
        by_reason: dict[str, list[str]] = {}
        for capability, reason in sorted(view.unsupported.items(), key=lambda kv: kv[0].value):
            by_reason.setdefault(reason, []).append(capability.value)
        for reason, names in by_reason.items():
            out += textwrap.wrap(
                f"{', '.join(names)}  <- {reason}", width=WIDTH, initial_indent="  unsupported: ", subsequent_indent="                "
            )
        explained = set(view.unsupported) | set(view.partial) | set(view.active) | EVIDENCE_CAPABILITIES
        elsewhere = sorted(c.value for c in Capability if c not in explained)
        out += _listing("  not wired to this backend (by design):", elsewhere)
        out.append(f"  live read probe: {view.probe}")
        if verbose and view.tools:
            out.append("  tools (describe_tools):")
            out += [f"    {line}" for line in view.tools.splitlines()]
    out += [f"  WARNING: {w}" for w in report.warnings]
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def endpoints_from(env: Mapping[str, str]) -> tuple[Endpoint, ...]:
    roles: dict[str, list[str]] = {}
    for name, role in ((IDA_PRO_URL_ENV, "ida-pro"), (IDA_FREE_URL_ENV, "ida-free")):
        if env.get(name):
            roles.setdefault(env[name].rstrip("/"), []).append(role)
    found = [Endpoint(url, "ida", tuple(r)) for url, r in roles.items()]
    if env.get(GHIDRA_URL_ENV):
        found.append(Endpoint(env[GHIDRA_URL_ENV].rstrip("/"), "ghidra", ("ghidra",)))
    if not found:  # nothing configured: look at the default ports, informationally
        found = [Endpoint(DEFAULT_IDA_URL, "ida", ()), Endpoint(DEFAULT_GHIDRA_URL, "ghidra", ())]
    return tuple(found)


SandboxCheck = Callable[[], Sequence[Check]]


def live_sandbox() -> Sequence[Check]:
    return asyncio.run(verify_sandbox(PodmanScriptRunner(image=DEFAULT_IMAGE)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rea-mcp-doctor", description="Live, read-only diagnostics for rea-mcp.")
    parser.add_argument("--host-config", type=Path, help="mcp.host.json written by rea-mcp-bootstrap (REA_* settings are taken from it)")
    parser.add_argument("--require-all", action="store_true", help="fail unless every configured backend is live (default: at least one)")
    parser.add_argument("--sandbox", action="store_true", help="also run the live Podman isolation check")
    parser.add_argument("--verbose", action="store_true", help="print describe_tools() for each live IDA profile")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait per backend call (default 10)")
    return parser


def resolve_environment(host_config: Path | None, environ: Mapping[str, str]) -> dict[str, str]:
    env = dict(environ)
    if host_config is not None:
        server = hostconfig.load(host_config)
        env.update({k: v for k, v in server.env.items() if k.startswith("REA_")})
    return env


async def run_checks(
    env: Mapping[str, str], args: argparse.Namespace, factories: Factories, sandbox: SandboxCheck, emit: Callable[[str], None]
) -> int:
    endpoints = endpoints_from(env)
    reports: list[EndpointReport] = []
    for endpoint in endpoints:
        probe = probe_ida if endpoint.family == "ida" else probe_ghidra
        reports.append(await probe(endpoint, factories, args.timeout))

    emit("Disassembler backends")
    rows = []
    for r in reports:
        view = r.negotiated
        rows.append([
            r.endpoint.label, r.endpoint.hostport,
            ", ".join(r.endpoint.roles) or "default probe (not configured)",
            r.status,
            view.name if view else "-",
            view.counts() if view else "-",
        ])
    for line in table(["Backend", "Endpoint", "Configured as", "Status", "Profile", "Capabilities"], rows):
        emit(line)
    emit("")
    for r in reports:
        if r.reachable:
            for line in render_endpoint(r, verbose=args.verbose):
                emit(line)
            emit("")

    emit("Smoke test (read-only)")
    checks = list(await smoke_test(env))
    if args.sandbox:
        checks += [Check(f"sandbox: {c.name}", c.ok, c.detail) for c in sandbox()]
    for check in checks:
        emit(f"  [{'ok' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
    emit("")

    problems = [f"{c.name}: {c.detail}" for c in checks if not c.ok]
    configured = [r for r in reports if r.endpoint.configured]
    if configured:
        live = [r for r in configured if r.usable()]
        if args.require_all and len(live) != len(configured):
            problems.append("not every configured backend is live and usable")
        elif not live:
            problems.append("no configured backend is live and usable (open IDA or Ghidra with its MCP bridge, or unset the URLs)")
    else:
        emit("No backend URL is configured: only source reading, scanning and the ledger are available.")
    for r in reports:
        for warning in r.warnings:
            emit(f"warning: {warning}")
    if problems:
        emit("UNHEALTHY")
        for problem in problems:
            emit(f"  - {problem}")
        return 1
    emit("HEALTHY")
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    emit: Callable[[str], None] = print,
    environ: Mapping[str, str] | None = None,
    factories: Factories | None = None,
    sandbox: SandboxCheck = live_sandbox,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        env = resolve_environment(args.host_config, os.environ if environ is None else environ)
    except hostconfig.HostConfigError as exc:
        print(f"rea-mcp-doctor: {exc}", file=sys.stderr)
        return 2
    try:
        load_config(env)
    except ConfigError as exc:
        print(f"rea-mcp-doctor: configuration error: {exc}", file=sys.stderr)
        return 2
    return asyncio.run(run_checks(env, args, factories if factories is not None else Factories(), sandbox, emit))
