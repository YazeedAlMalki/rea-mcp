"""Capability sandbox: tiers, default-deny authorization, audit log, redaction.

Provenance of each control (see the Phase 1 write-up for what was verified):

* Tiers / default-deny / read-only default: smokinggun's "static scans are
  read-only, offline, never execute repo code" posture, applied per capability.
* Header deny-list, no redirects, loopback-only backends: nac's model-request
  hardening (its API has no client auth; it relies on loopback binding).
* Redaction is split by scope. Host/transport scrubbing (host env secrets, auth
  headers, local user paths outside REA_ALLOWED_ROOTS) is always on. Binary-artifact
  secrets are evidence: by default they are left intact and only tagged as
  ``[SECRET_CANDIDATE:kind:fp8]`` metadata; ``REA_REDACT_ARTIFACTS=on`` masks them.
  nac has no redaction code to port, so every pattern here is original and heuristic.

Nothing in this module touches the network or runs sample code.
"""

import asyncio
import json
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urlsplit

from blake3 import blake3

from rea_mcp.core.fsafe import binary_flag
from rea_mcp.core.models import (
    AnyArgs,
    Capability,
    DebuggerControlArgs,
    ErrorCategory,
    LEDGER_WRITES,
    PatchAsmArgs,
    PatchBytesArgs,
    SecurityTier,
    WriteMemoryArgs,
)

# --------------------------------------------------------------------------- #
# Tier table (exhaustive; unknown capability => denied)
# --------------------------------------------------------------------------- #

_READ: Final = SecurityTier.READ_ONLY
_MUT: Final = SecurityTier.MUTATE_SAFE
_PRIV: Final = SecurityTier.PRIVILEGED_DANGEROUS

TIER_OF: Final[Mapping[Capability, SecurityTier]] = {
    Capability.LIST_DATABASES: _READ,
    Capability.DECOMPILE: _READ,
    Capability.DISASM: _READ,
    Capability.XREFS_TO: _READ,
    Capability.XREFS_FROM: _READ,
    Capability.CALLEES: _READ,
    Capability.BASIC_BLOCKS: _READ,
    Capability.STACK_FRAME: _READ,
    Capability.FUNCTION_INFO: _READ,
    Capability.LIST_FUNCTIONS: _READ,
    Capability.LIST_GLOBALS: _READ,
    Capability.LIST_SEGMENTS: _READ,
    Capability.LIST_IMPORTS: _READ,
    Capability.LIST_EXPORTS: _READ,
    Capability.LIST_STRINGS: _READ,
    Capability.LIST_NAMESPACES: _READ,
    Capability.SEARCH_FUNCTIONS: _READ,
    Capability.FIND_REGEX: _READ,
    Capability.FIND_BYTES: _READ,
    Capability.GET_BYTES: _READ,
    Capability.CALLGRAPH: _READ,
    Capability.READ_STRUCT: _READ,
    Capability.LEDGER_LIST: _READ,
    Capability.LEDGER_GET: _READ,
    Capability.LEDGER_SUMMARY: _READ,
    Capability.SCAN_HOTSPOTS: _READ,
    Capability.SOURCE_OUTLINE: _READ,
    Capability.SOURCE_READ: _READ,
    Capability.OPEN_DATABASE: _MUT,
    Capability.CLOSE_DATABASE: _MUT,
    Capability.RENAME_SYMBOL: _MUT,
    Capability.RENAME_VARIABLE: _MUT,
    Capability.SET_COMMENT: _MUT,
    Capability.SET_TYPE: _MUT,
    Capability.SET_FUNCTION_PROTOTYPE: _MUT,
    Capability.SET_VARIABLE_TYPE: _MUT,
    Capability.DECLARE_TYPE: _MUT,
    Capability.ADD_BOOKMARK: _MUT,
    Capability.DEFINE_FUNCTION: _MUT,
    Capability.DEFINE_CODE: _MUT,
    Capability.UNDEFINE: _MUT,
    Capability.DECLARE_STACK_VAR: _MUT,
    Capability.DELETE_STACK_VAR: _MUT,
    Capability.LEDGER_RECORD_FACT: _MUT,
    Capability.LEDGER_RECORD_HYPOTHESIS: _MUT,
    Capability.LEDGER_PROMOTE: _MUT,
    Capability.LEDGER_REFUTE: _MUT,
    Capability.LEDGER_DECLARE_GAP: _MUT,
    Capability.LEDGER_CLOSE_GAP: _MUT,
    Capability.IMPORT_SARIF: _MUT,
    Capability.PATCH_BYTES: _PRIV,
    Capability.PATCH_ASM: _PRIV,
    Capability.WRITE_MEMORY: _PRIV,
    Capability.SAVE_DATABASE: _PRIV,
    Capability.SCRIPT_EVAL: _PRIV,
    Capability.DEBUGGER_CONTROL: _PRIV,
}

_missing = set(Capability) - set(TIER_OF)
if _missing:  # import-time guard: a new capability must be tiered explicitly
    raise RuntimeError(f"capabilities without a tier: {sorted(c.value for c in _missing)}")


class SecurityDenied(Exception):
    """Raised for every policy refusal; carries a stable error category."""

    def __init__(self, category: ErrorCategory, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.message = message


def tier_of(capability: Capability) -> SecurityTier:
    tier = TIER_OF.get(capability)
    if tier is None:
        raise SecurityDenied(ErrorCategory.DENIED_TIER, f"capability {capability.value} has no tier")
    return tier


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Scrubbed:
    text: str
    candidates: tuple[str, ...]  # ``[SECRET_CANDIDATE:kind:fp8]`` tags; text is untouched


@dataclass(frozen=True, slots=True)
class _Rule:
    kind: str
    regex: re.Pattern[str]
    group: int = 0


_RULES: Final[tuple[_Rule, ...]] = (
    _Rule("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    _Rule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Rule("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    _Rule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    _Rule("api_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    _Rule("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    _Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    _Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    _Rule("bearer", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"), group=1),
    _Rule(
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*[\"']?([^\s\"']{8,})"
        ),
        group=1,
    ),
)

_SECRET_ENV_NAME: Final = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)")
_MIN_HOST_SECRET_LEN: Final = 8
_MAX_CANDIDATES: Final = 32
_HEADER_LINE: Final = re.compile(
    r"(?i)\b((?:authorization|proxy-authorization|x-api-key|cookie|set-cookie)\s*:\s*)[^\r\n]+"
)
_USER_PATH_POSIX: Final = re.compile(r"(?:/home|/Users)/[^/\s:'\"<>|]+(?:/[^\s:'\"<>|]*)?")
_USER_PATH_WIN: Final = re.compile(r"[A-Za-z]:\\Users\\[^\\\s:'\"<>|]+(?:\\[^\s:'\"<>|]*)?")


def _fingerprint(value: str) -> str:
    return blake3(value.encode("utf-8")).hexdigest()[:8]


class HostRedactor:
    """Always-on scrubbing of the analyst's machine; never of the target binary's text."""

    def __init__(self, host_secrets: frozenset[str], allowed_roots: tuple[Path, ...]) -> None:
        self._secrets = tuple(sorted(host_secrets, key=len, reverse=True))
        self._roots = tuple(str(r) for r in allowed_roots)

    @classmethod
    def from_environ(cls, env: Mapping[str, str], allowed_roots: tuple[Path, ...]) -> "HostRedactor":
        values = frozenset(
            v for k, v in env.items() if _SECRET_ENV_NAME.search(k) and len(v) >= _MIN_HOST_SECRET_LEN
        )
        return cls(values, allowed_roots)

    def scrub_env(self, text: str) -> str:
        for secret in self._secrets:  # host secrets never leave, not even fingerprinted
            text = text.replace(secret, "[REDACTED:host_secret]")
        return text

    def scrub_transport(self, text: str) -> str:
        """Host-channel text: env secrets, auth/cookie header values, user paths outside roots."""
        text = self.scrub_env(text)
        text = _HEADER_LINE.sub(lambda m: m.group(1) + "[REDACTED:header]", text)
        text = _USER_PATH_POSIX.sub(self._path_replacer, text)
        return _USER_PATH_WIN.sub(self._path_replacer, text)

    def _path_replacer(self, match: re.Match[str]) -> str:
        path = match.group(0)
        for root in self._roots:
            if path == root or path.startswith((root + "/", root + "\\")):
                return path
        return "[REDACTED:host_path]"


class ArtifactScanner:
    """Credential-shaped strings inside the target binary: evidence first.

    ``redact=False`` (default) keeps the text byte-for-byte and returns
    ``[SECRET_CANDIDATE:kind:fp8]`` tags as metadata; ``redact=True`` masks instead.
    """

    def __init__(self, redact: bool) -> None:
        self._redact = redact

    def process(self, text: str) -> Scrubbed:
        if self._redact:
            for rule in _RULES:
                text = rule.regex.sub(self._replacer(rule), text)
            return Scrubbed(text, ())
        tags: dict[str, None] = {}
        for rule in _RULES:
            for match in rule.regex.finditer(text):
                tags[f"[SECRET_CANDIDATE:{rule.kind}:{_fingerprint(match.group(rule.group))}]"] = None
                if len(tags) >= _MAX_CANDIDATES:
                    return Scrubbed(text, tuple(tags))
        return Scrubbed(text, tuple(tags))

    @staticmethod
    def _replacer(rule: _Rule) -> Callable[[re.Match[str]], str]:
        def replace(match: re.Match[str]) -> str:
            value = match.group(rule.group)
            tag = f"[REDACTED:{rule.kind}:{_fingerprint(value)}]"
            if rule.group == 0:
                return tag
            whole = match.group(0)
            start = match.start(rule.group) - match.start(0)
            return whole[:start] + tag + whole[start + len(value):]

        return replace


class RedactionPipeline:
    def __init__(self, host: HostRedactor, artifacts: ArtifactScanner) -> None:
        self._host = host
        self._artifacts = artifacts

    @classmethod
    def from_policy(cls, policy: "SecurityPolicy", env: Mapping[str, str]) -> "RedactionPipeline":
        return cls(
            HostRedactor.from_environ(env, policy.allowed_roots),
            ArtifactScanner(policy.redact_artifacts),
        )

    def scrub_artifact(self, text: str) -> Scrubbed:
        return self._artifacts.process(self._host.scrub_env(text))

    def scrub_host_channel(self, text: str) -> Scrubbed:
        return Scrubbed(self._host.scrub_transport(text), ())

    def scrub_transport(self, text: str) -> str:
        return self._host.scrub_transport(text)


# --------------------------------------------------------------------------- #
# Audit log (append-only JSONL, BLAKE3 hash-chained, fsync'd, 0600)
# --------------------------------------------------------------------------- #

AuditValue = str | int


class AuditLog:
    """Tamper-evident log: each record commits to the previous record's hash."""

    GENESIS: Final = "0" * 64

    def __init__(self, path: Path | None, clock: Callable[[], float] = time.time) -> None:
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = self.GENESIS
        self.memory: list[dict[str, AuditValue]] = []
        if path is not None and path.exists():
            self._resume(path)

    @property
    def durable(self) -> bool:
        return self._path is not None

    def _resume(self, path: Path) -> None:
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines:
            last = json.loads(lines[-1])
            self._seq = int(last["seq"])
            self._prev = str(last["hash"])

    def append(self, fields: Mapping[str, AuditValue]) -> None:
        """Write one record; raises OSError on any failure (callers fail closed)."""
        with self._lock:
            record: dict[str, AuditValue] = {
                "seq": self._seq + 1,
                "ts_ms": int(self._clock() * 1000),
                "prev": self._prev,
                **fields,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            record["hash"] = blake3((self._prev + canonical).encode("utf-8")).hexdigest()
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
            if self._path is not None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | binary_flag(), 0o600)
                try:
                    os.write(fd, line.encode("ascii"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
            self.memory.append(record)
            self._seq += 1
            self._prev = str(record["hash"])

    @staticmethod
    def verify_chain(lines: list[str]) -> bool:
        prev = AuditLog.GENESIS
        for line in lines:
            record: dict[str, AuditValue] = json.loads(line)
            claimed = str(record.pop("hash"))
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            if record["prev"] != prev or blake3((prev + canonical).encode("utf-8")).hexdigest() != claimed:
                return False
            prev = claimed
        return True


# --------------------------------------------------------------------------- #
# Policy (immutable, read once from the operator's environment)
# --------------------------------------------------------------------------- #

OVERRIDE_ENV: Final = "REA_PRIVILEGED_OVERRIDE"
OVERRIDE_VALUE: Final = "enable-dangerous-ops"
ALLOW_ENV: Final = "REA_PRIVILEGED_ALLOW"
KEYFILE_ENV: Final = "REA_PRIVILEGED_KEYFILE"
AUTO_GRANT_ENV: Final = "REA_AUTO_GRANT_MUTATE"
ROOTS_ENV: Final = "REA_ALLOWED_ROOTS"
REDACT_ARTIFACTS_ENV: Final = "REA_REDACT_ARTIFACTS"
AUDIT_ENV: Final = "REA_AUDIT_LOG"
LEDGER_DIR_ENV: Final = "REA_LEDGER_DIR"
LEDGER_FOREIGN_ENV: Final = "REA_LEDGER_ALLOW_WORKSPACE_MISMATCH"


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    privileged_override: bool = False
    privileged_allow: frozenset[Capability] = frozenset()
    keyfile: Path | None = None
    mutate_auto_grant: bool = False
    allowed_roots: tuple[Path, ...] = ()
    redact_artifacts: bool = False
    ledger_dir: Path | None = None
    ledger_allow_foreign_workspace: bool = False

    def workspace_fingerprint(self) -> str:
        """BLAKE3 over the normalized, sorted ``REA_ALLOWED_ROOTS``: which target tree a ledger is about."""
        roots = sorted({str(root) for root in self.allowed_roots})
        return blake3("\n".join(["rea-workspace-v1", *roots]).encode()).hexdigest()

    @classmethod
    def from_environ(cls, env: Mapping[str, str]) -> "SecurityPolicy":
        allow: set[Capability] = set()
        for name in filter(None, (p.strip() for p in env.get(ALLOW_ENV, "").split(","))):
            try:
                capability = Capability(name)
            except ValueError as exc:  # fail closed on typos instead of ignoring them
                raise ValueError(f"{ALLOW_ENV}: unknown capability {name!r}") from exc
            if TIER_OF[capability] is not SecurityTier.PRIVILEGED_DANGEROUS:
                raise ValueError(f"{ALLOW_ENV}: {name!r} is not a privileged capability")
            allow.add(capability)
        keyfile = env.get(KEYFILE_ENV)
        roots = tuple(
            Path(p).resolve() for p in env.get(ROOTS_ENV, "").split(os.pathsep) if p.strip()
        )
        flag = env.get(REDACT_ARTIFACTS_ENV, "off")
        if flag not in {"on", "off"}:
            raise ValueError(f"{REDACT_ARTIFACTS_ENV}: expected 'on' or 'off'")
        return cls(
            privileged_override=env.get(OVERRIDE_ENV) == OVERRIDE_VALUE,
            privileged_allow=frozenset(allow),
            keyfile=Path(keyfile) if keyfile else None,
            mutate_auto_grant=env.get(AUTO_GRANT_ENV) == "1",
            allowed_roots=roots,
            redact_artifacts=flag == "on",
            ledger_dir=Path(env[LEDGER_DIR_ENV]) if env.get(LEDGER_DIR_ENV) else None,
            ledger_allow_foreign_workspace=env.get(LEDGER_FOREIGN_ENV) == "1",
        )

    def is_enabled(self, capability: Capability) -> bool:
        """Static view for ``rea_capabilities`` (the keyfile is re-checked per call)."""
        if TIER_OF[capability] is not SecurityTier.PRIVILEGED_DANGEROUS:
            return True
        return self.privileged_override and capability in self.privileged_allow


# --------------------------------------------------------------------------- #
# Consent, session grants, authorizer
# --------------------------------------------------------------------------- #


class ConsentProvider(Protocol):
    """Human-in-the-loop hook (maps to MCP elicitation in the server wiring)."""

    async def approve_session_mutations(self, session_id: str) -> bool: ...


class DenyAllConsent:
    async def approve_session_mutations(self, session_id: str) -> bool:
        return False


@dataclass(slots=True)
class SessionGrants:
    session_id: str
    mutate_granted: bool = False


@dataclass(frozen=True, slots=True)
class AuthTicket:
    capability: Capability
    tier: SecurityTier
    args_digest: str


def args_digest(args: AnyArgs) -> str:
    return blake3(args.model_dump_json().encode("utf-8")).hexdigest()


def summarize(args: AnyArgs) -> str:
    """Short, non-sensitive description for the audit log (never the payload)."""
    base = args.capability
    if isinstance(args, (PatchBytesArgs, WriteMemoryArgs)):
        return f"{base} addr=0x{args.address:x} bytes={len(args.data) // 2}"
    if isinstance(args, PatchAsmArgs):
        return f"{base} addr=0x{args.address:x}"
    if isinstance(args, DebuggerControlArgs):
        addr = "" if args.address is None else f" addr=0x{args.address:x}"
        return f"{base} action={args.action}{addr}"
    return base


class Authorizer:
    """Default-deny gate. Privileged capabilities require ALL of:

    1. ``REA_PRIVILEGED_OVERRIDE=enable-dangerous-ops`` in the operator env,
    2. the capability named in ``REA_PRIVILEGED_ALLOW``,
    3. if ``REA_PRIVILEGED_KEYFILE`` is set, that (e.g. hardware-token) file
       exists and is non-empty *at call time* (removal revokes immediately),
    4. a durable audit log, written ahead of execution (fail closed).
    """

    def __init__(
        self,
        policy: SecurityPolicy,
        audit: AuditLog,
        consent: ConsentProvider,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._consent = consent

    @property
    def policy(self) -> SecurityPolicy:
        return self._policy

    async def authorize(
        self, session: SessionGrants, capability: Capability, args: AnyArgs
    ) -> AuthTicket:
        tier = tier_of(capability)
        ticket = AuthTicket(capability, tier, args_digest(args))
        if tier is SecurityTier.READ_ONLY or capability in LEDGER_WRITES:
            return ticket  # ledger notes are validated by the engine, not gated on a human
        try:
            if tier is SecurityTier.MUTATE_SAFE:
                await self._check_mutate(session)
            else:
                self._check_privileged(capability)
        except SecurityDenied as denied:
            await self._record(session, ticket, "denied", denied.category.value, args, strict=False)
            raise
        await self._record(session, ticket, "allowed", "policy_satisfied", args, strict=True)
        return ticket

    async def complete(self, session: SessionGrants, ticket: AuthTicket, outcome: str) -> None:
        if ticket.tier is SecurityTier.READ_ONLY or ticket.capability in LEDGER_WRITES:
            return
        entry = {
            "event": "completed",
            "session": session.session_id,
            "capability": ticket.capability.value,
            "tier": ticket.tier.value,
            "args_digest": ticket.args_digest,
            "reason": outcome,
        }
        try:
            await asyncio.to_thread(self._audit.append, entry)
        except OSError:
            pass  # the write-ahead "allowed" record already exists; completion is best-effort

    async def _check_mutate(self, session: SessionGrants) -> None:
        if session.mutate_granted:
            return
        if self._policy.mutate_auto_grant or await self._consent.approve_session_mutations(
            session.session_id
        ):
            session.mutate_granted = True
            return
        raise SecurityDenied(
            ErrorCategory.DENIED_CONSENT,
            "mutating capabilities require per-session approval, which was not granted",
        )

    def _check_privileged(self, capability: Capability) -> None:
        p = self._policy
        if not p.privileged_override:
            raise SecurityDenied(
                ErrorCategory.DENIED_OVERRIDE,
                f"{capability.value} is hard-disabled; the operator override flag is not set",
            )
        if capability not in p.privileged_allow:
            raise SecurityDenied(
                ErrorCategory.DENIED_OVERRIDE, f"{capability.value} is not in the operator allow-list"
            )
        if p.keyfile is not None:
            try:
                present = p.keyfile.is_file() and p.keyfile.stat().st_size > 0
            except OSError:
                present = False
            if not present:
                raise SecurityDenied(ErrorCategory.DENIED_OVERRIDE, "hardware key file is absent")
        if not self._audit.durable:
            raise SecurityDenied(
                ErrorCategory.AUDIT_FAILURE, "privileged operations require a durable audit log"
            )

    async def _record(
        self,
        session: SessionGrants,
        ticket: AuthTicket,
        event: str,
        reason: str,
        args: AnyArgs,
        *,
        strict: bool,
    ) -> None:
        entry: dict[str, AuditValue] = {
            "event": event,
            "session": session.session_id,
            "capability": ticket.capability.value,
            "tier": ticket.tier.value,
            "args_digest": ticket.args_digest,
            "summary": summarize(args),
            "reason": reason,
        }
        try:
            await asyncio.to_thread(self._audit.append, entry)
        except OSError as exc:
            if strict:  # cannot prove it was logged => do not run it
                raise SecurityDenied(ErrorCategory.AUDIT_FAILURE, "audit log write failed") from exc


# --------------------------------------------------------------------------- #
# Path, URL and header hardening
# --------------------------------------------------------------------------- #


def resolve_under_roots(raw: str, roots: tuple[Path, ...]) -> Path:
    """Resolve symlinks, then require the real path to sit under an allowed root."""
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise SecurityDenied(ErrorCategory.DENIED_PATH, "path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SecurityDenied(ErrorCategory.DENIED_PATH, "path does not exist or loops") from exc
    if not any(resolved.is_relative_to(root) for root in roots):
        raise SecurityDenied(ErrorCategory.DENIED_PATH, "path is outside REA_ALLOWED_ROOTS")
    return resolved


_LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1"})  # literals only: no DNS, no "localhost"
FORBIDDEN_OVERRIDE_HEADERS: Final = frozenset(
    {"host", "authorization", "proxy-authorization", "x-api-key", "cookie", "content-length"}
)


def assert_loopback_url(url: str) -> str:
    """Backends are local bridges; refuse anything else (and embedded credentials)."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SecurityDenied(ErrorCategory.BACKEND_UNAVAILABLE, "backend URL must be http(s)")
    if parts.username is not None or parts.password is not None:
        raise SecurityDenied(ErrorCategory.BACKEND_UNAVAILABLE, "credentials in URL are forbidden")
    if parts.hostname not in _LOOPBACK_HOSTS:
        raise SecurityDenied(ErrorCategory.BACKEND_UNAVAILABLE, "backend must be on loopback")
    return url


def sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    for name in headers:
        if name.lower() in FORBIDDEN_OVERRIDE_HEADERS:
            raise SecurityDenied(ErrorCategory.INVALID_REQUEST, f"header {name!r} cannot be overridden")
    return dict(headers)

