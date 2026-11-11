# rea-mcp — handoff for Claude Code

Zero-trust reverse-engineering MCP server. Four tools (`rea_query`, `rea_mutate`, `rea_privileged`,
`rea_capabilities`) sit in front of IDA Pro, IDA Free and Ghidra bridges, a read-only source and evidence
engine, an append-only evidence ledger (ConfirmedFact / Hypothesis / UnanalyzedGap), and a `rea://` registry
of playbooks and reference material. Python 3.12+, `mypy --strict` clean, Apache-2.0.

Owner: Yazeed (non-technical builder; reviews and approves each phase before the next one starts — do not
jump ahead without explicit sign-off). See `README.md` in this repo root for full usage/config/CLI reference;
this file is about where things stand and how to continue, not a restatement of the README.

## Where things are
- This repo: `C:\Users\yazz9\workspace\rea-mcp` on laptop `ym-dell` (Windows 11, user `yazz9`).
- Sibling data folder (not in this repo): `C:\Users\yazz9\workspace\rea-data` — `knowledge/` (cloned reference
  repos, Markdown-only), `ledger/`, `targets/` (extracted reverse-engineering targets, e.g. SelfCAD), and
  `mcp.host.json` / `bootstrap.json`.
- Version: 1.2.1 (`pyproject.toml`). Current venv: `.venv/` (gitignored).
- A second deployment is expected on a workstation named `yamal` (also native Windows 11) — not yet confirmed
  set up as of 2026-11-11; treat `yamal` as a target to provision, not an assumption that it already has this
  repo.
- Earlier handover with full session narrative: project doc `selfcad-re-handover-2026-11-09.md` (Claude Docs /
  claude.ai project "REA MCP project").

## Structure
- `src/rea_mcp/` — `server.py` (the 4 tools), `core/` (router, security, paging, fsafe, pydantic models),
  `adapters/` (IDA Pro / IDA Free / Ghidra bridges, incl. `ghidra_v2.py` for GhidraMCP 2.0's JSON dialect),
  `registry/` (`rea://` resources, txt-to-md converter), `evidence/` (ledger), `bootstrap.py`, `doctor.py`,
  `register.py`, `hostconfig.py`, `sandbox_check.py`.
- `tests/` — `test_phase1.py` .. `test_phase5.py` plus `test_arg_coercion.py`, `test_ghidra_v2.py`,
  `test_register.py`, `test_windows_portability.py`. 322 tests total; see "State" below for current pass
  rate on native Windows — it is NOT all green right now, for a known, understood reason.
- `skills/rea-mcp/SKILL.md` — teaches a host model how to use the plugin.
- `mcp.json`, `plugin.json` — Agent Plugins 1.0.0 manifest (so this repo can be dropped in as a plugin directly).

## Commands
```
pip install -e .[dev]
pytest                      # includes mypy --strict-level checks + a scan for Any/placeholders/suppressions
rea-mcp-doctor --host-config <path to mcp.host.json>
rea-mcp-bootstrap --workspace ~/workspace/rea-data
```
Windows native setup uses `uv` (see README "Windows 11 (native)" section) — Python 3.11 is too old, needs 3.12+.

## Decisions (binding — do not relitigate without Yazeed)
- Host/transport redaction always on; binary-artifact secrets kept as evidence (tagged), redaction opt-in via
  `REA_REDACT_ARTIFACTS=on`.
- Structural edits (`define_function`, `define_code`, `undefine`, stack edits) live in `rea_mutate`
  (MUTATE_SAFE tier), not privileged.
- `script_eval` runs only in rootless Podman, never forwarded to IDA's `py_eval`.
- Knowledge corpus is clean Markdown only — exactly 3,842 docs from the 15 reference repos, no `.git`, hidden
  folders, symlinks, or non-text files.
- GhidraMCP 2.0 (JSON, `/functions`) vs 1.x (plain text, `/methods`) are told apart via `GET /health` — do not
  assume one dialect.

## State
- Phases 1–6 approved and implemented: core router + tiers, IDA/Ghidra adapters + Podman sandbox runner,
  evidence ledger, `rea://` registry, bootstrap/doctor CLIs, txt-to-md converter.
- Live-verified against Ghidra 12.1.4 + GhidraMCP 2.0 on `ym-dell` (doctor HEALTHY; list_functions/segments/
  imports/strings, decompile all worked) as of 2026-11-09.
- Not yet done: git history for this repo (none existed until 2026-11-11 — this handoff), GitHub remote (being
  created now), confirming/provisioning the `yamal` deployment, Ghidra pass on SelfCAD's native `renderer.exe`.
- **Test suite on native Windows (verified 2026-11-11): 268 passed, 46 failed, 1 skipped, 8 errors** (not the
  322/322 the 2026-11-09 handover reported — that run was presumably on Linux/WSL, this one is native Windows).
  Every failure traces to the same root cause: tests written assuming POSIX semantics the README already flags
  as Windows gaps — `os.O_NOFOLLOW` doesn't exist on Windows (`AttributeError` in the `windows_like` fixture),
  file-mode assertions expect `0o600`/`0o700` but Windows has no POSIX mode bits (`stat.S_IMODE` returns
  `0o666`/`0o777`-shaped values instead), and `Path.symlink_to` needs an elevated privilege Windows denies by
  default (`WinError 1314`). This is almost certainly a real, not-yet-addressed platform gap in the test suite
  itself (the Windows-portability code paths work; the *tests asserting POSIX-specific behavior* don't adapt to
  running on Windows) — not a regression in rea-mcp's logic. Confirm this diagnosis and either skip/adapt the
  POSIX-only assertions on Windows (`sys.platform == "win32"`) or run the suite on Linux/WSL for full coverage,
  before reporting test status to Yazeed as a pass/fail count.
- Side project spun out of this one: using rea-mcp to reverse-engineer SelfCAD led to a decision to recreate
  its AI Image-to-3D feature as an independent, model-agnostic app — that became **modelsmith**
  (`C:\Users\yazz9\workspace\modelsmith`, separate repo, its own CLAUDE.md/README). Don't conflate the two:
  rea-mcp is the reverse-engineering tool; modelsmith is the thing partly discovered *with* it.

## Known gaps / open questions
- `yamal` deployment status is unconfirmed — don't assume rea-mcp is installed there until checked.
- SelfCAD reverse-engineering (via this tool) is parked, not abandoned: client-side AI pipeline and
  Image-to-3D internals were extracted (see `selfcad-re-handover-2026-11-09.md`), but response JSON schemas for
  several commands (voxel-model, point-cloud, revolve, bridge, follow-path, custom-shape) are only partly
  extracted, and a Ghidra pass on the native `renderer.exe` was never done.
- Stray `C:\WINDOWS\system32\.venv` from an earlier session was flagged for cleanup — not confirmed removed.

## Suggested skills
- `mattpocock-skills:tdd` — this codebase is built test-first; keep using it for new phases.
- `mattpocock-skills:code-review` before each phase's commit.
- `6ba53849-2ee0-4cf0-957e-31c122ea1dd1:verification-before-completion` before telling Yazeed something works
  (run the actual tests/doctor, don't infer from reading code).
