# rea-mcp

Zero-trust reverse-engineering MCP server. Four tools (`rea_query`, `rea_mutate`, `rea_privileged`,
`rea_capabilities`) sit in front of IDA Pro, IDA Free and Ghidra bridges, a read-only source and
evidence engine, an append-only evidence ledger (ConfirmedFact / Hypothesis / UnanalyzedGap) and a `rea://`
registry of playbooks and reference material. Python 3.12+.

## Quick start

From the extracted folder (needs `git`; Podman is optional):

```
python3 -m venv .venv && . .venv/bin/activate && pip install -e . && rea-mcp-bootstrap --workspace ~/workspace/rea-data && rea-mcp-doctor --host-config ~/workspace/rea-data/mcp.host.json
```

Then import `~/workspace/rea-data/mcp.host.json` into your MCP host (it is the standard `mcpServers` format).
Open IDA Pro, IDA Free or Ghidra with its MCP bridge before running the doctor if you want it to exit 0 with
backends configured.

### Windows 11 (native)

Needs Python 3.12 or newer (3.11 is too old; `uv` installs 3.12 beside it without touching it) and Git for Windows.
In PowerShell, from the extracted folder:

```
winget install --id astral-sh.uv -e; winget install --id Git.Git -e      # skip what you already have; reopen PowerShell after
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"
.\.venv\Scripts\rea-mcp-bootstrap.exe --workspace $HOME\workspace\rea-data --ghidra-url http://127.0.0.1:18080
.\.venv\Scripts\rea-mcp-doctor.exe --host-config $HOME\workspace\rea-data\mcp.host.json
.\.venv\Scripts\rea-mcp-register.exe --host-config $HOME\workspace\rea-data\mcp.host.json --config $env:APPDATA\Claude\claude_desktop_config.json
```

Then quit and reopen Claude Desktop. If Claude Desktop is the Microsoft Store (MSIX) build, its config is under
`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\` instead. For Claude Code run
`claude mcp add-json --scope user rea` with the `rea` block from `mcp.host.json`.

Differences from Linux: the Podman sandbox is Linux-only, so `script_eval` stays disabled and bootstrap skips
that step; links are never followed (symlinks and junctions are skipped, and a file swapped for a link between
the check and the open is refused); file modes `0600` and `0700` are Unix permissions, so on Windows the
workspace is protected by your profile folder's ACL instead, so keep it under `%USERPROFILE%`.
IDA and Ghidra run natively on Windows, so their loopback bridges (`127.0.0.1`) are reachable directly.

## Commands

| Command | What it does |
|---|---|
| `rea-mcp` | Starts the MCP server on stdio. This is what the host launches. |
| `rea-mcp-bootstrap --workspace DIR` | Prepares a workspace (see below). Safe to re-run. |
| `rea-mcp-doctor [--host-config FILE]` | Read-only live diagnostics. |
| `rea-mcp-convert-txt PATH...` | Converts `.txt` notes to Markdown, in place. |
| `rea-mcp-register --host-config FILE --config FILE` | Adds the `rea` server to an MCP client's config (Claude Desktop, `.mcp.json`...) without touching its other servers. Backs the file up to `<file>.bak` first. |

### `rea-mcp-bootstrap`

```
rea-mcp-bootstrap --workspace ~/workspace/rea-data [--convert-txt] [--only REPO ...] [--skip-clone] [--skip-podman]
                  [--ida-pro-url URL|none] [--ida-free-url URL|none] [--ghidra-url URL|none] [--image IMAGE] [--git PATH]
```

1. Creates `targets/`, `knowledge/` and `ledger/` with mode `0700`.
2. Shallow-clones the 15 reference repositories into `knowledge/`, skipping any that already exist. Clones run
   with hooks, symlinks, submodules, credentials and non-HTTPS protocols disabled, into a private staging folder
   that is moved into place only after cleaning. Cleaning removes `.git`, hidden folders, symlinks and every
   file that is not Markdown or text.
3. Converts the text files to Markdown and drops boilerplate (below), so `knowledge/` holds `.md` files only.
   `--convert-txt` also sweeps what is already in `knowledge/`, including your own stray `.txt` notes.
4. Checks that every file under `knowledge/` is a regular `.md` file and indexes the corpus.
5. If rootless Podman is installed: pulls `docker.io/library/python:3.12-slim` and runs the sandbox isolation probe.
6. Writes `mcp.host.json` (mode `0600`) with absolute paths, and `bootstrap.json` (commits fetched, per-repo counts).

Backend URLs must be loopback (`127.0.0.1` or `::1`). Defaults: IDA Pro `http://127.0.0.1:13337`, Ghidra
`http://127.0.0.1:8080`, IDA Free off (it shares port 13337 with IDA Pro). Exit status: `0` ok, `1` a step
failed (a clone, the corpus, a stray non-Markdown file, or an installed-but-unusable Podman), `2` bad usage.

### `rea-mcp-doctor`

```
rea-mcp-doctor [--host-config FILE] [--require-all] [--sandbox] [--verbose] [--timeout SECONDS]
```

Probes each configured loopback endpoint (the default ports if none is configured), prints a status table
(wire profile negotiated: `ida-pro-mcp`, `ida-free-mcp` or `GhidraMCP`; active capabilities; why the others
are unsupported), then runs a read-only smoke test of the real server wiring: `rea_capabilities`, the evidence
engine, the `rea://` registry and the corpus index.

Every active capability carries a label. `PROBED_LIVE` capabilities were actually called (one read-only
listing request each). For Ghidra the other active capabilities are `STATIC_ROUTE_TABLE`: matched from the
route table and never fired, so no mutating POST is ever sent. For IDA they are `TOOL_LIST_MATCH`: matched from
the bridge's own tool list.

Exit status: `0` healthy, `1` a problem was found (one live configured backend is enough unless `--require-all`),
`2` unusable configuration. `--sandbox` also runs the live Podman probe; `--verbose` prints the IDA tool list.

### `rea-mcp-convert-txt`

```
rea-mcp-convert-txt PATH [PATH ...] [--delete-rejected]
```

`PATH` is a `.txt` file or a folder. The registry indexes Markdown only, so each `.txt` becomes a `.md`:

- **Dropped unread:** `requirements*.txt`, `constraints*.txt`, `license*.txt`, `copying*.txt`, `notice*.txt`,
  `authors*.txt`, `version*.txt`, `robots.txt`, `cmakelists.txt`, `manifest.txt`, `indexnow*.txt`; empty files too.
- **Rejected, never repaired:** symlinks (never followed), non-regular files, files over 2 MiB, files with a NUL
  byte, files that are not strictly valid UTF-8. They are left in place and reported (exit `1`) unless you pass
  `--delete-rejected`; bootstrap always deletes them from `knowledge/`.
- **Promoted:** a file with no top-level heading gets `# <Title from the file name>`; an unclosed code fence is
  closed; a raw disassembly or hex dump is kept verbatim inside a fenced `text` block.
- **Placed safely:** written atomically with mode `0600` to `<stem>.md`, or `<stem>_txt.md` (then `_txt_2`...)
  when that name exists, and only then is the original deleted. Nothing is ever overwritten.

`.markdown` and `.MD` files are renamed to `.md` the same way.

## Configuration (environment of the MCP host)

| Variable | Meaning |
|---|---|
| `REA_ALLOWED_ROOTS` | `os.pathsep`-separated directories the server may read. Required for source, scan and SARIF tools. Must exist. |
| `REA_IDA_PRO_URL` | IDA Pro bridge (`ida-pro-mcp`), loopback only. A backend that is not configured is never contacted. |
| `REA_IDA_FREE_URL` | IDA Free bridge, loopback only. |
| `REA_GHIDRA_URL` | GhidraMCP bridge, loopback only. GhidraMCP **2.0** (JSON replies, `/functions`) and 1.x (plain text, `/methods`) are told apart by `GET /health`; the doctor names the dialect and the open program. 2.0 needs a program open in a CodeBrowser. Default port 8080. |
| `REA_LEDGER_DIR` | Persist ledgers here. Journals are bound to the workspace (BLAKE3 of the normalized roots). |
| `REA_SESSION_ID` | Stable session id (default `default` when `REA_LEDGER_DIR` is set, else random per process). |
| `REA_LEDGER_ALLOW_WORKSPACE_MISMATCH=1` | Load a journal written for a different workspace. |
| `REA_KNOWLEDGE_DIR` | Folder of Markdown repositories, inside `REA_ALLOWED_ROOTS`, mounted under `rea://cases/`. Only `.md` files are indexed. |
| `REA_REDACT_ARTIFACTS=on` | Mask secrets found in the target (default: tag only). |
| `REA_AUDIT_LOG` | Tamper-evident audit log path. |
| `REA_PRIVILEGED_OVERRIDE=enable-dangerous-ops` | First of the switches that unlock the privileged tier (off by default; any other value keeps it off). |
| `REA_PRIVILEGED_ALLOW` | Comma-separated privileged capabilities to enable (for example `patch_bytes,save_database`). Unknown or non-privileged names stop startup. |
| `REA_PRIVILEGED_KEYFILE` | Optional kill switch: if set, the file must exist and be non-empty at every privileged call; delete it to revoke access. |
| `REA_AUTO_GRANT_MUTATE=1` | Approve database edits without asking the user (unattended use only). |

Bad settings stop startup with a message on stderr; unrecognized `REA_*` names produce a warning.

## The four tools

| Tool | Tier | Capabilities | Approval |
|---|---|---|---|
| `rea_capabilities` | n/a | Lists every capability, its tier and whether it is enabled now. Takes no arguments; call it first. | none |
| `rea_query` | read-only (28) | `decompile`, `disasm`, `xrefs_to`, `xrefs_from`, `callees`, `basic_blocks`, `stack_frame`, `function_info`, `callgraph`, `read_struct`, `list_*`, `search_functions`, `find_regex`, `find_bytes`, `get_bytes`, `scan_hotspots`, `source_outline`, `source_read`, `ledger_list`, `ledger_get`, `ledger_summary` | none |
| `rea_mutate` | mutate-safe (22) | Evidence ledger: `ledger_record_fact`, `ledger_record_hypothesis`, `ledger_promote`, `ledger_refute`, `ledger_declare_gap`, `ledger_close_gap`, `import_sarif`. Database edits: `rename_symbol`, `rename_variable`, `set_comment`, `set_type`, `set_function_prototype`, `set_variable_type`, `declare_type`, `add_bookmark`, `define_function`, `define_code`, `undefine`, `declare_stack_var`, `delete_stack_var`, `open_database`, `close_database` | ledger: none; database edits: user, once per session |
| `rea_privileged` | privileged (6) | `patch_bytes`, `patch_asm`, `write_memory`, `save_database`, `script_eval` (rootless Podman sandbox), `debugger_control` | hard-disabled until the operator enables each one |

Every call is `{"args": {"capability": "...", ...}, "control": {...}}`, with optional top-level `database` and
`backend`. `control` carries `receipt_id`, `known_hashes` and `token_budget`; results report `meta.next_cursor`,
`meta.truncated` and `meta.result_complete`. Results are compact JSON text (no `structuredContent`). Prompts:
`triage-binary`, `crypto-audit`, `protocol-reconstruction`, `vulnerability-surface-audit`, `evidence-review`.
Resources: `rea://index`, `rea://prompts/{name}`, `rea://cases/{category}[/{path}]`, `rea://search/{query}`.

## Install as a plugin or plain server

As a plugin (Claude Code, Cursor, any host that reads Agent Plugins 1.0.0): drop this directory in as a plugin.
`mcp.json` launches it with `uvx --from ${PLUGIN_ROOT} rea-mcp`; `skills/rea-mcp/SKILL.md` teaches the model how
to use it. As a plain MCP server: `pip install .`, then run `rea-mcp` (stdio), or use the host config that
`rea-mcp-bootstrap` writes.

## Develop

`pip install -e .[dev]`, then `pytest` (it includes `mypy --strict`-level checks over `src`, `tests` and
`scripts`, and a scan that fails on `Any`, placeholders and type-check suppressions).
