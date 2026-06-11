<!-- Technical spec for VERDICT (FIND EVIL! hackathon). Produced via 4 veto/approve
     checkpoints, all approved without edits; 0 deepening rounds (declined by choice).
     Every component heading below is a stable address — /checklist references them as
     `spec.md > [Section] > [Subsection]`. Cross-references to prd.md epics throughout. -->

# VERDICT — Technical Spec

One command on a SIFT Workstation — `verdict investigate <case-folder>` — runs a fully
autonomous DFIR investigation through a custom typed read-only MCP server, adversarially
verifies every finding, and emits a cited HTML/PDF report plus a server-written
append-only audit ledger. Safety is architectural: the model's tool list contains only
the 12 typed tools; no shell tool exists to disable.

## Stack

| Layer | Choice | Why | Docs |
|---|---|---|---|
| Language | Python 3.11+ | Learner's strength; both SDKs are Python-first | — |
| MCP server | `mcp` SDK **v1.x (pin <2)** — v1.27.2 current, v2 is pre-alpha | Official SDK; FastMCP server authoring with typed params | [repo](https://github.com/modelcontextprotocol/python-sdk) · [PyPI](https://pypi.org/project/mcp/) |
| LLM client | `anthropic` Python SDK, **manual agentic loop** (not Claude Agent SDK) | The API request contains only our 12 tools — architectural constraint by construction; manual loop hosts narration/ledger/budget hooks | [repo](https://github.com/anthropics/anthropic-sdk-python) · [tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview.md) |
| Models | `claude-sonnet-4-6` for triage **and** verifier | $3/$15 per MTok fits the $5/run cap (Opus 4.8 at $5/$25 ≈ 1.7× busts it); verifier independence comes from fresh context + restricted tools, not model identity. Resolves PRD open question #3. | [models](https://platform.claude.com/docs/en/about-claude/models/overview.md) · [pricing](https://platform.claude.com/docs/en/pricing.md) |
| Validation | `pydantic` v2 | Typed tool params; malformed calls rejected server-side | [docs](https://docs.pydantic.dev/) |
| Terminal UI | `rich` | Live status bar, severity tables, the on-camera REFUTED flip | [docs](https://rich.readthedocs.io/) |
| CLI | `typer` | One subcommand, clean help text | [docs](https://typer.tiangolo.com/) |
| Report | `jinja2` → single self-contained HTML | No server, works offline for judges | [docs](https://jinja.palletsprojects.com/) |
| Forensic binaries | Sleuth Kit, Volatility 3, YARA (native on SIFT); EZ Tools via .NET **or** static fallbacks | Native-first minimizes Day-1 risk | see [Forensic Binary Matrix](#forensic-binary-matrix) |

Async throughout: the MCP client is async, so the orchestrator runs `AsyncAnthropic` +
`mcp.ClientSession` on one event loop.

## Runtime & Deployment

- **Runs on:** SIFT Workstation VM (Ubuntu-based), local only. No deployed URL — judges
  run the bundled smoke case locally (`prd.md > Judge Experience`).
- **Dev loop:** code lives in this repo on the Windows 11 host; runs on the SIFT VM via
  git clone. Forensic binaries exist only on the VM, so the smoke case is also the fast
  iteration loop there.
- **Requirements:** Python 3.11+, `ANTHROPIC_API_KEY` env var, ~60 GB free disk for the
  Szechuan Sauce images, optional .NET runtime for EZ Tools.
- **CLI surface:**
  `verdict investigate <case_dir> [--budget 5.00] [--output runs/] [--model claude-sonnet-4-6]`
  Exit codes: `0` success · `1` invalid/empty case folder (immediate, no investigation
  starts) · `2` interrupted (API outage → partial report) · `3` internal error.

## Architecture Overview

Two processes, one hard boundary. Implements `prd.md > Constrained Tooling`.

```
┌────────────────────── verdict (orchestrator) ──────────────────────┐
│  CLI ─→ survey ─→ TRIAGE LOOP ─→ VERIFIER ─→ report generator      │
│         (Sonnet 4.6, manual loop)  (fresh context    (Jinja2 →     │
│          cost ticker · budget guard  per finding,     HTML/PDF)    │
│          rich terminal narration     restricted tools)             │
└──────────────┬─────────────────────────────────────────────────────┘
               │ stdio (MCP protocol) — the ONLY channel
┌──────────────▼────────────────── verdict-mcp (server) ─────────────┐
│  Pydantic validation → path guard → subprocess runner → LEDGER     │
│  (evidence dir: read-only allowlist · run dir: write-only)         │
│  (fixed binaries, shell=False, timeouts, output caps, SHA-256)     │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
   Sleuth Kit · Volatility 3 · YARA · EZ Tools / static fallbacks
```

**Security boundary (the architecture diagram for submission draws exactly this):**
the model's only actuators are the typed MCP tools the orchestrator places in its
`tools` array for the current phase. There is no bash tool, no file-write tool, no
arbitrary-command tool — not disabled, *absent*. The server independently enforces
path constraints, fixed binaries, `shell=False`, timeouts, and output caps, so even a
confused orchestrator can't be talked into touching evidence. The ledger has a single
writer: the server.

### Phase tool allowlists

| Phase | Tools in the model's `tools` array |
|---|---|
| Triage | tools 1–12 (includes `record_finding`) |
| Verify | tools 2–11 + `record_verdict` (no `record_finding`, no `evidence_inventory`) |
| Orchestrator-only (never shown to the model) | `_log_event` control-plane tool |

Double gate: the orchestrator also refuses to execute any tool name not in the current
phase's allowlist, so a hallucinated call to an unlisted tool is rejected and ledgered.

## Orchestrator (`verdict/`)

### CLI & case validation (`cli.py`)

Typer entry point. Validates the case folder: exists, readable, contains ≥1 recognized
evidence type (disk image `.E01/.dd/.raw`, memory `.mem/.raw/.vmem`, loose artifact
files, pcap). Failure → clear message, exit 1, nothing else runs. Success → create
`runs/<UTC-timestamp>/` (a re-run never overwrites a prior trail), spawn `verdict-mcp`
over stdio, print the evidence inventory table and stated investigation plan within
~10 s. PRD ref: `prd.md > Autonomous Investigation Run`.

### MCP client (`mcp_client.py`)

Spawns the server (`python -m verdict_mcp --case <dir> --run <run_dir>`) and holds the
`ClientSession`. On startup: `list_tools()` → convert each MCP `inputSchema` to an
Anthropic tool definition. On a `tool_use` block: check phase allowlist →
`session.call_tool(name, input)` → stringify result for the `tool_result` block. Tool
schemas are serialized deterministically (sorted) so the prompt cache holds.

### Agent loop (`agent/loop.py`)

The shared manual loop ([pattern docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview.md)):

```
while True:
    response = client.messages.create(model, max_tokens=8192,
        thinking={"type": "adaptive"}, output_config={"effort": "medium"},
        system=[...cache_control...], tools=phase_tools, messages=history)
    track cost from response.usage → budget guard check
    if stop_reason == "end_turn": break
    for tool_use block: narrate line → execute via MCP client → append tool_result
    append assistant turn + tool results; cache_control on newest turn's last block
```

- **Prompt caching:** breakpoint on the last system block (caches tools + system) and on
  the newest message turn. Sonnet 4.6 minimum cacheable prefix is 2048 tokens — our
  system + 12 tool schemas clear it. ([caching docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching.md))
- **Effort:** `medium` default (cost), tunable via config; re-evaluate on smoke runs.
- **Context discipline:** single triage conversation; tool excerpts capped at 8 KB
  (server-side); budget guard as backstop. Fallback lever if smoke runs show context
  blowout: split triage into kill-chain phases with a carried case-notes summary —
  *not* built unless needed.
- **Resilience:** SDK default retries handle 429/5xx. If the API stays down ~2 minutes
  of backoff → write partial report from existing findings, mark run `INTERRUPTED` in
  report + ledger, exit 2. PRD ref: `prd.md > Failure & Empty-Case Behavior`.

### Triage phase (`agent/triage.py`, `agent/prompts.py`)

Hypothesis-driven loop across the kill chain: initial access → persistence → lateral
movement → C2, MITRE [ATT&CK](https://attack.mitre.org/)-guided. System prompt rules:

- Work hypothesis-by-hypothesis; narrate reasoning in 1–2 plain-English sentences
  between hypotheses (`prd.md > Autonomous Investigation Run`).
- **Recall-oriented:** record findings as hypotheses with citations — the verifier
  reproduces them. (This division of labor is also what makes the smoke-case decoy fire.)
- Always narrow queries (time window / keyword / event IDs); never slurp.
- Conflicting evidence (e.g., inconsistent timestamps) is itself a finding citing both
  sources — never silently resolved (`prd.md > Failure & Empty-Case Behavior`).
- Clean evidence → say so; an honest empty report is a success state.
- Cite ledger sequence numbers via `record_finding`; uncited claims are worthless.
- Seek ≥1 finding cited from **both** memory and disk (the disk↔memory correlation
  requirement, `prd.md > Investigation Report`).

### Verifier phase (`agent/verifier.py`)

For each recorded finding, a **fresh conversation** (no triage history): adversarial
system prompt ("your job is to break this claim"), restricted toolset, input = the claim
+ the cited ledger entries (tool names + exact params + output SHA-256 + stored output
path). The verifier re-runs the cited queries itself and must independently re-derive
the claim. Verdicts via `record_verdict`:

| Verdict | Meaning |
|---|---|
| `VERIFIED` | Independently reproduced; evidence supports the claim |
| `UNCONFIRMED` | Could not fully reproduce (tool failure, ambiguity) — no contradiction found |
| `REFUTED` | Evidence contradicts the claim; reason recorded |

Each verdict flips live on the terminal with a one-line reason. Refuted findings go to
the report appendix with their refutations. Verify contexts are small (one finding
each), so this phase is cheap. PRD ref: `prd.md > Self-Verification`.

### Budget guard (`budget.py`)

Tracks cost from every `response.usage` (input $3/M, output $15/M, cache read $0.30/M,
cache write $3.75/M). Estimated full-run cost ≈ $2.50–4.50 with caching + caps.
Sub-budgets: triage soft-cap at 60% of `--budget`, verify reserved 30%, report 10%.
Triage hitting its cap → stop opening hypotheses, force transition to verify; emit a
`budget_event` ledger line and a report note. Never a dead process at $5.01.
PRD ref: `prd.md > Autonomous Investigation Run` (≤$5/run story).

### Findings store (`findings.py`)

In-memory list flushed to `runs/<id>/findings.json` after every mutation. Fields per
finding: `id`, `claim`, `severity` (critical/high/medium/low), `attack_id` (technique,
e.g. `T1543.003`), `cites` (ledger seq numbers), `verdict`, `verdict_reason`. The ledger
remains the authoritative audit trail; this file is convenience run-state.

### Terminal UI (`terminal.py`)

`rich` rendering — this *is* the demo video (`prd.md > Autonomous Investigation Run`):

- One line per tool call: `[09:14:03] evtx_query log=Security ids=[4624] 1.2s sha=ab12… $0.43 total`
- Agent narration between hypotheses, dimmed.
- Persistent status bar: findings count · elapsed · cumulative cost.
- Verify phase: per-finding `VERIFIED`/`UNCONFIRMED`/`REFUTED` flip with color + reason.
- Completion: severity-sorted findings summary table + artifact paths, exit 0.

### Report generator (`report/`)

Jinja2 → **one self-contained `report.html`** (inline CSS, no JS dependencies, anchors
only — judges open it offline). Structure, per `prd.md > Investigation Report`:

1. Header: case, run ID, wall time, total cost, model.
2. Executive summary — 5–8 plain-English sentences (what happened, when, how bad).
3. Attack narrative — chronological, every sentence footnoted to a finding.
4. Findings table — severity-coded: ID, title, severity, confidence, ATT&CK ID,
   evidence count. `VERIFIED` + `UNCONFIRMED` only.
5. Per-finding detail — claim, artifact excerpts + paths, verifier's reproduction note,
   citations as anchors jumping into the embedded ledger rendering (§7).
6. Appendix A — refuted findings **with refutations** (proof the self-correction fired).
7. Appendix B/C — evidence inventory + SHA-256s; full chronological tool-call index
   (human-readable ledger rendering).
8. Appendix D — methodology + constraints statement (what the agent physically cannot do).

Summary/narrative prose is one extra Sonnet call over the verified findings.
**PDF:** attempt chain — `chromium --headless --print-to-pdf` → `wkhtmltopdf` → manual
print-to-PDF before submission (PRD only requires the PDF exists; resolves open
question #4).

## MCP Server (`verdict_mcp/`)

FastMCP app, stdio transport, started per-run with `--case` (read root) and `--run`
(write root). PRD ref: `prd.md > Constrained Tooling`.

### Path guard (`pathguard.py`)

Resolves every path param to an absolute real path (symlinks resolved). Reads must fall
under the case dir; writes only under the run dir. Violations → typed refusal, ledgered
as `tool_rejected`. Evidence files are never opened for writing anywhere in the server.

### Subprocess runner (`runner.py`)

Single choke point for all external binaries: fixed executable paths from a config map
(never from model input), `shell=False`, argument lists built from validated params,
per-tool timeout (default 120 s; `mem_analyze` 600 s), stdout/stderr captured. Full
output → `runs/<id>/outputs/<seq>_<tool>.{json,txt}` + SHA-256 → ledger. The model
receives an excerpt capped at 8 KB plus a pointer to the full artifact
(`prd.md > Constrained Tooling`, oversized-output story). Nonzero exit → structured
error result (`is_error`), ledgered; the loop retries once, then routes around — one
broken parser never kills the run.

### Ledger writer (`ledger.py`)

Append-only `runs/<id>/ledger.jsonl`, **written by the server only**, one JSON object
per line, `fsync` after every line — intact up to the moment of death if the process is
killed. PRD ref: `prd.md > Audit Ledger`. Schema:

```json
{"seq": 43, "ts": "2026-06-12T09:14:03.221Z", "run_id": "...", "event": "tool_result",
 "tool": "evtx_query", "duration_ms": 1180, "output_sha256": "ab12…",
 "output_path": "outputs/0043_evtx_query.json", "truncated": true, "exit_code": 0}
```

Event types: `run_started` · `tool_called` (tool, params) · `tool_result` (above) ·
`tool_rejected` (tool, validation/path error) · `finding_recorded` · `verdict_recorded`
· `api_usage` (tokens in/out/cached, cost USD) · `budget_event` · `run_interrupted` ·
`run_ended`. Orchestrator-side events (`run_started`, `api_usage`, `budget_event`,
`run_ended`) reach the ledger through the `_log_event` control-plane tool — which is
**never in the model's tool list** — preserving the single-writer claim: the agent has
no tool that writes the ledger.

### Tool definitions (`server.py`, `tools/`)

All params Pydantic-validated; every query tool requires narrowing params where the
underlying data is large. Tools accept either image-backed evidence or loose artifact
files (the smoke case is loose files; tools 2–3 apply to images only).

#### 1. `evidence_inventory`
Walk the case dir; classify each file (disk image / memory / loose artifact / pcap —
pcap noted, never parsed, per PRD non-goals); SHA-256 everything. Returns the inventory
table. Wraps: `file`, hashlib.

#### 2. `fs_list`
List files in a disk image path. Params: `image`, `partition_offset?`, `path`,
`recursive?` (depth-capped). Wraps Sleuth Kit [`fls`](https://www.sleuthkit.org/sleuthkit/man/fls.html)
(E01 via libewf, native on SIFT). No mounting — no root needed.

#### 3. `fs_extract`
Extract one file from an image into `runs/<id>/artifacts/` for downstream parsing.
Params: `image`, `partition_offset?`, `inode|path`. Wraps `icat`/`tsk_recover`.

#### 4. `mft_query`
Parse MFT (extracted via tool 3) with filters: `path_contains?`, `after?`, `before?`,
`deleted_only?`. Wraps MFTECmd (fallback `fls -m` bodyfile filtering).

#### 5. `evtx_query`
Query an event log. Params: `log` (path), `event_ids?`, `after?`, `before?`,
`keyword?`, `limit` (≤500). Wraps EvtxECmd (fallback
[`evtx_dump`](https://github.com/omerbenamram/evtx) + jq-style filter in Python).

#### 6. `registry_query`
Run named plugins against an extracted hive. Params: `hive` (path), `plugin` (enum:
run_keys, services, usb, network, sam_users, …). Wraps RECmd batch (fallback
RegRipper `rip.pl`, native on SIFT).

#### 7. `execution_evidence`
Prefetch + Amcache in one tool. Params: `source` (pf file/dir or Amcache.hve),
`name_contains?`, `after?`, `before?`. Wraps PECmd + AmcacheParser.

#### 8. `timeline_query`
Filesystem timeline pivots. Params: `image|bodyfile`, `after`, `before` (window
required), `keyword?`. Wraps `fls -m` → [`mactime`](https://www.sleuthkit.org/sleuthkit/man/mactime.html);
bodyfile built once per image and cached in the run folder. **Deliberate scope choice:**
no Plaso supertimeline — `log2timeline` on 25–30 GB images runs for hours and would
break the 30-minute target; Plaso stays as targeted single-artifact fallback only.

#### 9. `mem_analyze`
Run one allowed [Volatility 3](https://volatility3.readthedocs.io/) plugin. Params:
`image`, `plugin` (enum: pslist, pstree, psscan, netscan, malfind, cmdline, dlllist,
handles), `filter?`. Plugin allowlist enforced server-side — arbitrary plugin names
rejected.

#### 10. `yara_scan`
Params: `target` (extracted file, artifact dir, or memory image), `ruleset` (enum from
`rules/`). Wraps [YARA](https://yara.readthedocs.io/). Returns match names + offsets.

#### 11. `read_artifact`
Bounded read of an extracted/output file. Params: `path` (run dir or case dir loose
file), `offset?`, `length` (≤8 KB), `mode` (text|hex). The verifier's content-inspection
workhorse.

#### 12. `record_finding` (triage only)
Params: `claim` (plain English), `severity` (enum), `attack_id` (validated against
`T\d{4}(\.\d{3})?`), `cites` (list of ledger seq numbers, ≥1 required, must reference
existing `tool_result` entries). Writes to findings store + ledger.

#### 13. `record_verdict` (verify only)
Params: `finding_id`, `verdict` (enum VERIFIED/UNCONFIRMED/REFUTED), `reason` (one
line). Ledgered; flips the terminal line.

#### `_log_event` (orchestrator only — never exposed to the model)
Control-plane channel for orchestrator events into the server-written ledger
(`run_started`, `api_usage`, `budget_event`, `run_interrupted`, `run_ended`).

### Forensic Binary Matrix

Day-1 gate validates every row before any other work (see [Open Issues](#open-issues)).

| Capability | Primary | Fallback | Native on SIFT? |
|---|---|---|---|
| Filesystem / extract | Sleuth Kit (`fls`, `icat`, `mactime`) | — | ✅ |
| Memory | Volatility 3 | — | ✅ |
| YARA | `yara` | `yara-python` | ✅ |
| Event logs | EvtxECmd (.NET — [SANS Linux guide](https://www.sans.org/blog/running-ez-tools-natively-on-linux-a-step-by-step-guide)) | `evtx_dump` static binary | install |
| MFT | MFTECmd (.NET) | `fls -m` bodyfile | install / ✅ |
| Registry | RECmd (.NET) | RegRipper (`rip.pl`) | install / ✅ |
| Prefetch/Amcache | PECmd + AmcacheParser (.NET) | prefetch: `pyscca`; amcache: RegRipper plugin | install / partial |
| Timeline | `fls -m` + `mactime` | Plaso (targeted, single-artifact only) | ✅ |

## Data Model

### Finding
`id` · `claim` · `severity` (critical/high/medium/low) · `attack_id` · `cites[]`
(ledger seqs) · `verdict` (VERIFIED/UNCONFIRMED/REFUTED/None) · `verdict_reason`.

### Ledger event
See [Ledger writer](#ledger-writer-ledgerpy) — `seq` (monotonic), `ts`, `run_id`,
`event`, event-specific fields. JSONL, one event per line, server-written.

### Run folder
`runs/<UTC-timestamp>/` → `ledger.jsonl` · `findings.json` · `report.html` ·
`report.pdf` · `outputs/<seq>_<tool>.*` (full tool outputs) · `artifacts/` (files
extracted from images) · `bodyfile/` (cached timelines).

### State lifecycle
Conversation state: in memory only, gone at exit. Everything durable: the run folder.
Nothing global. Re-run after interruption = fresh run folder, never a resume
(`prd.md > Failure & Empty-Case Behavior`).

## Data Flow — Lifecycle of a Finding

```
triage agent ──tool_use──▶ MCP server: validate → pathguard → runner
                              │  full output → outputs/0042_… (+SHA-256)
                              │  ledger seq 42 tool_called / seq 43 tool_result
                ◀─excerpt (≤8KB) + pointer──┘
agent narrates → record_finding(claim, severity, T-id, cites=[43]) → store + ledger
                                ▼
verifier (fresh context, restricted tools): claim + cited params
        re-runs the queries itself → record_verdict(VERIFIED|UNCONFIRMED|REFUTED)
                                ▼
report generator: VERIFIED/UNCONFIRMED → main table · REFUTED → appendix w/ refutation
        every citation = anchor into the embedded ledger rendering → report.html/pdf
```

## Smoke Case (`cases/smoke/`)

A few MB of loose sanitized artifacts; full pipeline in ~3 minutes for pennies; doubles
as the dev test loop protecting the $50 budget. Resolves PRD open question #5.
PRD ref: `prd.md > Judge Experience`.

| Artifact | Source | Role |
|---|---|---|
| Small `Security.evtx`/`System.evtx` (type-3 logons, 7045 service install) | sanitized picks from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (verify license Day 1; fallback: generate events on the Windows host) | findable indicator #1 |
| Registry hive with Run-key → `C:\Users\Public\update.exe` | exported from Windows 11 host | findable indicator #2 (persistence) |
| Prefetch `.pf` for that exe | renamed real prefetch | execution evidence → dual-source `VERIFIED` finding |
| Benign file matching a custom YARA rule | ours (EICAR-style) | malware-ID path |
| **Decoy: `mimikatz.exe` that is 12 bytes of ASCII text** | ours | **the reproducible REFUTED flip** |

Why the decoy fires: triage is recall-oriented by prompt and flags the filename; the
verifier reads the content (`read_artifact`) and yara-scans it → `REFUTED: filename
suggests credential-theft tool; content is ASCII text`. Not staged — it is the
architecture's real triage-recall / verifier-precision split catching a real-world
trap. A non-biting take re-runs for pennies.

### Clean case (`cases/clean/`)
A handful of benign artifacts. Standing test: run it, expect a valid, complete,
honest-empty report — zero invented findings (`prd.md > Failure & Empty-Case Behavior`).

## Primary Dataset

**The Case of the Stolen Szechuan Sauce** —
[dfirmadness.com](https://dfirmadness.com/the-case-of-the-stolen-szechuan-sauce/): DC +
desktop disk images (E01), memory captures, pcap, published ground truth.
`docs/accuracy-report.md` tables every ground-truth fact as found / partially found /
missed, counts extra findings, states misses honestly (`prd.md > Judge Experience`).
Day-1 gate: download links live, hashes verify, Volatility 3 handles both memory
captures, ground-truth facts list enumerated (PRD open questions #1–2). Fallback
datasets: SANS / CFReDS / Digital Corpora.

## File Structure

```
verdict/
├── pyproject.toml            # anthropic, mcp<2, pydantic, rich, jinja2, typer
├── README.md                 # try-it-out: smoke case first        [submission]
├── LICENSE                   # Apache-2.0                          [submission]
├── verdict/                  # ── ORCHESTRATOR ──
│   ├── cli.py                # entry, case validation, run-folder creation
│   ├── agent/
│   │   ├── loop.py           # manual agentic loop (both phases)
│   │   ├── triage.py         # kill-chain hypothesis phase
│   │   ├── verifier.py       # fresh-context per-finding adversarial pass
│   │   └── prompts.py        # triage / verifier / report-prose system prompts
│   ├── mcp_client.py         # stdio spawn, schema conversion, phase allowlists
│   ├── budget.py             # token→$ ticker, sub-budgets, graceful degrade
│   ├── findings.py           # findings store → findings.json
│   ├── terminal.py           # rich: tool lines, status bar, REFUTED flip
│   └── report/
│       ├── generator.py      # render report.html, PDF attempt chain
│       └── template.html.j2  # self-contained: findings + embedded ledger view
├── verdict_mcp/              # ── MCP SERVER (the constrained side) ──
│   ├── server.py             # FastMCP app, 13 tool defs, phase metadata
│   ├── tools/                # inventory.py fs.py mft.py evtx.py registry.py
│   │                         #   execution.py timeline.py memory.py yara_scan.py
│   │                         #   artifacts.py findings_tools.py
│   ├── runner.py             # fixed bins, shell=False, timeouts, caps, SHA-256
│   ├── pathguard.py          # evidence RO / run-dir WO enforcement
│   ├── ledger.py             # append-only JSONL, fsync per line, server-only
│   └── binaries.py           # binary path map + Day-1 availability check
├── cases/
│   ├── smoke/                # bundled judge case                  [submission]
│   └── clean/                # honest-empty-report standing test
├── rules/                    # curated YARA rules (incl. smoke-case rule)
├── runs/                     # per-run outputs (gitignored)
├── docs/                     # scope/prd/spec/checklist +
│   ├── architecture.md       #   security-boundary diagram         [submission]
│   ├── dataset.md            #   Szechuan + smoke provenance       [submission]
│   └── accuracy-report.md    #   vs published ground truth         [submission]
└── process-notes.md
```

## Key Technical Decisions

1. **Manual agentic loop over Claude Agent SDK.** The Agent SDK ships bash/file tools
   that must be disabled by configuration — a permission-based guardrail, the exact
   weakness in baseline Protocol SIFT that VERDICT attacks. The manual loop means the
   API request *contains only the typed tools*; the harmful capability never exists.
   Tradeoff accepted: more loop code to write — which we wanted anyway for narration,
   ledger, cost ticker, and budget-guard hooks.
2. **Sonnet 4.6 for both triage and verifier.** Fits the $5/run cap (~$2.50–4.50
   estimated with caching + caps); Opus 4.8 ≈ 1.7× cost busts it. Verifier independence
   is structural (fresh context, restricted tools), not model-based. Tradeoff: slightly
   lower ceiling than Opus on hard reasoning; mitigated by hypothesis-driven prompting
   and the verify pass.
3. **Bodyfile/mactime timeline instead of Plaso supertimeline.** `log2timeline` on
   25–30 GB images runs for hours, breaking the 30-minute target and Day 1–2. Tradeoff:
   timeline covers filesystem timestamps only; event-log/registry/execution timestamps
   come from their own tools (4–7), which collectively cover the kill chain.
4. **Single-writer ledger via an orchestrator-only control-plane tool.** All ledger
   lines are written by the server; orchestrator events flow through `_log_event`,
   which is never in the model's tool list. Keeps the audit-trail claim crisp: *the
   agent has no tool that writes the ledger.*
5. **Smoke case as loose artifacts with a filename decoy.** No tiny disk image to
   engineer; tools handle loose files; the `mimikatz.exe`-that-is-text decoy makes the
   REFUTED wow moment reproducible without staging.

## Dependencies & External Services

| Dependency | Notes | Docs |
|---|---|---|
| Anthropic API | Only external service. $50 total budget, $5/run guard, cost tracked per call from `usage`. Key via `ANTHROPIC_API_KEY`. | [SDK](https://github.com/anthropics/anthropic-sdk-python) |
| `mcp` (pin `<2`) | v1.27.2 current; v2 pre-alpha — do not float | [PyPI](https://pypi.org/project/mcp/) |
| Forensic binaries | See [Forensic Binary Matrix](#forensic-binary-matrix); validated by Day-1 gate | per-row links |
| Szechuan Sauce dataset | ~25–30 GB download; hashes verified Day 1 | [case page](https://dfirmadness.com/the-case-of-the-stolen-szechuan-sauce/) |

## Open Issues

| # | Issue | Resolve |
|---|---|---|
| 1 | **Day-1 go/no-go gate** (carries PRD #1–2): Szechuan links live + hashes verify; Volatility 3 parses *both* memory captures; ground-truth facts enumerable; every Binary-Matrix row green on the SIFT VM. | Day 1, before any other build work |
| 2 | **Vol3 vs the Server 2012 R2 DC memory image** — symbol support for older Windows builds is the weakest Vol3 spot. Fallback: focus memory analysis on the Win10 desktop capture; DC covered by disk artifacts. | Day-1 gate |
| 3 | **EVTX-ATTACK-SAMPLES redistribution license** for smoke artifacts. Fallback: generate events on the Windows host. | Day 1 |
| 4 | **Effort/cost calibration** — `effort: medium` and the 8 KB excerpt cap are estimates; tune on smoke runs before the first full Szechuan run. Fallback lever: phased triage with case-notes carryover. | Day 2 smoke runs |
| 5 | **Verifier replay drift** — evidence is static so re-runs should match cited outputs; if a re-run's SHA differs from the cited `tool_result`, the verifier flags it explicitly (possible nondeterministic tool output) rather than silently passing. | Build (verifier) |
| 6 | Demo video tooling + take structure (PRD #6). | Day 5, not blocking |
