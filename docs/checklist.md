<!-- Build checklist for VERDICT (FIND EVIL! hackathon, deadline June 15, 2026).
     Every item MUST use the five-field format. /build reads each item and relies on
     all five fields. Sequencing approved by learner June 11, 2026: riskiest first
     (Day-1 gate), loose-artifact tools before image tools so the full pipeline is
     proven end-to-end on the cheap smoke case (~Day 2) before touching 30GB images.
     Day mapping: items 1–4 Day 1 · 5–8 Day 2 · 9–11 Day 3 · 12–13 Day 4 · June 15 buffer.
     Dev on Windows 11 host; execution on SIFT Workstation VM (git clone). -->

# Build Checklist

## Build Preferences

- **Build mode:** Autonomous — one `/build` run orchestrates the whole checklist, dispatching items to subagents.
- **Comprehension checks:** N/A (autonomous mode)
- **Git:** Commit after each item with message: `Complete step N: [title]`. Commits are revert points — if an item breaks mid-build, revert to the last clean commit, revise the checklist, resume. Push to GitHub after each checkpoint.
- **Verification:** Yes — checkpoints after items **2** (go/no-go gate), **5** (tools + cases), **7** (first autonomous smoke run), **11** (full Szechuan run). At each checkpoint the agent pauses, summarizes, and the learner reviews before the build continues. Items requiring the learner physically (SIFT VM runs, video recording) are flagged inline.
- **Check-in cadence:** N/A (autonomous mode)
- **Budget guardrail (build-wide):** $50 total API budget. All dev/test iteration runs on the smoke case (pennies/run). Full Szechuan runs are scarce — budget allows ~6–8 at ≤$5 each; item 11 plans for at most 2–3.

## Checklist

- [x] **1. Scaffold, GitHub repo, dataset download kickoff**
  Spec ref: `spec.md > File Structure` + `spec.md > Runtime & Deployment`
  What to build: Full package skeleton exactly per the spec's file structure (`verdict/` orchestrator + `verdict_mcp/` server + `cases/` + `rules/` + `docs/`); `pyproject.toml` pinning anthropic, `mcp<2`, pydantic v2, rich, jinja2, typer; Apache-2.0 `LICENSE`; README stub (smoke-case-first layout, filled in item 12); `.gitignore` covering `runs/`, dataset paths, `.env`. `git init`, create **public** GitHub repo `verdict` via `gh` (account `prabhakaran-jm`, already authenticated), push. Write `scripts/get-dataset.sh` (Szechuan Sauce download URLs + SHA verification) and start the ~25–30GB download on the SIFT VM in the background so it runs while items 2–4 proceed.
  Acceptance: Public repo live with the scaffold; `pip install -e .` succeeds clean in a fresh venv; download started and progressing on the VM (`prd.md > Submission Package` — public Apache-2.0 repo).
  Verify: Open the `gh repo view --web` URL and confirm the repo is public with LICENSE visible; run `pip install -e .` and confirm exit 0; check download progress on the VM.

- [x] **2. Day-1 go/no-go gate (on the SIFT VM)** ⚠ learner at the VM
  Spec ref: `spec.md > Open Issues` (#1–#3) + `spec.md > MCP Server > Forensic Binary Matrix` + `spec.md > Primary Dataset`
  What to build: `verdict_mcp/binaries.py` — the binary path map plus a `--check` mode that probes every Forensic Binary Matrix row (primary, then fallback) and prints a green/red table. Then run the gate on the VM: (a) every matrix row green or fallback noted; (b) Volatility 3 `windows.pslist` succeeds on **both** Szechuan memory captures (DC 2012 R2 is the known weak spot — if it fails, record the fallback: desktop capture for memory, DC via disk artifacts); (c) dataset hashes verify; (d) enumerate the published ground-truth facts into `docs/ground-truth.md` as the scoring base for item 11; (e) confirm EVTX-ATTACK-SAMPLES redistribution license for smoke artifacts (fallback: generate events on the Windows host). Record an explicit GO / PIVOT decision in `process-notes.md`.
  Acceptance: PRD Open Questions #1–2 resolved with evidence; every capability in `prd.md > Constrained Tooling` (tool coverage list) has a confirmed working binary; GO/PIVOT recorded.
  Verify: Run `python -m verdict_mcp.binaries --check` on the VM and confirm all rows green/fallback; eyeball two successful pslist outputs; open `docs/ground-truth.md` and confirm the facts list is enumerable and scorable. **← VERIFICATION CHECKPOINT 1**

- [x] **3. MCP server foundation — ledger, pathguard, runner**
  Spec ref: `spec.md > MCP Server` (Ledger writer · Path guard · Subprocess runner) + `spec.md > Architecture Overview`
  What to build: `ledger.py` — append-only `ledger.jsonl`, one JSON object per line, monotonic `seq`, UTC `ts`, `fsync` after every line, all event types from the spec schema; `pathguard.py` — resolve to real paths, reads only under `--case`, writes only under `--run`, violations return typed refusals and ledger `tool_rejected`; `runner.py` — single subprocess choke point: fixed executable paths from `binaries.py` (never from model input), `shell=False`, per-tool timeouts (default 120s, `mem_analyze` 600s), full output to `runs/<id>/outputs/<seq>_<tool>.*` with SHA-256 ledgered, 8KB excerpt returned; `server.py` FastMCP skeleton taking `--case`/`--run`, registering the `_log_event` control-plane tool (never exposed to the model).
  Acceptance: `prd.md > Audit Ledger` — server-only writer, seq+timestamp per line, written the moment events happen, intact if the process dies; `prd.md > Constrained Tooling` — malformed calls rejected with clear ledgered errors, path escapes refused.
  Verify: Run the foundation test script: a malformed tool call produces a `tool_rejected` ledger line; a read outside the case dir is refused; kill the server process mid-write and confirm `ledger.jsonl` is valid JSONL up to the kill.

- [x] **4. Loose-artifact + recording tools (8 of 13)**
  Spec ref: `spec.md > MCP Server > Tool definitions` (#1 `evidence_inventory`, #5 `evtx_query`, #6 `registry_query`, #7 `execution_evidence`, #10 `yara_scan`, #11 `read_artifact`, #12 `record_finding`, #13 `record_verdict`)
  What to build: The eight tools that work on loose artifact files — everything the smoke case needs. Pydantic-validated params per spec (narrowing params required: `limit ≤500` on evtx, plugin enums on registry, `length ≤8KB` on read_artifact); `record_finding` validates `attack_id` against `T\d{4}(\.\d{3})?` and requires `cites` to reference existing `tool_result` seq numbers; `record_verdict` enum-validated. Wire all through runner/pathguard/ledger from item 3. Use fallback binaries where the item-2 gate dictated.
  Acceptance: `prd.md > Constrained Tooling` — typed validated params, rejections ledgered, output caps with full-output-plus-hash on disk; tools accept loose files (smoke case) per spec.
  Verify: Against a scratch folder of sample artifacts, call each tool once via a test harness: confirm sensible output, a `tool_called`/`tool_result` ledger pair per call, and one deliberately malformed call per tool rejected cleanly.

- [x] **5. Smoke case + clean case construction**
  Spec ref: `spec.md > Smoke Case (cases/smoke/)` + `spec.md > Smoke Case > Clean case (cases/clean/)`
  What to build: `cases/smoke/` (a few MB, loose sanitized artifacts): small Security/System EVTX with type-3 logons + 7045 service install (EVTX-ATTACK-SAMPLES picks per the item-2 license check, else host-generated); registry hive with Run-key → `C:\Users\Public\update.exe` (exported from the Windows host); matching renamed prefetch `.pf` (execution evidence → enables the dual-source finding); benign file matching a custom EICAR-style YARA rule in `rules/`; **the decoy: `mimikatz.exe` containing 12 bytes of ASCII text** — the reproducible REFUTED flip. `cases/clean/`: a handful of benign artifacts. Document both in `docs/dataset.md` (smoke provenance section).
  Acceptance: `prd.md > Judge Experience` — smoke case is a few MB with ≥1 planted findable indicator; clean case supports the honest-empty standing test; every smoke artifact readable by the item-4 tools.
  Verify: Run `evidence_inventory` against both case folders — every artifact classified and hashed; spot-check `evtx_query` finds the 7045 event, `registry_query` run_keys finds the Run-key, `read_artifact` on the decoy returns ASCII text. **← VERIFICATION CHECKPOINT 2**

- [x] **6. Orchestrator — CLI, case validation, MCP client, terminal UI**
  Spec ref: `spec.md > Orchestrator > CLI & case validation (cli.py)` + `spec.md > Orchestrator > MCP client (mcp_client.py)` + `spec.md > Orchestrator > Terminal UI (terminal.py)`
  What to build: Typer CLI `verdict investigate <case_dir> [--budget 5.00] [--output runs/] [--model claude-sonnet-4-6]`; case validation (missing/empty folder → clear message, exit 1, nothing runs); `runs/<UTC-timestamp>/` creation (never overwrites a prior run); `mcp_client.py` spawns `verdict_mcp` over stdio, converts `list_tools()` schemas to Anthropic tool definitions (deterministic sorted serialization for cache stability), enforces phase allowlists as the double gate; `terminal.py` rich rendering — one line per tool call (timestamp, tool, args, duration, sha, cost), dimmed narration, persistent status bar (findings · elapsed · cost), verdict-flip rendering, completion summary table.
  Acceptance: `prd.md > Autonomous Investigation Run` — within ~10s of launch: case validated, evidence inventory table, stated plan; invalid folder exits nonzero immediately; re-runs get fresh folders.
  Verify: Run `verdict investigate ./cases/smoke/` (no agent loop yet — it should validate, spawn the server, print the inventory table, create the run folder) and `verdict investigate ./nonexistent/` (immediate clear error, exit 1).

- [x] **7. Agent loop, budget guard, triage — first autonomous smoke run** ⚠ learner watches (VM)
  Spec ref: `spec.md > Orchestrator > Agent loop (agent/loop.py)` + `spec.md > Orchestrator > Triage phase` + `spec.md > Orchestrator > Budget guard (budget.py)` + `spec.md > Orchestrator > Findings store (findings.py)`
  What to build: The manual agentic loop per the spec pseudocode (Sonnet 4.6, adaptive thinking, effort medium, prompt-cache breakpoints on system block + newest turn); triage system prompt per spec rules (kill-chain hypothesis order, narrate between hypotheses, recall-oriented, always narrow queries, conflicts-as-findings, honest-clean, cite ledger seqs, seek the disk↔memory dual citation); `budget.py` cost tracking from `response.usage` ($3/$15 per MTok, cache $0.30/$3.75) with sub-budgets (triage 60% / verify 30% / report 10%) and graceful degrade → `budget_event`; `findings.py` flushed to `findings.json` per mutation; API-outage handling (SDK retries → ~2min backoff → partial report, `INTERRUPTED`, exit 2). Then: **first full autonomous triage run against the smoke case on the VM.** Calibrate effort/excerpt caps here (spec Open Issue #4).
  Acceptance: `prd.md > Autonomous Investigation Run` — zero human input start to finish; narrated hypotheses; live cost ticker; budget guard demonstrably caps spend. Triage records ≥2 findings on the smoke case including the decoy (recall-oriented — verification comes next item).
  Verify: Watch `verdict investigate ./cases/smoke/` run end-to-end with zero interaction; confirm narration + one-line-per-tool-call + status bar; open `findings.json` and `ledger.jsonl` — findings cite real seq numbers; total cost on screen ≈ pennies. **← VERIFICATION CHECKPOINT 3**

- [x] **8. Verifier pass — the REFUTED flip**
  Spec ref: `spec.md > Orchestrator > Verifier phase (agent/verifier.py)` + `spec.md > Architecture Overview > Phase tool allowlists`
  What to build: Per-finding fresh-context adversarial pass: input = claim + cited ledger entries (tool, exact params, output SHA-256, stored output path); restricted toolset (tools 2–11 + `record_verdict`; no `record_finding`, no `evidence_inventory`); verifier re-runs cited queries and must independently re-derive the claim; verdicts `VERIFIED`/`UNCONFIRMED`/`REFUTED` flip live on the terminal with one-line reasons; SHA drift between re-run and cited output flagged explicitly (spec Open Issue #5). Refuted findings retained for the report appendix.
  Acceptance: `prd.md > Self-Verification` — every finding gets a verdict; smoke decoy (`mimikatz.exe` = ASCII text) reliably flips to `REFUTED` with the reason printed; refuted findings excluded from the headline set.
  Verify: Run the smoke case end-to-end and watch the decoy flip to `REFUTED` on the terminal — the wow moment, on demand. Re-run once to confirm reproducibility; confirm `verdict_recorded` ledger lines.

- [ ] **9. Report generator + clean-case honest-empty test**
  Spec ref: `spec.md > Orchestrator > Report generator (report/)` + `spec.md > Smoke Case > Clean case (cases/clean/)`
  What to build: Jinja2 → one self-contained `report.html` (inline CSS, no JS, anchors only) with all eight spec sections: header · 5–8 sentence executive summary · chronological attack narrative footnoted to findings · severity-coded findings table (`VERIFIED`+`UNCONFIRMED` only) · per-finding detail with artifact excerpts and clickable anchors into the embedded ledger rendering · Appendix A refuted-with-refutations · Appendix B/C evidence inventory + full tool-call index · Appendix D methodology/constraints. Summary+narrative prose = one Sonnet call over verified findings (report sub-budget). PDF attempt chain: `chromium --headless --print-to-pdf` → `wkhtmltopdf` → manual fallback noted. Then run `cases/clean/` end-to-end.
  Acceptance: `prd.md > Investigation Report` — citations click through to ledger entries offline; refuted-to-appendix policy holds; `prd.md > Failure & Empty-Case Behavior` — clean case yields a valid, complete, zero-findings report.
  Verify: Open `report.html` from the smoke run in a browser with networking irrelevant — click a citation and land on the ledger entry; confirm `report.pdf` exists; run the clean case and read an honest empty report with zero invented findings.

- [ ] **10. Image-backed tools (5 of 13)**
  Spec ref: `spec.md > MCP Server > Tool definitions` (#2 `fs_list`, #3 `fs_extract`, #4 `mft_query`, #8 `timeline_query`, #9 `mem_analyze`)
  What to build: The five tools that operate on disk images and memory captures: `fs_list`/`fs_extract` via Sleuth Kit `fls`/`icat` (E01 via libewf, no mounting); `mft_query` via MFTECmd or `fls -m` fallback per the item-2 gate; `timeline_query` via `fls -m` → `mactime` with required time window, bodyfile built once per image and cached in `bodyfile/`; `mem_analyze` with the server-enforced Vol3 plugin allowlist (pslist, pstree, psscan, netscan, malfind, cmdline, dlllist, handles). All through runner/pathguard/ledger.
  Acceptance: `prd.md > Constrained Tooling` — full kill-chain tool coverage now complete (all 13 model-visible tools); narrowing params required on every large-data tool; arbitrary Vol3 plugin names rejected.
  Verify: On the VM against the Szechuan images: `fs_list` the desktop image root, `fs_extract` one known file, `timeline_query` a one-day window, `mem_analyze pslist` the desktop capture — each returns sensible output with ledger pairs; one out-of-allowlist plugin call is rejected.

- [ ] **11. Full Szechuan Sauce run + accuracy report** ⚠ learner at the VM; scarce-budget item
  Spec ref: `spec.md > Primary Dataset` + `prd.md > Judge Experience` (accuracy story)
  What to build: First full autonomous run: `verdict investigate /cases/szechuan/` on the VM — target ~30min wall-clock, ≤$5 (budget guard live). Capture the terminal transcript (this take is demo-video raw material — record it). Then score: `docs/accuracy-report.md` tables every `docs/ground-truth.md` fact as found / partially found / missed; counts and lists extra findings not in ground truth; states misses honestly. If results are weak, one calibration pass (prompts/effort) + at most one re-run — budget allows 2–3 total.
  Acceptance: `prd.md > Autonomous Investigation Run` — full run, zero input, exit 0, report + ledger produced; `prd.md > Investigation Report` — ≥1 `VERIFIED` finding citing **both** memory and disk evidence; `prd.md > Judge Experience` — accuracy is a number with named misses.
  Verify: Run completes ≤$5 with exit 0; open `report.html` and find the dual-cited finding; read `accuracy-report.md` — every ground-truth fact has a row and a verdict. **← VERIFICATION CHECKPOINT 4**

- [ ] **12. Submission docs — diagram, dataset docs, README, story**
  Spec ref: `spec.md > Architecture Overview` (the boundary drawing) + `spec.md > File Structure` (docs/ entries) + `prd.md > Submission Package`
  What to build: `docs/architecture.md` — the security-boundary diagram exactly as the spec draws it (model's only actuators = typed tools; no shell/file-write tool *exists*; server-side path guard; single-writer ledger) plus the "ask it to delete a file, watch the architecture refuse" demonstration note; `docs/dataset.md` completed — Szechuan provenance, download+verify steps, smoke-case provenance; README finished — try-it-out leading with the 3-minute smoke case, full Szechuan walkthrough second, requirements, exit codes; Devpost story draft — GTG-1002 defender-mirror narrative from scope.md + PRD problem statement; screenshot set captured per the submission plan (launch/inventory · triage+ticker · REFUTED flip · summary table · citation click-through · diagram). Commit a real `ledger.jsonl` + transcript from item 11 as the execution-logs component. Push everything.
  Acceptance: `prd.md > Submission Package` — components 1 (repo+README), 3 (diagram), 5 (dataset docs), 6 (accuracy report, from item 11), 7 (try-it-out), 8 (execution logs) done; story text ready to paste.
  Verify: Cold-read the README top to bottom and confirm a stranger could run the smoke case from it alone; confirm the diagram shows what the agent physically cannot do; `git push` and view all docs rendered on GitHub.

- [ ] **13. Demo video + submit to Devpost**
  Spec ref: `prd.md > Submission Package` + `prd.md > What We're Building` (the core submission story)
  What to build: Record the ≤5-minute demo anchored by one real run — must show: the one-command launch, the narrated triage with live cost ticker, **the REFUTED flip**, and the final report with a citation click-through (use the item-11 recording or one fresh smoke take; the decoy re-fires for pennies). Upload to YouTube (unlisted is fine). Then the Devpost form at findevil.devpost.com: project name **VERDICT**, tagline (*every finding cited, every action audited, zero hallucinated evil*), paste the story, built-with tags (Python, Anthropic Claude, MCP, SIFT Workstation, Volatility, Sleuth Kit, YARA), screenshot gallery, video link, public repo link, docs/ artifacts (scope, PRD, spec, checklist) in the repo. Cross-check all 8 required components one final time — missing any one is elimination. Submit with margin before the June 15 deadline.
  Acceptance: Submission live on Devpost with all required fields and all 8 components present; video ≤5min and shows the four required beats.
  Verify: Open the Devpost submission page and confirm the "Submitted" badge; watch the video once end-to-end; run the 8-component checklist against the live page — every component locatable by a judge in under a minute.
