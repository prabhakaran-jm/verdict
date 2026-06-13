# VERDICT

**Every finding cited, every action audited, zero hallucinated evil.**

One command on a SIFT Workstation — `verdict investigate <case-folder>` — runs a fully
autonomous DFIR investigation through a custom typed read-only MCP server, adversarially
verifies every finding, and emits a cited HTML/PDF report plus a server-written
append-only audit ledger. Safety is architectural: the model's tool list contains only
typed forensic tools; **no shell tool exists to disable**.

Built for the [FIND EVIL!](https://findevil.devpost.com/) DFIR hackathon. Apache-2.0.

## Try it (smoke case — ~3 minutes, pennies)

The bundled smoke case is a few MB of sanitized Windows artifacts. It exercises the
full pipeline — survey, triage, verify, report — including the demo centerpiece:
a **`REFUTED`** flip when the verifier catches an overclaim on the `mimikatz.exe` decoy
(12 bytes of ASCII text, not malware).

### 1. Set up on the SIFT VM

```bash
git clone https://github.com/prabhakaran-jm/verdict.git
cd verdict
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

export ANTHROPIC_API_KEY=sk-ant-...   # required — VERDICT calls Claude autonomously
```

Optional sanity check (forensic binaries on PATH):

```bash
python -m verdict_mcp.binaries --check
```

### 2. Run the smoke investigation

From the repo root:

```bash
verdict investigate ./cases/smoke/
```

Within ~10 seconds you should see: case validated, an evidence inventory table, and a
stated investigation plan. The run narrates each tool call, shows a live cost ticker,
runs triage then verify, and finishes with a findings summary.

Typical cost: **~$0.30–0.50** · Wall time: **~3–4 minutes**.

### 3. Open the report

Each run writes to a fresh timestamped folder (prior runs are never overwritten):

```bash
ls runs/
# e.g. runs/20260613T092457Z/report.html
```

Open `report.html` in a browser. Click a citation link — it jumps to the matching
`ledger.jsonl` entry (tool name, args, output SHA-256). Confirm `report.pdf` exists
alongside.

### 4. What to look for

| Beat | Where |
|------|--------|
| Service install (`VerdictSmokeSvc` → `update.exe`) | VERIFIED finding + System.evtx / 7045 |
| Run-key persistence | Registry finding on `NTUSER.DAT` |
| YARA hit on invoice marker | `yara_scan` + `rules/smoke.yar` |
| **`REFUTED` decoy** | Finding on `mimikatz.exe` flipped in verify — plain text, not credential dumping |

### 5. Clean-case control (optional)

```bash
verdict investigate ./cases/clean/
```

Expect an honest empty report — **zero invented findings** (`prd.md > Failure & Empty-Case Behavior`).

---

## Full Szechuan Sauce walkthrough

The primary dataset is **~25–30 GB extracted** — not in git. Download once on the VM,
then run the full autonomous investigation used for the accuracy report.

### Download and verify

```bash
sudo mkdir -p /cases/szechuan && sudo chown "$USER" /cases/szechuan
./scripts/get-dataset.sh              # ~13.5 GB download, MD5-verified, auto-extract
pip install volatility3               # if not already in venv — required for mem_analyze
./scripts/day1-gate.sh /cases/szechuan   # optional: binaries + dataset + Vol3 gate
```

See **`docs/dataset.md`** for provenance, MD5 table, and known constraints.

### Full run

```bash
source .venv/bin/activate
export ANTHROPIC_API_KEY=sk-ant-...
verdict investigate /cases/szechuan/ --budget 5.00 2>&1 | tee szechuan-transcript.txt
```

| Parameter | Typical value |
|-----------|----------------|
| Wall time | ~30–60 min (target ~30) |
| API cost | ≤ **$5.00** (hard budget guard) |
| Exit code | `0` on success |

Outputs under `runs/<UTC-timestamp>/`:

- `report.html` / `report.pdf` — verified findings with ATT&CK mapping and ledger citations
- `findings.json` — structured findings + verdicts
- `ledger.jsonl` — append-only audit trail (submission execution log)
- `artifacts/` — files extracted from disk images during the run

Accuracy vs published ground truth: **`docs/accuracy-report.md`** — 39.6% recall at 100% precision (zero hallucinated findings), every miss named.

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **Platform** | [SIFT Workstation](https://www.sans.org/tools/sift-workstation/) VM (Ubuntu-based); dev on Windows host, **run on SIFT** |
| **Python** | 3.11+ |
| **API key** | `ANTHROPIC_API_KEY` — Claude Sonnet 4.6 for triage + verify |
| **Disk** | ~60 GB free for Szechuan download + extraction; smoke case is a few MB |
| **Forensic stack** | Sleuth Kit, Volatility 3, YARA, EZ Tools — preinstalled on SIFT; see `python -m verdict_mcp.binaries --check` |
| **Optional** | .NET runtime for EZ Tools fallbacks; `pip install volatility3` in the project venv for reliable `mem_analyze` |

Install VERDICT:

```bash
pip install -e .
```

---

## Architecture

Two processes: **orchestrator** (`verdict/`) + **read-only MCP server** (`verdict_mcp/`),
connected only by stdio. The model sees 13 typed tools; the server enforces path guard,
fixed binaries, output caps, and the single-writer ledger.

Full diagram and security boundary: **[`docs/architecture.md`](docs/architecture.md)**

Quick summary: there is no bash tool, no evidence write path, and no model-facing ledger
tool — safety is structural, not prompt-based.

---

## Exit codes

| Code | Meaning |
|------|---------|
| **0** | Success — investigation completed, report + ledger written |
| **1** | Invalid or empty case folder — nothing runs (no run folder created) |
| **2** | Interrupted — API outage or Ctrl+C; partial trail in the run folder |
| **3** | Internal error — misconfiguration or unexpected failure |

Missing `ANTHROPIC_API_KEY` fails fast with a plain message (exit **3**) before any
run folder is created.

---

## Project docs

| Doc | Purpose |
|-----|---------|
| [`docs/scope.md`](docs/scope.md) | Hackathon scope and differentiation |
| [`docs/prd.md`](docs/prd.md) | Product requirements |
| [`docs/spec.md`](docs/spec.md) | Technical specification |
| [`docs/dataset.md`](docs/dataset.md) | Smoke + Szechuan dataset provenance |
| [`docs/ground-truth.md`](docs/ground-truth.md) | 24 scorable facts for accuracy |
| [`docs/accuracy-report.md`](docs/accuracy-report.md) | Self-assessment vs ground truth — 39.6% recall, 100% precision, named misses |
| [`docs/execution-logs/`](docs/execution-logs/) | Submission ledgers + transcripts (both Szechuan runs + smoke) |
| [`docs/devpost-story.md`](docs/devpost-story.md) | Submission narrative (paste into Devpost) |

## License

Apache-2.0. See [`LICENSE`](LICENSE).
