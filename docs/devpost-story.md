# VERDICT — Devpost project description

Paste-ready narrative for [findevil.devpost.com](https://findevil.devpost.com/).

**Project name:** VERDICT  
**Tagline:** Every finding cited, every action audited, zero hallucinated evil.

---

## What it does

An IR analyst handed a disk image and memory capture faces hours of manual triage before
anyone can act — and most new "AI DFIR" agents can't be trusted, because nothing stops
them from hallucinating findings or running destructive commands against evidence.

VERDICT is one command on a SIFT Workstation:

```bash
verdict investigate <case-folder>
```

Walk away. The agent autonomously surveys evidence, triages with 13 typed read-only MCP
tools, runs an **adversarial verify pass** on every finding (re-runs cited queries, flags
SHA drift), and emits a cited HTML/PDF report plus an append-only `ledger.jsonl` the agent
cannot edit. Confidence states: **VERIFIED** / **UNCONFIRMED** / **REFUTED**.

**Autonomous execution qualities we target:**

- **Full autonomy (tiebreaker):** zero human input from launch to report; live cost ticker
  and $5/run budget guard.
- **Self-correction:** verifier flips overclaims to REFUTED on screen (demo centerpiece).
- **Depth:** one Windows intrusion kill chain (initial access → persistence → lateral → C2),
  MITRE-mapped, not shallow artifact bingo.
- **Auditability:** every finding links to ledger sequence numbers and output SHA-256 hashes.

**Inspiration:** Anthropic's **GTG-1002** disclosure showed attackers running Claude Code +
MCP at high autonomy. VERDICT is the **defender-side mirror** — same MCP-shaped boundary,
pointed at finding evil instead of doing it.

---

## How we built it

**Pattern:** manual Anthropic agent loop + custom MCP server (we deliberately avoided the
Claude Agent SDK, which ships bash/file tools that must be *disabled* by configuration).

**Orchestrator (`verdict/`):** Typer CLI → evidence survey → triage loop (Sonnet 4.6,
prompt caching, phase tool allowlists) → per-finding verifier (fresh context, restricted
tools) → Jinja2 report (HTML + PDF).

**MCP server (`verdict_mcp/`):** Pydantic validation → path guard → fixed-binary runner
(`shell=False`, timeouts, 8 KB excerpts + full hashed outputs on disk) → server-only
ledger. Forensic backends: Sleuth Kit, Volatility 3, YARA, EvtxECmd / EZ Tools fallbacks.

**Design tradeoffs:**

| Choice | Why |
|--------|-----|
| Manual loop vs Agent SDK | Harmful tools **absent** from API requests, not permission-blocked |
| Sonnet 4.6 for triage + verify | Fits ~$5/run cap; verifier independence is structural (fresh context), not a second model |
| Bodyfile/mactime vs Plaso supertimeline | Hours on 30 GB images breaks the ~30-minute target |
| Smoke case before 30 GB images | Cheap dev loop; caught four primary-vs-stub parser bugs before Szechuan |
| Verifier required | Triage optimizes recall; precision comes from reproduction, not prompt pleading |

Architecture diagram: [`docs/architecture.md`](https://github.com/prabhakaran-jm/verdict/blob/main/docs/architecture.md)

---

## Challenges

**1. Real binaries ≠ stub tests.** EvtxECmd writes UTF-8 BOM and nested JSON payloads;
`binaries.resolve()` once leaked probe argv into real calls; SHA replay drift hashed
run-stamped console logs instead of deterministic records. Each surfaced only on real
smoke runs — strong argument for pennies-before-terabytes sequencing.

**2. DC01 disk image partition layout.** The 11 GB DC E01 did not yield a walkable C:
at naive offsets. Early runs burned triage budget on empty `fs_list` results until we added
**`mmls` auto-discovery** and multi-host triage prompts. Desktop disk + memory + extracted
EVTX remained the reliable path when DC C: stayed partial.

**3. Volatility 3 on Server 2012 R2 DC memory.** Symbol packs, long runtimes, and a system
`vol` without symbols vs venv `volatility3` — Day-1 gate documents the pivot: desktop
memory is the blocker test; DC memory is best-effort.

**4. Making REFUTED reproducible.** Smart triage sometimes *reads* the smoke decoy during
triage and hedges accurately ("filename only") — verifier then confirms instead of refutes.
We tuned for recall on scary names and let verify knock down credential-dumping *capability*
claims so the wow moment stays deterministic.

**5. $5/run vs depth.** Full Szechuan runs take ~30–60 minutes and ~$3–4 API spend. Image
tools, verifier passes per finding, and prompt caching all compete for the same budget guard.

---

## What we learned

- **Architectural guardrails are judgeable.** "Ask it to delete evidence" fails because no
  delete tool exists and `PathGuard` blocks writes under the case folder — refusals land in
  `ledger.jsonl` as `tool_rejected`.
- **Verification changes the product story.** Triage recall + verifier precision beats a
  single pass tuned for scary output; REFUTED findings belong in the appendix, not silent drops.
- **Honest accuracy beats inflated scores.** We score 24 published facts in
  [`docs/ground-truth.md`](https://github.com/prabhakaran-jm/verdict/blob/main/docs/ground-truth.md)
  and name every miss in [`docs/accuracy-report.md`](https://github.com/prabhakaran-jm/verdict/blob/main/docs/accuracy-report.md).
- **MCP is the right shape for DFIR** when the server owns paths, binaries, and the audit log —
  the model gets hypotheses and excerpts, not the keys to the evidence room.

---

## Evidence integrity (architectural, not prompt-based)

Prompts ask the agent to cite sources; **prompts do not protect evidence.**

VERDICT enforces integrity on the MCP server:

- **Evidence directory is read-only** — all writes go to `runs/<id>/` only (`pathguard.py`).
- **No shell, delete, or arbitrary-write tools** in the 13-tool surface — absent from the API,
  not disabled in config.
- **Ledger is server-written** — append-only JSONL with fsync; the model has no tool that
  appends or edits audit lines.
- **Tool outputs are hashed** — full output on disk, SHA-256 in the ledger; verifier re-runs
  and flags SHA drift between citation and replay.

If the model ignores a prompt, it might overstate a finding in prose — it **cannot** modify
original E01, EVTX, or memory captures. Spoliation is prevented by **missing capability**,
not by hoping the model behaves. We document refusals and verifier demotions as signal in
the accuracy report rather than hiding failure modes.

---

## What's next

With more time after the hackathon:

- **Deep pcap parsing** — inventory notes the capture today; Zeek/Wireshark-style IOC
  extraction would close GT-12 URL/host gaps without manual analyst work.
- **Resume interrupted runs** — re-run from fresh folder works; checkpoint/resume would
  save budget on API outages mid-Szechuan.
- **Stronger DC disk access** — partition-aware bodyfile cache per host; NTDS/Share artifacts
  when C: is reachable at the correct offset.
- **Cross-run IOC memory** — interesting for SOC workflows, out of scope for a one-case MVP.
- **Opus verifier option** — quality ceiling vs $5 cap tradeoff as models cheapen.

---

## Try it yourself

**~3 minutes, pennies (judges who won't download 30 GB):**

```bash
git clone https://github.com/prabhakaran-jm/verdict.git
cd verdict && python3 -m venv .venv && source .venv/bin/activate
pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...
verdict investigate ./cases/smoke/
```

Open `runs/<timestamp>/report.html` — click a citation → ledger entry. Watch verify flip
the `mimikatz.exe` decoy to **REFUTED**.

**Full accuracy path (~30–60 min, ≤$5):**

```bash
./scripts/get-dataset.sh
pip install volatility3
verdict investigate /cases/szechuan/ --budget 5.00
```

Dataset docs: [`docs/dataset.md`](https://github.com/prabhakaran-jm/verdict/blob/main/docs/dataset.md)  
Execution logs: [`docs/execution-logs/`](https://github.com/prabhakaran-jm/verdict/blob/main/docs/execution-logs/)

---

## Built with

Python · Anthropic Claude (Sonnet 4.6) · MCP · SIFT Workstation · Volatility 3 ·
Sleuth Kit · YARA · Rich · Jinja2 · Typer

## Links

- **Repository:** https://github.com/prabhakaran-jm/verdict
- **Primary dataset:** https://dfirmadness.com/the-stolen-szechuan-sauce/
- **Hackathon:** https://findevil.devpost.com/
