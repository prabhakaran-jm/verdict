<!-- PRD for VERDICT (FIND EVIL! hackathon). Produced via 5 veto/approve checkpoints;
     learner approved all coach recommendations verbatim, 0 deepening rounds (declined by
     choice, consistent with profile). Epic headings below are stable addresses —
     /spec and /checklist reference them as `prd.md > [Epic name]`. -->

# VERDICT — Product Requirements

## Problem Statement

An IR analyst handed a disk image and memory capture faces hours-to-days of manual triage before anyone can act — and existing AI triage agents can't be trusted, because nothing stops them from hallucinating findings or quietly running destructive commands against evidence. The FIND EVIL! judges will score dozens of agents that *claim* autonomy and safety; almost all will enforce both with prompts, which is to say not at all. VERDICT exists to be the entry where the safety is physical, the autonomy is total, and every finding survives an adversarial reproduction attempt before it's allowed in the report.

**The one-sentence product:** type `verdict investigate <case-folder>` on a SIFT Workstation, walk away, and return to a cited, self-verified incident report with a tamper-proof audit trail — zero human input in between.

**The wow moment (demo + Devpost centerpiece):** the verify phase catching the agent's own error on screen — a finding flipping to `REFUTED` with the reason printed. Every competitor demos "agent finds malware"; VERDICT demos "agent catches itself being wrong." The smoke case is seeded so this moment is reproducible on demand.

## User Stories

### Autonomous Investigation Run

- As a judge running the entry, I want one command with zero interaction to produce the full investigation so that autonomous-execution quality (the tiebreaker criterion) is demonstrated, not claimed.
  - [ ] `verdict investigate /cases/szechuan/` runs start-to-finish with no prompts, confirmations, or human input of any kind
  - [ ] Within ~10 seconds of launch, the terminal shows: case folder validated, an inventory table of recognized evidence (disk images, memory captures, pcap), and a stated investigation plan
  - [ ] On completion: a severity-sorted findings summary table, paths to `report.html` and `ledger.jsonl`, exit code 0
  - [ ] A full run on the Szechuan Sauce case completes in ~30 minutes wall-clock (target, not hard cutoff) so one take can anchor the demo video
  - [ ] Pointing at a missing folder or one with zero recognizable evidence exits immediately with a clear message and nonzero exit code — no investigation starts without ground to stand on

- As an IR analyst watching the run, I want the terminal to narrate the investigation so that I can follow the agent's reasoning live (and the recording doubles as the demo video).
  - [ ] Every tool call prints exactly one line: timestamp, tool name, key arguments, duration, output hash
  - [ ] Between hypotheses, the agent narrates its reasoning in 1–2 plain-English sentences
  - [ ] A running status line shows: findings so far, elapsed time, cumulative API cost
  - [ ] The triage loop visibly works hypothesis-by-hypothesis across the kill chain: initial access → persistence → lateral movement → C2

- As the builder on a $50 total API budget, I want each run to cost ≤$5 by default so that I get 6–8 full runs plus testing without blowing the budget.
  - [ ] Cumulative API cost is tracked and displayed live during the run
  - [ ] At a configurable cost cap (default $5), the agent stops opening new hypotheses, verifies what it has, and emits a smaller-but-complete report — never a dead process at $5.01
  - [ ] A budget-guard activation is recorded in the ledger and noted in the report

### Constrained Tooling

*The architectural-guardrails criterion. The agent cannot do harm because the capability doesn't exist — not because a prompt asks nicely.*

- As a judge scoring constraint implementation, I want the agent's only access to evidence to be through typed, read-only tools so that safety is enforced by architecture, not prompts.
  - [ ] The agent has no shell access — there is no tool that accepts an arbitrary command string
  - [ ] Every tool takes typed, validated parameters; malformed calls are rejected by the server with a clear error (and the rejection is ledgered)
  - [ ] Tools can read only from the evidence folder and write only to the run's output folder; an attempted path outside either is refused by the server
  - [ ] The constraint story is documented in one diagram (security boundaries) and demonstrable on request: ask the agent to delete a file on camera, watch the architecture refuse

- As the investigating agent, I want ~12 tools that cover the full Windows kill chain so that depth of investigation is never blocked by a missing capability.
  - [ ] Tool coverage spans: evidence inventory + hashing, filesystem/MFT, Windows event logs, registry, execution evidence (prefetch/amcache), supertimeline query, memory analysis (Volatility 3), YARA scan
  - [ ] Every tool requires narrowing parameters (time window, keyword, target) where the underlying data is large — the agent queries, it never slurps
  - [ ] Tool output is capped; when output exceeds the cap, the agent receives a truncated excerpt plus a pointer, and the full output is written to the run folder with its SHA-256 in the ledger so citations stay verifiable against the complete artifact

### Self-Verification

- As a judge skeptical of AI-generated findings, I want every reported finding independently re-derived from cited raw evidence so that nothing in the headline report is hallucinated.
  - [ ] After triage, a separate adversarial pass attempts to reproduce each finding using only the evidence that finding cites
  - [ ] Each finding visibly flips on the terminal to `VERIFIED`, `UNCONFIRMED`, or `REFUTED` with a one-line reason
  - [ ] The report's main findings table contains only `VERIFIED` and `UNCONFIRMED` items — nothing the verifier refuted appears in the headline table
  - [ ] Refuted findings appear in the report appendix *with their refutations* — visible proof the self-correction fired
  - [ ] The smoke case reliably produces at least one finding that gets refuted or demoted on camera, making the wow moment reproducible on demand

### Audit Ledger

- As a judge auditing the run, I want a tamper-proof, complete record of every action so that any claim in the report can be traced to the exact tool call that produced its evidence.
  - [ ] `ledger.jsonl` contains one JSON line per event, written by the server the moment the event happens — never batched at the end
  - [ ] Event types cover: run started, tool called (with args), tool result (duration + SHA-256 of output + cost), finding recorded, verification verdict, budget event, run ended
  - [ ] Every line carries a sequence number and timestamp
  - [ ] The agent has no tool that can write to or modify the ledger — it is written by the server only
  - [ ] If the process is killed mid-run, the ledger on disk is intact up to the moment of death
  - [ ] Each run writes to its own timestamped output folder; a re-run never overwrites a previous run's trail

### Investigation Report

- As an IR analyst's manager, I want an executive summary in plain English so that I understand what happened without forensic vocabulary.
  - [ ] `report.html` opens with a 5–8 sentence executive summary: what happened, when, how bad
  - [ ] An attack narrative tells the intrusion chronologically (initial access → persistence → lateral movement → C2), each sentence footnoted to a finding

- As an IR analyst acting on the report, I want every finding cited down to raw evidence so that I can verify any claim before staking my response on it.
  - [ ] The findings table is severity-coded with: ID, title, severity, confidence (`VERIFIED`/`UNCONFIRMED`), MITRE ATT&CK technique ID, evidence count
  - [ ] Each finding's detail section gives the claim in plain English, the artifacts it rests on (file path + relevant excerpt), and the verifier's reproduction note
  - [ ] Citations are clickable and jump to the exact entries in a human-readable rendering of the ledger embedded in the HTML — works offline, no server, nothing for judges to run
  - [ ] At least one `VERIFIED` finding cites **both** memory and disk evidence (e.g., malicious process in memory ↔ its executable and prefetch on disk) — the disk↔memory correlation challenge pattern as a measurable requirement
  - [ ] The appendix contains: refuted findings with refutations, evidence inventory with SHA-256 hashes, full chronological tool-call index, and a methodology note stating the agent's constraints
  - [ ] `report.pdf` is produced from the same HTML with no separate layout work

### Failure & Empty-Case Behavior

- As the builder, I want VERDICT to report honestly on clean evidence so that the agent is never rewarded for *having* findings, only for verified ones.
  - [ ] Run against a clean evidence folder, VERDICT produces a valid, complete report stating what was examined and found clean — zero invented findings
  - [ ] This is a standing test: "feed it clean evidence, expect an honest empty report"

- As an IR analyst, I want contradictory evidence surfaced rather than resolved silently so that possible anti-forensics becomes a finding instead of a blind spot.
  - [ ] When evidence conflicts (e.g., inconsistent timestamps suggesting tampering), the agent reports the conflict as a finding citing both sources — it never silently picks a side

- As the builder, I want failures to degrade rather than destroy so that no run ends as a dead process with nothing to show.
  - [ ] A failed tool call retries once, then is logged and routed around — one broken parser never kills the run
  - [ ] If the Claude API stays down after a couple minutes of backoff, VERDICT writes a partial report from existing findings, marks the run `INTERRUPTED` in report and ledger, and exits nonzero with a plain-English message
  - [ ] Recovery from interruption is a fresh run (new output folder), not a resume

### Judge Experience

- As a judge who will not download 30GB, I want a tiny bundled case so that I can watch the full pipeline run in minutes.
  - [ ] The repo ships a smoke case: a few MB of sanitized artifacts with at least one planted, findable indicator
  - [ ] `verdict investigate ./cases/smoke/` exercises the complete pipeline — survey, triage, verify, report — in ~3 minutes for pennies
  - [ ] Try-it-out instructions lead with the smoke case; the full Szechuan Sauce walkthrough is the second path
  - [ ] The smoke case doubles as the builder's cheap test loop, protecting the $50 budget

- As a judge scoring IR accuracy, I want VERDICT's results scored against published ground truth so that accuracy is a number, not a vibe.
  - [ ] `accuracy-report.md` tables every ground-truth fact from the published Szechuan Sauce solution as found / partially found / missed
  - [ ] Findings VERDICT reported that are *not* in ground truth are counted and listed
  - [ ] Misses are stated honestly — a credible 85%-with-named-misses beats a suspicious 100%

### Submission Package

- As the entrant, I want all 8 required components shipped with margin so that nothing is eliminated on a technicality.
  - [ ] Public repo (Apache-2.0) with README
  - [ ] 5-minute demo video — anchored by one real run; must show the launch, the narrated triage, the `REFUTED` flip, and the final report
  - [ ] Architecture diagram showing security boundaries (what the agent physically cannot do)
  - [ ] Written project description (Devpost story; GTG-1002 defender-mirror narrative)
  - [ ] Dataset documentation (Szechuan Sauce provenance + download/verify steps)
  - [ ] Accuracy report (per Judge Experience above)
  - [ ] Try-it-out instructions (smoke case first)
  - [ ] Agent execution logs (a real `ledger.jsonl` + terminal transcript from the final run)

## What We're Building

The 4-day MVP, by epic — every item above with unchecked boxes is in scope:

1. **Constrained Tooling** — ~12 typed read-only tools covering the Windows kill chain, with output caps and path constraints enforced server-side
2. **Autonomous Investigation Run** — one command, zero interaction, narrated terminal, cost ticker, $5 budget guard, ~30-minute target
3. **Self-Verification** — adversarial verify pass; `VERIFIED`/`UNCONFIRMED`/`REFUTED`; refuted-to-appendix
4. **Audit Ledger** — server-written, append-only, event-complete, crash-surviving, per-run folders
5. **Investigation Report** — exec summary, attack narrative, cited findings table, clickable ledger citations, ≥1 disk↔memory dual-cited finding, HTML + PDF
6. **Failure & Empty-Case Behavior** — honest clean reports, conflicts-as-findings, retry-and-route-around, graceful `INTERRUPTED`
7. **Judge Experience** — smoke case (~3 min, pennies), accuracy report vs. ground truth
8. **Submission Package** — all 8 components, demo centered on the `REFUTED` flip

## What We'd Add With More Time

- **Deep pcap analysis** — findings may mention the pcap exists; no parsing in MVP.
- **Resume interrupted runs** — re-run instead; resume logic isn't worth the build time.
- **Additional datasets / batch mode** — one case investigated deeply beats three investigated shallowly.
- **Linux/macOS artifact support** — Windows-only by design.
- **Any UI beyond terminal + HTML report** — the report is the UI.
- **Cross-case memory of indicators** — an agent that remembers IOCs across cases; interesting, out of scope.

## Non-Goals

- **No human-in-the-loop, ever** — full autonomy is the tiebreaker criterion and the differentiator vs. competitors (e.g., Valhuntir is human-in-the-loop). No confirmation prompts, no "press Y to continue."
- **No live response / SIEM / remote endpoints** — multiplies setup risk; judges can't reproduce it.
- **No multi-agent frameworks** — one agent plus a verifier pass demonstrates "self-correcting" more cleanly than orchestration complexity.
- **No prompt-based safety claims** — if a guardrail can be removed by editing a prompt, it does not count as a guardrail anywhere in our docs or demo.
- **No breadth-chasing** — ~12 tools that cover the kill chain, not 200 wrapped CLIs; one scenario investigated completely, not every artifact type touched.
- **No fine-tuning / custom models** — Claude via API; the architecture and prompts do the work.

## Open Questions

| # | Question | Resolve by |
|---|----------|------------|
| 1 | Szechuan Sauce images: confirm download links live, verify hashes, confirm Volatility 3 handles the memory captures out of the box | **Day 1, before anything else** — this is the go/no-go on the dataset; fallback is SANS/CFReDS/Digital Corpora |
| 2 | Is the published Szechuan Sauce ground truth complete enough to score against? (Enumerate the facts list Day 1) | Day 1, alongside #1 |
| 3 | Which Claude model(s) for triage vs. verifier — cost/quality split inside the $5/run cap | /spec |
| 4 | PDF generation method (automated vs. print-to-PDF of the final HTML) | Build time — requirement is only that the PDF exists in the submission |
| 5 | Smoke case construction: which sanitized artifacts, and how to plant a reliably-refutable decoy for the wow moment | /spec sketches it; build day finalizes |
| 6 | Demo video: screen-recording tool and take structure | Day 5; not blocking |
