<!-- Scope doc for the FIND EVIL! hackathon entry. Learner fully delegated direction
     ("you decide the project which wins"); all decisions below are coach-recommended,
     learner-approved-by-delegation, and optimized against the published judging criteria. -->

# VERDICT — Autonomous DFIR Agent That Never Reports What It Can't Prove

## Idea
An autonomous incident-response agent for the SANS SIFT Workstation that investigates a compromised Windows environment end-to-end through a **custom, typed, read-only MCP server** — and runs every finding through an adversarial **verification pass** before it's allowed into the report. Tagline: *every finding cited, every action audited, zero hallucinated evil.*

## Who It's For
- **Immediate:** FIND EVIL! hackathon judges scoring six criteria — autonomous execution (tiebreaker), IR accuracy, depth, architectural constraints, audit trail, usability.
- **Real-world:** an IR analyst handed a disk image + memory capture who wants a senior-analyst-quality triage in minutes, with every claim traceable to a raw artifact — trustworthy enough to act on.

## Inspiration & References
- Hackathon: [findevil.devpost.com](https://findevil.devpost.com/) · [Official rules](https://findevil.devpost.com/rules) · [SANS launch post](https://www.sans.org/blog/sans-launches-first-hackathon-autonomous-incident-response) · [Rob Lee's registration post](https://robtlee73.substack.com/p/registration-is-open-find-evil-hackathon)
- Baseline framework: [Protocol SIFT](https://github.com/teamdfir/protocol-sift) — Claude Code config + skill files + permission blocklist wrapping Volatility 3, Plaso, Sleuth Kit, EZ Tools, YARA. **Key finding: its guardrails are permission/prompt-based, not architectural.** That's our wedge.
- Competitive field (public repos already up): [AppliedIR/sift-mcp (Valhuntir)](https://github.com/AppliedIR/sift-mcp) — 11-package platform, human-in-the-loop; [marez8505/find-evil](https://github.com/marez8505/find-evil); [iffystrayer/find-evil-agent](https://github.com/iffystrayer/find-evil-agent); [dhyabi2/findevil](https://github.com/dhyabi2/findevil). We differentiate on **full autonomy + architectural constraints + self-verification depth**, not platform breadth.
- Origin story for the narrative: Anthropic's GTG-1002 disclosure (attackers ran Claude Code + MCP at 80–90% autonomy). VERDICT is the defender-side mirror — same architecture, pointed at finding evil instead of doing it.
- Dataset (primary): **"The Case of the Stolen Szechuan Sauce"** ([dfirmadness.com](https://dfirmadness.com/the-case-of-the-stolen-szechuan-sauce/)) — public Windows intrusion case with DC + desktop disk images, memory captures, and pcap; well-documented ground truth, ideal for the accuracy report. (Verify availability Day 1; fallback: SANS/CFReDS/Digital Corpora samples.)
- Design energy: clean and functional. Terminal-first demo, generated HTML/PDF report with a severity-coded findings table and clickable citations into the audit ledger. No custom UI beyond that.

## Goals
1. **Win prize money** — every decision optimizes against the six judging criteria, explicitly.
2. Land the three criteria most entrants will fumble:
   - **Architectural constraints:** the agent physically cannot do harm — typed MCP tools only, no shell, read-only evidence enforced by the server, not the prompt.
   - **Autonomous execution (tiebreaker):** one command, zero human input, full investigation loop with self-correction.
   - **Audit trail:** server-written append-only ledger (the agent can't tamper with its own audit log), with output hashes, rendered into the report.
3. **Depth over breadth:** one Windows intrusion scenario investigated completely (initial access → persistence → lateral movement → C2, MITRE ATT&CK-mapped), not shallow coverage of every artifact type.
4. All 8 submission components ship with margin — nothing left for the last day.

## What "Done" Looks Like
One command on a SIFT Workstation:

```
verdict investigate /cases/szechuan/
```

…then walk away. The agent autonomously: surveys evidence → forms hypotheses → calls typed MCP tools (filesystem, event logs, registry, prefetch, timeline, memory, YARA) → **runs a verifier pass that must independently reproduce each finding from cited raw evidence** → demotes anything unverifiable to "unconfirmed" → emits:
1. `report.html` / `report.pdf` — verified findings with confidence levels, ATT&CK mapping, and per-finding citations linking to exact tool calls
2. `ledger.jsonl` — append-only audit trail: every tool call, args, timestamp, SHA-256 of output
3. Terminal narration suitable for the 5-min demo video

Plus the full submission package: public repo (Apache-2.0), architecture diagram with security boundaries, dataset docs, accuracy report scored against the case's published ground truth, try-it-out instructions, execution logs.

## What's Explicitly Cut
- **Live response / SIEM / remote endpoints** — a named stretch track, but it multiplies setup risk and judges can't reproduce it. Cut.
- **Multi-agent frameworks (AutoGen/CrewAI/LangGraph)** — orchestration complexity without criterion payoff; a single agent + verifier pass hits "self-correcting" cleaner. Cut.
- **Custom web UI / dashboard** — usability criterion is satisfied by docs + one-command run + polished report. Cut.
- **Network/pcap deep analysis** — stretch only if Days 1–3 run ahead; otherwise findings reference pcap existence without deep parsing. Cut from MVP.
- **Linux/macOS artifact support** — Windows-only, by design. Depth over breadth.
- **Breadth of every SIFT tool** — ~12 typed tools that cover the kill chain beat 200 wrapped CLIs.
- **Fine-tuning / custom models** — Claude via API, prompt + architecture do the work.

## Loose Implementation Notes
*(Non-binding; refined in /spec.)*
- **Stack:** Python 3.11+, MCP Python SDK for the server, Claude Agent SDK (or Claude Code headless) for the orchestrator. Runs on SIFT Workstation VM.
- **MCP server (`verdict-mcp`):** ~12 typed tools wrapping Sleuth Kit, Plaso/psort, EvtxECmd, MFTECmd, RECmd/AmcacheParser, PECmd (prefetch), Volatility 3, YARA. Pydantic-validated params, fixed binaries, `shell=False`, path allowlist (evidence RO, output dir WO), timeouts, output caps. Server writes the ledger — agent never touches it.
- **Agent loop:** triage phase (hypothesis-driven, ATT&CK-guided) → verification phase (separate prompt, restricted toolset, must re-derive each finding from cited artifacts) → report generation. Confidence states: verified / unconfirmed / refuted.
- **Two named challenge patterns hit:** "self-correcting triage agent" (core) + "disk↔memory correlation" (Szechuan Sauce has both image types — correlate where cheap).
- **5-day shape:** D1 dataset download + MCP server + 5 core tools + ledger · D2 agent loop, first autonomous run · D3 verifier pass + report generator · D4 accuracy report vs. ground truth, diagram, docs, polish · D5 demo video + Devpost submission + buffer.
- **Assumptions to validate Day 1:** SIFT VM runs on learner's hardware (Windows 11 host — VMware/VirtualBox, ≥8GB RAM to VM); Claude API key with budget for long agentic runs; Szechuan Sauce images downloadable (~25–30GB).
