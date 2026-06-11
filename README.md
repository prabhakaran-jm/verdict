# VERDICT

**Every finding cited, every action audited, zero hallucinated evil.**

One command on a SIFT Workstation — `verdict investigate <case-folder>` — runs a fully
autonomous DFIR investigation through a custom typed read-only MCP server, adversarially
verifies every finding, and emits a cited HTML/PDF report plus a server-written
append-only audit ledger. Safety is architectural: the model's tool list contains only
typed forensic tools; no shell tool exists to disable.

Built for the FIND EVIL! DFIR hackathon. Apache-2.0.

## Try it (smoke case — ~3 minutes, pennies)

*Placeholder — completed in checklist item 12. Will lead with
`verdict investigate ./cases/smoke/` and the reproducible REFUTED flip.*

## Full Szechuan Sauce walkthrough

*Placeholder — completed in checklist item 12. Dataset download via
`scripts/get-dataset.sh`, then `verdict investigate /cases/szechuan/`
(~30 min, ≤$5 budget guard).*

## Requirements

*Placeholder — completed in checklist item 12. Short version: SIFT Workstation,
Python 3.11+, `ANTHROPIC_API_KEY`, ~60 GB free disk for the full dataset.*

## Architecture

*Placeholder — completed in checklist item 12. Security-boundary diagram lives in
`docs/architecture.md`: the agent's only actuators are 13 typed read-only MCP tools;
path guard, fixed binaries, and the single-writer ledger are enforced server-side.*

## Exit codes

*Placeholder — completed in checklist item 12.
`0` success · `1` invalid/empty case folder · `2` interrupted (partial report) ·
`3` internal error.*
