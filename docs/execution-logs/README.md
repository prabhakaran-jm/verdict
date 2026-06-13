# Execution logs (FIND EVIL submission #8)
| File | Run | Purpose |
|------|-----|---------|
| `ledger-szechuan-run1.jsonl` | `20260613T133425Z` | Primary full Szechuan investigation (~12 findings); score in accuracy-report.md |
| `ledger-szechuan-run2.jsonl` | `20260613T165313Z` | Second run — 2 REFUTED overclaims (F-001 DKOM, F-004 date correlation); demo video |
| `ledger-smoke-demo.jsonl` | `20260613T092457Z` | ~3 min smoke case; try-it-out / REFUTED flip |
Each line in `ledger-*.jsonl` is one JSON event: tool calls, SHA-256 outputs, findings, verdicts, budget.
Open the matching `findings-*.json` for structured F-00x IDs and verdicts.
