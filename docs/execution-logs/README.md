# Agent Execution Logs (Submission Component #8)

Structured audit trail for a real VERDICT run. Judges must be able to trace any finding
back to the specific tool execution that produced it.

## Files in this folder

| File | Purpose | Status |
|------|---------|--------|
| **`ledger.jsonl`** | Append-only server-written log: every tool call, args, duration, output SHA-256, findings, verdicts, budget events | **Pending** — copy from final run |
| **`szechuan-transcript.txt`** | Full terminal stdout/stderr from `verdict investigate … \| tee …` | **Pending** |
| **`smoke-transcript.txt`** | Optional: short demo run for the 5-minute video | Optional |
| **`run-metadata.json`** | Run id, UTC timestamp, cost, finding counts, paths to report | **Pending** |

> After your final Szechuan run completes, copy artifacts from the VM:

```bash
# On the SIFT VM (replace RUN_ID with runs/20260613TxxxxxxZ)
RUN_ID=runs/TBD

cp "$RUN_ID/ledger.jsonl" docs/execution-logs/ledger.jsonl
cp szechuan-transcript.txt docs/execution-logs/szechuan-transcript.txt   # if you used tee

# Optional metadata helper
python3 - <<'PY'
import json, sys
from pathlib import Path
run = Path("runs/TBD")  # edit
meta = {
    "run_id": run.name,
    "ledger": "docs/execution-logs/ledger.jsonl",
    "report_html": str(run / "report.html"),
    "findings_json": str(run / "findings.json"),
    "note": "Fill cost, duration, exit code from transcript after copy",
}
Path("docs/execution-logs/run-metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
PY
```

Then commit and push. Full run folders stay under `runs/` (gitignored); this folder is
the **submission excerpt**.

## Ledger format

Each line is one JSON object. Event types include:

- `run_started` / `run_ended`
- `tool_called` / `tool_result` (with `seq`, `ts`, `tool`, `args`, `sha256`, `duration_ms`)
- `tool_rejected` (path violations, schema errors, phase violations)
- `finding_recorded` / `verdict_recorded`
- `budget_event`

Example trace (illustrative):

```
finding F-004 cites ledger seq 142 (timeline_query) and seq 158 (mem_analyze pslist)
  → open ledger.jsonl, search "seq": 142 and "seq": 158
  → match sha256 to runs/<id>/outputs/0142_timeline_query.txt etc.
```

## Which run to commit

| Use case | Recommended source |
|----------|-------------------|
| **Accuracy report (component #6)** | Final Szechuan run scored in `docs/accuracy-report.md` |
| **Demo video (component #2)** | Smoke run transcript (~3 min, shows REFUTED flip) — optional second file |
| **Minimum for submission** | At least one complete **`ledger.jsonl`** + terminal transcript with timestamps |

## Privacy

Ledger and transcripts contain case artifact paths, tool arguments, and forensic excerpts —
not secrets. Do not commit API keys; `ANTHROPIC_API_KEY` never appears in the ledger.
