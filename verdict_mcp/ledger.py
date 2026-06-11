"""Ledger writer - append-only JSONL, fsync per line, server-only.

Spec ref: spec.md > MCP Server > Ledger writer (ledger.py).
Filled in by checklist item 3.

Append-only runs/<id>/ledger.jsonl, written by the server ONLY, one JSON object
per line, fsync after every line - intact up to the moment of death if the
process is killed. Event types: run_started / tool_called / tool_result /
tool_rejected / finding_recorded / verdict_recorded / api_usage / budget_event /
run_interrupted / run_ended.

Schema example:
{"seq": 43, "ts": "2026-06-12T09:14:03.221Z", "run_id": "...",
 "event": "tool_result", "tool": "evtx_query", "duration_ms": 1180,
 "output_sha256": "ab12...", "output_path": "outputs/0043_evtx_query.json",
 "truncated": true, "exit_code": 0}
"""

from __future__ import annotations


class Ledger:
    """Single writer for the audit trail. TODO(item 3)."""

    def __init__(self, run_dir: str, run_id: str) -> None:
        # TODO(item 3): open ledger.jsonl append-only; monotonic seq; UTC ts.
        raise NotImplementedError("Implemented in checklist item 3.")

    def write(self, event: str, **fields) -> int:
        """Append one event line + fsync; returns the assigned seq."""
        raise NotImplementedError("Implemented in checklist item 3.")
