"""Terminal UI - rich rendering; this IS the demo video.

Spec ref: spec.md > Orchestrator > Terminal UI (terminal.py).
Filled in by checklist item 6 (verdict-flip rendering refined in item 8).

- One line per tool call:
  [09:14:03] evtx_query log=Security ids=[4624] 1.2s sha=ab12... $0.43 total
- Agent narration between hypotheses, dimmed.
- Persistent status bar: findings count / elapsed / cumulative cost.
- Verify phase: per-finding VERIFIED/UNCONFIRMED/REFUTED flip with color + reason.
- Completion: severity-sorted findings summary table + artifact paths.
"""

from __future__ import annotations


class TerminalUI:
    """Rich live display wrapper. TODO(item 6)."""

    def tool_line(self, ts: str, tool: str, args: dict, duration_s: float,
                  sha: str, total_cost: float) -> None:
        raise NotImplementedError("Implemented in checklist item 6.")

    def narration(self, text: str) -> None:
        raise NotImplementedError("Implemented in checklist item 6.")

    def verdict_flip(self, finding_id: str, verdict: str, reason: str) -> None:
        # The on-camera REFUTED flip.
        raise NotImplementedError("Implemented in checklist item 8.")

    def summary_table(self, findings: list[dict]) -> None:
        raise NotImplementedError("Implemented in checklist item 6.")
