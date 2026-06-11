"""Triage phase - kill-chain hypothesis-driven investigation.

Spec ref: spec.md > Orchestrator > Triage phase (agent/triage.py).
Filled in by checklist item 7.

Hypothesis-driven loop across the kill chain (initial access -> persistence ->
lateral movement -> C2), MITRE ATT&CK-guided. Recall-oriented: record findings
as hypotheses with citations - the verifier reproduces them. Always narrow
queries; conflicting evidence is itself a finding; clean evidence -> say so.
"""

from __future__ import annotations


async def run_triage(client, mcp_client, *, model: str, budget_guard,
                     findings_store, terminal_ui) -> None:
    """Run the triage conversation until done or budget-capped. TODO(item 7)."""
    raise NotImplementedError("Implemented in checklist item 7.")
