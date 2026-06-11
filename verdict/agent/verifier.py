"""Verifier phase - fresh-context per-finding adversarial pass.

Spec ref: spec.md > Orchestrator > Verifier phase (agent/verifier.py).
Filled in by checklist item 8.

For each recorded finding, a FRESH conversation (no triage history): adversarial
system prompt ("your job is to break this claim"), restricted toolset (tools
2-11 + record_verdict), input = the claim + cited ledger entries (tool names +
exact params + output SHA-256 + stored output path). The verifier re-runs the
cited queries itself and must independently re-derive the claim.

Verdicts: VERIFIED / UNCONFIRMED / REFUTED. SHA drift between a re-run and the
cited output is flagged explicitly (spec Open Issue #5), never silently passed.
"""

from __future__ import annotations


async def verify_finding(client, mcp_client, *, model: str, finding: dict,
                         cited_ledger_entries: list[dict], budget_guard,
                         findings_store, terminal_ui) -> str:
    """Adversarially verify one finding; returns the verdict. TODO(item 8)."""
    raise NotImplementedError("Implemented in checklist item 8.")
