"""Findings store - in-memory list flushed to runs/<id>/findings.json.

Spec ref: spec.md > Orchestrator > Findings store (findings.py).
Filled in by checklist item 7.

Fields per finding: id, claim, severity (critical/high/medium/low), attack_id
(MITRE ATT&CK technique, e.g. T1543.003), cites (ledger seq numbers), verdict
(VERIFIED/UNCONFIRMED/REFUTED/None), verdict_reason. The ledger remains the
authoritative audit trail; this file is convenience run-state.
"""

from __future__ import annotations


class FindingsStore:
    """Flushes to findings.json after every mutation. TODO(item 7)."""

    def __init__(self, run_dir: str) -> None:
        self.run_dir = run_dir
        self.findings: list[dict] = []

    def record(self, claim: str, severity: str, attack_id: str, cites: list[int]) -> str:
        """Append a finding and flush; returns the finding id."""
        raise NotImplementedError("Implemented in checklist item 7.")

    def set_verdict(self, finding_id: str, verdict: str, reason: str) -> None:
        """Attach a verifier verdict and flush."""
        raise NotImplementedError("Implemented in checklist item 8.")
