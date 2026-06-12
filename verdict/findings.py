"""Findings store - in-memory list flushed to runs/<id>/findings.json.

Spec ref: spec.md > Orchestrator > Findings store (findings.py).
Built by checklist item 7.

Fields per finding: id, claim, severity (critical/high/medium/low), attack_id
(MITRE ATT&CK technique, e.g. T1543.003), cites (ledger seq numbers), verdict
(VERIFIED/UNCONFIRMED/REFUTED/None), verdict_reason. The ledger remains the
authoritative audit trail; findings.json is convenience run-state.

INGESTION MODEL (decided cleanly per the checklist): record_finding is a
SERVER-SIDE MCP tool - it already writes the ledger, assigns the F-id, and
returns the finding dict. So this store does NOT mint findings; the agent loop
OBSERVES each tool result and, when it sees a record_finding result, calls
ingest() with the parsed dict. The store mirrors the server's truth into
run-state and flushes findings.json after every mutation. The loop is the single
place that watches tool results, so the store stays a passive mirror with no MCP
knowledge of its own (it never reads results back off the wire itself).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FINDINGS_FILENAME = "findings.json"

#: The finding fields findings.json carries (spec.md > Data Model > Finding).
#: id mirrors the server's finding_id; verdict/verdict_reason default empty and
#: are filled by the verifier (item 8) via set_verdict().
_FIELDS = ("id", "claim", "severity", "attack_id", "cites", "verdict",
           "verdict_reason")


class FindingsStore:
    """Mirror of the server's findings, flushed to findings.json on every
    mutation.

    Construct with the run dir; findings.json lands at its root. ingest() takes
    the dict the server's record_finding returned (already F-id'd, already
    ledgered) and mirrors it; set_verdict() (item 8) attaches a verifier verdict.
    Every mutation re-flushes the whole list, so findings.json is always
    consistent with in-memory state and survives a mid-run crash.
    """

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.path = self.run_dir / FINDINGS_FILENAME
        #: id -> finding dict, preserving record order for the report.
        self._by_id: dict[str, dict[str, Any]] = {}

    # --------------------------------------------------------------- ingest

    def ingest(self, server_finding: dict[str, Any]) -> str:
        """Mirror a server record_finding result into run-state; flush.

        `server_finding` is exactly what the record_finding tool returned:
        {"finding_id", "claim", "severity", "attack_id", "cites",
         "recorded_seq"}. We normalize finding_id -> id and seed an empty
        verdict. Returns the finding id. Idempotent on re-ingest of the same id
        (the server assigns ids monotonically per run, so this only matters if a
        result is observed twice - the mirror stays correct either way).
        """
        finding_id = str(server_finding.get("finding_id")
                         or server_finding.get("id") or "")
        if not finding_id:
            raise ValueError(
                f"record_finding result has no finding_id: {server_finding!r}")
        existing = self._by_id.get(finding_id, {})
        finding = {
            "id": finding_id,
            "claim": server_finding.get("claim", existing.get("claim", "")),
            "severity": server_finding.get("severity",
                                           existing.get("severity", "")),
            "attack_id": server_finding.get("attack_id",
                                            existing.get("attack_id", "")),
            "cites": list(server_finding.get("cites", existing.get("cites", []))),
            "verdict": existing.get("verdict"),
            "verdict_reason": existing.get("verdict_reason", ""),
        }
        self._by_id[finding_id] = finding
        self.flush()
        return finding_id

    def set_verdict(self, finding_id: str, verdict: str, reason: str) -> None:
        """Attach a verifier verdict and flush (the verifier, item 8, calls this).

        Built here in item 7 so the shared store is complete; the verifier wires
        it. Unknown finding_id is a programming error - raise loudly.
        """
        finding = self._by_id.get(finding_id)
        if finding is None:
            known = ", ".join(self._by_id) or "(none)"
            raise KeyError(
                f"set_verdict for unknown finding '{finding_id}'; known: {known}")
        finding["verdict"] = verdict
        finding["verdict_reason"] = reason
        self.flush()

    # ----------------------------------------------------------- accessors

    @property
    def findings(self) -> list[dict[str, Any]]:
        """The findings in record order (a fresh list; callers may not mutate
        in place and expect a flush)."""
        return list(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)

    def get(self, finding_id: str) -> dict[str, Any] | None:
        """The finding dict for an id, or None."""
        finding = self._by_id.get(finding_id)
        return dict(finding) if finding is not None else None

    # ------------------------------------------------------------- flush

    def flush(self) -> None:
        """Write the whole findings list to findings.json (atomic-ish replace).

        Writes to a temp sibling then replaces, so a crash mid-write never
        leaves a half-written findings.json (the ledger is the authoritative
        trail regardless). Called after every mutation.
        """
        self.run_dir.mkdir(parents=True, exist_ok=True)
        payload = [{key: finding.get(key) for key in _FIELDS}
                   for finding in self._by_id.values()]
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(self.path)
