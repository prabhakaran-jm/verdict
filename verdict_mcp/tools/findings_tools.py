"""Tools 12-13: record_finding (triage only), record_verdict (verify only).

Spec ref: spec.md > MCP Server > Tool definitions > #12 record_finding,
#13 record_verdict. Filled in by checklist item 4.

record_finding: claim (plain English), severity (enum), attack_id (validated
against T\\d{4}(\\.\\d{3})?), cites (ledger seq numbers, >=1 required, must
reference existing tool_result entries). Writes to findings store + ledger.

record_verdict: finding_id, verdict (enum VERIFIED/UNCONFIRMED/REFUTED),
reason (one line). Ledgered; flips the terminal line.
"""

from __future__ import annotations

import re

SEVERITIES = ("critical", "high", "medium", "low")
VERDICTS = ("VERIFIED", "UNCONFIRMED", "REFUTED")
ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def record_finding(claim: str, severity: str, attack_id: str, cites: list[int]) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")


def record_verdict(finding_id: str, verdict: str, reason: str) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
