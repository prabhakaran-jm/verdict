"""Tools 12-13: record_finding (triage only), record_verdict (verify only).

Spec ref: spec.md > MCP Server > Tool definitions > #12 record_finding,
#13 record_verdict; data flow: spec.md > Data Flow - Lifecycle of a Finding.

record_finding: claim (plain English, nonempty), severity (enum),
attack_id (^T\\d{4}(\\.\\d{3})?$), cites (>=1 ledger seq numbers, each of
which MUST reference an existing tool_result line - checked against the
Ledger's in-memory seq->event index). Assigns F-001, F-002, ...; ledgers
`finding_recorded` with all fields.

record_verdict: finding_id (must reference a previously recorded finding
in this run), verdict (enum VERIFIED/UNCONFIRMED/REFUTED), reason (one
line, nonempty). Ledgers `verdict_recorded`.

These two write their own ledger events (finding_recorded /
verdict_recorded) - no tool_called/tool_result pair, matching the spec's
event vocabulary. Phase placement (record_finding triage-only,
record_verdict verify-only) is enforced by the orchestrator from the
TRIAGE_TOOLS/VERIFY_TOOLS allowlists in tools/__init__.py.

The finding registry lives in this module's register() closure: one dict
per server process == one per run, which is exactly the lifetime the spec
gives findings state (spec.md > Data Model > State lifecycle).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from verdict_mcp.tools.common import Rejection

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

SEVERITIES = ("critical", "high", "medium", "low")
VERDICTS = ("VERIFIED", "UNCONFIRMED", "REFUTED")
ATTACK_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"
ATTACK_ID_RE = re.compile(ATTACK_ID_PATTERN)

Severity = Literal["critical", "high", "medium", "low"]
Verdict = Literal["VERIFIED", "UNCONFIRMED", "REFUTED"]


def register(app: "FastMCP", ctx: "AppContext") -> None:
    findings: dict[str, dict[str, Any]] = {}  # per-run finding registry

    @app.tool(structured_output=True)
    def record_finding(
        claim: Annotated[str, Field(
            min_length=1,
            description="The finding in plain English, one or two sentences")],
        severity: Severity,
        attack_id: Annotated[str, Field(
            pattern=ATTACK_ID_PATTERN,
            description="MITRE ATT&CK technique, e.g. T1543.003")],
        cites: Annotated[list[int], Field(
            min_length=1,
            description="Ledger seq numbers of the tool_result entries "
                        "(the cite_seq values) this claim rests on")],
    ) -> dict[str, Any]:
        """Record an investigation finding (triage phase only). Every
        finding must cite at least one tool_result ledger entry - use the
        cite_seq value returned by the tool whose output supports the
        claim. Uncited claims are worthless; the verifier will attempt to
        reproduce each finding from exactly what it cites."""
        if not claim.strip():
            raise Rejection("claim must not be blank")
        for cite in cites:
            event = ctx.ledger.event_type(cite)
            if event != "tool_result":
                what = f"a {event} event" if event else "nothing"
                raise Rejection(
                    f"cite {cite} does not reference a tool_result ledger "
                    f"entry (seq {cite} is {what}); cite the cite_seq "
                    f"values returned by evidence tools"
                )
        finding_id = f"F-{len(findings) + 1:03d}"
        seq = ctx.ledger.write(
            "finding_recorded", finding_id=finding_id, claim=claim.strip(),
            severity=severity, attack_id=attack_id, cites=list(cites),
        )
        finding = {
            "finding_id": finding_id,
            "claim": claim.strip(),
            "severity": severity,
            "attack_id": attack_id,
            "cites": list(cites),
            "recorded_seq": seq,
        }
        findings[finding_id] = finding
        return dict(finding)

    @app.tool(structured_output=True)
    def record_verdict(
        finding_id: Annotated[str, Field(
            description="The finding being judged, e.g. F-001")],
        verdict: Verdict,
        reason: Annotated[str, Field(
            min_length=1, description="One-line justification")],
    ) -> dict[str, Any]:
        """Record the verification verdict for a previously recorded
        finding (verify phase only): VERIFIED (independently reproduced),
        UNCONFIRMED (could not fully reproduce, no contradiction found),
        or REFUTED (the evidence contradicts the claim)."""
        reason_line = " ".join(reason.split())
        if not reason_line:
            raise Rejection("reason must not be blank")
        finding = findings.get(finding_id)
        if finding is None:
            known = ", ".join(sorted(findings)) or "(none recorded yet)"
            raise Rejection(
                f"unknown finding_id '{finding_id}'; recorded findings: {known}"
            )
        seq = ctx.ledger.write(
            "verdict_recorded", finding_id=finding_id, verdict=verdict,
            reason=reason_line,
        )
        finding["verdict"] = verdict
        finding["verdict_reason"] = reason_line
        return {
            "finding_id": finding_id,
            "verdict": verdict,
            "reason": reason_line,
            "claim": finding["claim"],
            "recorded_seq": seq,
        }
