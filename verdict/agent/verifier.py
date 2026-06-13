"""Verifier phase - fresh-context, per-finding adversarial self-check.

Spec ref: spec.md > Orchestrator > Verifier phase (agent/verifier.py);
Data Flow - Lifecycle of a Finding; Open Issue #5 (replay drift); Smoke Case
(the REFUTED flip). Built by checklist item 8.

For EACH finding recorded in triage, the verifier opens a FRESH conversation
(no triage history) and reuses loop.run_phase with phase "verify":

  - Input: the finding's claim + the cited ledger entries (tool name, EXACT
    params, the cited output's SHA-256, the stored output path). These are
    reconstructed from the run's ledger.jsonl by matching the finding's `cites`
    seqs to their tool_result lines and the tool_called line each one paired
    with (build_cited_entries).
  - Restricted toolset: the "verify" allowlist (tools 2-11 + record_verdict;
    NO record_finding, NO evidence_inventory) - enforced by the MCP client's
    phase gate. The verifier RE-RUNS the cited queries itself and independently
    re-derives the claim, then calls record_verdict.
  - SHA replay-drift (Open Issue #5): the cited tool_result carries a SHA-256.
    When the verifier re-runs that cited query the loop produces a FRESH
    tool_result with its own SHA. The on_tool_result observer compares the
    fresh SHA against the cited SHA for the same tool; a mismatch is surfaced as
    a drift note (the evidence is static, so a faithful re-run must match - a
    mismatch means possible nondeterministic output and must never pass
    silently). The drift note is annotated onto the recorded verdict reason when
    the model did not already mention drift, and narrated live.
  - record_verdict routing: record_verdict is a verify-only server tool that
    ledgers verdict_recorded and returns the verdict. The loop's on_tool_result
    observer routes a successful record_verdict into findings_store.set_verdict
    + terminal_ui.verdict_flip (mirroring how triage routed record_finding into
    the store) so the flip shows live.
  - verify sub-budget: the verifier runs under budget_guard.verify_cap() (the
    cumulative 90% ceiling). Before opening each finding's verification it
    checks the cap; once hit, the remaining findings are marked UNCONFIRMED with
    a budget reason and the pass ends gracefully - never a blank verdict, never
    a crash.

Verify contexts are small (one finding each) so this phase is cheap; findings
are verified sequentially.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verdict.agent.loop import LoopConfig, LoopInterrupted, run_phase
from verdict.agent.prompts import VERIFIER_SYSTEM, verifier_kickoff

LEDGER_FILENAME = "ledger.jsonl"

#: Reason recorded when a finding is left unverified because the verify
#: sub-budget was exhausted (spec.md > Budget guard: never a blank verdict).
BUDGET_UNCONFIRMED_REASON = (
    "Left UNCONFIRMED: the verification budget was exhausted before this "
    "finding could be independently reproduced (no contradiction was found)."
)


# --------------------------------------------------- ledger reconstruction


def _read_ledger(run_dir: Path) -> list[dict[str, Any]]:
    """Parse runs/<id>/ledger.jsonl into a list of event records.

    Tolerates a torn final line (a killed prior process) and blank lines, the
    same way the server's Ledger does on continuation. Missing ledger -> [].
    """
    path = run_dir / LEDGER_FILENAME
    records: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # torn line; ignore
    return records


def build_cited_entries(records: list[dict[str, Any]],
                        cites: list[int]) -> list[dict[str, Any]]:
    """Reconstruct, for each cited seq, the evidence it pins down.

    A finding's `cites` are tool_result ledger seqs (the cite_seq values the
    tools return). For each one we pull:
      - tool            (from the tool_result line)
      - output_sha256   (the cited output's hash - the replay-drift anchor)
      - output_path     (where the full output was stored)
      - params          (the EXACT parameters, from the tool_called line that
                         this tool_result paired with)
    The runner and pure_tool_call both write tool_called immediately followed by
    tool_result for one call, so the matching tool_called is the latest
    tool_called line with the same tool and a smaller seq. argv (subprocess
    tools) is carried through for the audit trail when present.

    Returns one dict per cited seq that resolved to a tool_result; cites that
    don't resolve (not a tool_result, or absent) are dropped - the kickoff tells
    the verifier when it has no reproducible evidence to lean on.
    """
    by_seq: dict[int, dict[str, Any]] = {}
    for rec in records:
        seq = rec.get("seq")
        if isinstance(seq, int):
            by_seq[seq] = rec

    # tool_called lines in seq order, for the "latest before" lookup.
    called = sorted(
        (r for r in records if r.get("event") == "tool_called"),
        key=lambda r: r.get("seq", 0),
    )

    entries: list[dict[str, Any]] = []
    for cite in cites:
        result = by_seq.get(cite)
        if not result or result.get("event") != "tool_result":
            continue
        tool = result.get("tool")
        # The tool_called this result paired with: latest tool_called of the
        # same tool whose seq is below the result seq.
        match: dict[str, Any] | None = None
        for c in called:
            c_seq = c.get("seq", 0)
            if c_seq >= cite:
                break
            if c.get("tool") == tool:
                match = c
        entry: dict[str, Any] = {
            "cite_seq": cite,
            "tool": tool,
            "params": (match or {}).get("params", {}),
            "output_sha256": result.get("output_sha256"),
            "output_path": result.get("output_path"),
        }
        argv = (match or {}).get("argv")
        if argv is not None:
            entry["argv"] = argv
        entries.append(entry)
    return entries


# --------------------------------------------------------- drift detection


def _result_sha(result_text: str) -> str | None:
    """output_sha256 from a stringified tool result, or None."""
    try:
        data = json.loads(result_text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        sha = data.get("output_sha256")
        return sha if isinstance(sha, str) else None
    return None


def _detect_drift(tool: str, fresh_sha: str | None,
                  cited_entries: list[dict[str, Any]],
                  matched_shas: set[str]) -> str | None:
    """Compare a fresh re-run's SHA against the cited SHAs for this tool.

    Replay-drift mechanism (spec.md > Open Issue #5). The verifier re-runs a
    cited query; the loop produces a fresh tool_result whose output_sha256 we
    have here, and we hold the cited output_sha256 from the ledger. The evidence
    is static, so for a re-run of the same tool the fresh SHA should EQUAL one of
    that tool's cited SHAs. We report drift when the fresh result is for a tool
    that was cited but its SHA matches NONE of that tool's cited SHAs. A fresh
    SHA that matches a cited one is recorded (matched_shas) so a later identical
    re-run is not mistaken for drift. Tools with no SHA (record_verdict) and
    re-runs of tools that were not cited are ignored.

    Returns a one-line drift note to surface, or None when there is no drift.
    """
    if fresh_sha is None:
        return None
    cited_for_tool = [e.get("output_sha256") for e in cited_entries
                      if e.get("tool") == tool and e.get("output_sha256")]
    if not cited_for_tool:
        return None  # this tool was not part of the citation; nothing to drift
    if fresh_sha in cited_for_tool:
        matched_shas.add(fresh_sha)
        return None
    cited_display = ", ".join(f"{s[:12]}..." for s in cited_for_tool)
    return (
        f"REPLAY DRIFT on re-running `{tool}`: fresh output SHA-256 "
        f"{fresh_sha[:12]}... does not match the cited SHA(s) {cited_display} - "
        f"the cited evidence is not reproducible (possible nondeterministic "
        f"tool output); the citation could not be confirmed byte-for-byte."
    )


# --------------------------------------------------------- the verify pass


async def run_verifier(
    anthropic: Any,
    mcp_client: Any,
    *,
    run_dir: str | Path,
    budget_guard: Any,
    findings_store: Any,
    terminal_ui: Any,
    config: LoopConfig | None = None,
) -> None:
    """Adversarially verify every finding in the store, sequentially.

    Args:
      anthropic:      AsyncAnthropic (or a fake exposing .messages.create).
      mcp_client:     the MCPClient (phase-gated tool access + log_event).
      run_dir:        the run folder - ledger.jsonl is read to reconstruct each
                      finding's cited evidence.
      budget_guard:   a BudgetGuard; its verify_cap() (cumulative 90%) bounds the
                      pass. Findings not reached before the cap are marked
                      UNCONFIRMED (budget), never left blank.
      findings_store: the FindingsStore; set_verdict() lands each verdict.
      terminal_ui:    a TerminalUI; verdict_flip() shows each flip live.
      config:         optional LoopConfig (model/effort); defaults applied.

    Mutates findings_store (every finding ends with a verdict) and the terminal.
    Never raises on a per-finding failure - a finding whose verification cannot
    run cleanly degrades to UNCONFIRMED rather than crashing the pass.
    """
    run_dir = Path(run_dir).resolve()
    records = _read_ledger(run_dir)

    findings = findings_store.findings
    if not findings:
        terminal_ui.narration(
            "Verification: no findings were recorded - nothing to verify.")
        return

    mcp_client.set_phase("verify")
    tools = mcp_client.list_anthropic_tools("verify")

    terminal_ui.narration(
        f"Starting adversarial verification of {len(findings)} finding(s): a "
        f"fresh, restricted-tool re-check of each claim against exactly the "
        f"evidence it cited.")

    for finding in findings:
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        if not finding_id:
            continue

        # --- verify sub-budget gate: never open a verification past the cap.
        if budget_guard.total_cost >= budget_guard.verify_cap():
            _mark_budget_unconfirmed(
                budget_guard, findings_store, terminal_ui, finding_id)
            continue

        cited_entries = build_cited_entries(records, _int_cites(finding))

        await _verify_one(
            anthropic, mcp_client, tools=tools, config=config,
            budget_guard=budget_guard, findings_store=findings_store,
            terminal_ui=terminal_ui, finding=finding, finding_id=finding_id,
            cited_entries=cited_entries)


def _int_cites(finding: dict[str, Any]) -> list[int]:
    """The finding's cites coerced to ints (tolerating str/int mix)."""
    out: list[int] = []
    for c in finding.get("cites", []) or []:
        try:
            out.append(int(c))
        except (TypeError, ValueError):
            continue
    return out


async def _verify_one(
    anthropic: Any, mcp_client: Any, *, tools: list[dict],
    config: LoopConfig | None, budget_guard: Any, findings_store: Any,
    terminal_ui: Any, finding: dict[str, Any], finding_id: str,
    cited_entries: list[dict[str, Any]],
) -> None:
    """Run ONE finding's fresh-context verification and route its verdict.

    A fresh `messages` (no triage history). The on_tool_result observer (a)
    detects replay drift on every re-run and accumulates drift notes for this
    finding, and (b) routes a successful record_verdict into set_verdict +
    verdict_flip, annotating the reason with any drift note the model did not
    itself surface. If the model ends its turn WITHOUT recording a verdict (or a
    per-finding error), the finding is left UNCONFIRMED with an explanatory
    reason - never blank.
    """
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": verifier_kickoff(finding, cited_entries)},
    ]

    state: dict[str, Any] = {"verdict_recorded": False, "drift_notes": []}
    matched_shas: set[str] = set()

    def observe(name: str, args: dict, result_text: str, is_error: bool) -> None:
        # (a) replay-drift detection on every successful evidence re-run.
        if not is_error and name != "record_verdict":
            note = _detect_drift(name, _result_sha(result_text),
                                 cited_entries, matched_shas)
            if note and note not in state["drift_notes"]:
                state["drift_notes"].append(note)
                terminal_ui.narration(note)
        # (b) route a successful record_verdict -> set_verdict + verdict_flip.
        if name != "record_verdict" or is_error:
            return
        try:
            payload = json.loads(result_text)
        except (ValueError, TypeError):
            return
        if not isinstance(payload, dict):
            return
        verdict = payload.get("verdict")
        reason = payload.get("reason", "")
        fid = payload.get("finding_id", finding_id)
        if not verdict:
            return
        reason = _annotate_drift(reason, verdict, state["drift_notes"])
        findings_store.set_verdict(fid, verdict, reason)
        terminal_ui.verdict_flip(fid, verdict, reason)
        state["verdict_recorded"] = True

    try:
        await run_phase(
            mcp_client,
            anthropic,
            system=VERIFIER_SYSTEM,
            tools=tools,
            messages=messages,
            budget=budget_guard,
            ui=terminal_ui,
            ledger_via_client=mcp_client,
            phase_name="verify",
            config=config,
            on_tool_result=observe,
        )
    except LoopInterrupted:
        # A sustained API outage is a RUN-level failure, not a per-finding one:
        # let it propagate so the CLI writes a partial report and exits 2
        # (spec.md > Agent loop > Resilience). Findings already verified keep
        # their verdicts; this finding stays blank until the (re)run.
        raise
    except Exception as exc:  # noqa: BLE001 - one finding never kills the pass
        if not state["verdict_recorded"]:
            reason = (
                f"Left UNCONFIRMED: verification could not be completed for this "
                f"finding ({type(exc).__name__}: {exc}); no contradiction found.")
            findings_store.set_verdict(finding_id, "UNCONFIRMED", reason)
            terminal_ui.verdict_flip(finding_id, "UNCONFIRMED", reason)
        return

    # The model ended its turn without ever recording a verdict: do not leave a
    # blank verdict. If drift was seen, that is the headline; otherwise it is an
    # honest "couldn't reproduce / couldn't break".
    if not state["verdict_recorded"]:
        if state["drift_notes"]:
            reason = "Left UNCONFIRMED: " + state["drift_notes"][0]
        else:
            reason = (
                "Left UNCONFIRMED: the verifier did not record a verdict for "
                "this finding; no contradiction was independently observed.")
        findings_store.set_verdict(finding_id, "UNCONFIRMED", reason)
        terminal_ui.verdict_flip(finding_id, "UNCONFIRMED", reason)


def _annotate_drift(reason: str, verdict: str,
                    drift_notes: list[str]) -> str:
    """Fold any replay-drift note into the recorded verdict reason.

    Surfaces drift even when the model's own reason did not mention it
    (spec.md > Open Issue #5: never pass silently). If the model already wrote
    about drift, the reason is left as-is; otherwise the first drift note is
    appended.
    """
    if not drift_notes:
        return reason
    lowered = reason.lower()
    if "drift" in lowered or "sha" in lowered or "reproduc" in lowered:
        return reason
    note = drift_notes[0]
    if reason:
        return f"{reason}  [verifier note: {note}]"
    return note


def _mark_budget_unconfirmed(budget_guard: Any, findings_store: Any,
                             terminal_ui: Any, finding_id: str) -> None:
    """Mark a finding UNCONFIRMED because the verify budget was exhausted.

    Records the budget note once on the guard (for the report generator) the
    first time it degrades a finding, then flips the finding UNCONFIRMED with a
    budget reason (spec.md > Budget guard: never a dead process / blank verdict).
    """
    note_marker = "verify_budget_exhausted"
    if not any(note_marker in n for n in budget_guard.notes):
        budget_guard.notes.append(
            f"{note_marker}: the verification budget "
            f"(${budget_guard.verify_cap():.2f} of ${budget_guard.budget_usd:.2f} "
            f"total) was reached; remaining findings were left UNCONFIRMED "
            f"rather than verified.")
    findings_store.set_verdict(finding_id, "UNCONFIRMED",
                               BUDGET_UNCONFIRMED_REASON)
    terminal_ui.verdict_flip(finding_id, "UNCONFIRMED",
                             BUDGET_UNCONFIRMED_REASON)
