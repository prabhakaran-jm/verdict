"""Triage phase - kill-chain hypothesis-driven investigation.

Spec ref: spec.md > Orchestrator > Triage phase (agent/triage.py).
Built by checklist item 7.

Hypothesis-driven loop across the kill chain (initial access -> persistence ->
lateral movement -> C2), MITRE ATT&CK-guided. Recall-oriented: record findings
as hypotheses with citations - the verifier reproduces them. Always narrow
queries; conflicting evidence is itself a finding; clean evidence -> say so.

Wiring: build the initial messages (the case inventory + the kill-chain
marching order) -> set the MCP client to the "triage" phase -> get the triage
tool list -> call loop.run_phase with TRIAGE_SYSTEM and a triage-sub-budget
between-turn stop -> ingest every record_finding result into the FindingsStore
as the loop observes it. Returns when the model ends its turn or the triage
budget soft cap trips (a graceful transition, never a mid-tool kill).
"""

from __future__ import annotations

import json
from typing import Any

from verdict.agent.loop import LoopConfig, StopInfo, run_phase
from verdict.agent.prompts import TRIAGE_SYSTEM, triage_kickoff


async def run_triage(
    anthropic: Any,
    mcp_client: Any,
    *,
    inventory_json: str,
    budget_guard: Any,
    findings_store: Any,
    terminal_ui: Any,
    config: LoopConfig | None = None,
) -> StopInfo:
    """Run the triage conversation until done or budget-capped.

    Args:
      anthropic:    AsyncAnthropic (or a fake exposing .messages.create).
      mcp_client:   the MCPClient (phase-gated tool access + log_event).
      inventory_json: the stringified evidence_inventory result from survey -
                    triage starts from the same inventory the judge just saw.
      budget_guard: a BudgetGuard; its triage soft cap drives the transition.
      findings_store: a FindingsStore; record_finding results are ingested here.
      terminal_ui:  a TerminalUI for narration / tool lines / status.
      config:       optional LoopConfig (model/effort); defaults applied.

    Returns the StopInfo from the loop ("end_turn" or "budget_cap").
    """
    mcp_client.set_phase("triage")
    tools = mcp_client.list_anthropic_tools("triage")

    messages: list[dict[str, Any]] = [
        {"role": "user", "content": triage_kickoff(inventory_json)},
    ]

    async def stop_at_triage_cap() -> bool:
        """Between-turn transition: stop opening hypotheses at the soft cap.

        Never a mid-tool kill - the loop only checks this at the top of a turn
        (the loop awaits this predicate). Emits the budget_event ledger line + a
        report note exactly once when triage first crosses its cap (spec.md >
        Budget guard).
        """
        if not budget_guard.over_triage_cap():
            return False
        if budget_guard.announce_triage_cap():
            terminal_ui.narration(
                "Budget soft cap for triage reached - stopping new hypotheses "
                "and transitioning to verification.")
            # budget_event through the control plane; best-effort (never fatal).
            await _emit_budget_event(mcp_client, budget_guard)
        return True

    def ingest_findings(name: str, args: dict, result_text: str,
                        is_error: bool) -> None:
        """Mirror a successful record_finding result into the FindingsStore.

        The loop observes every tool result; only record_finding results (the
        server already F-id'd + ledgered them) become run-state. Malformed /
        rejected results (is_error) are ignored - the model retries or routes
        around. The UI findings count is pushed after each ingest.
        """
        if name != "record_finding" or is_error:
            return
        try:
            payload = json.loads(result_text)
        except (ValueError, TypeError):
            return
        if not isinstance(payload, dict) or "finding_id" not in payload:
            return
        findings_store.ingest(payload)
        terminal_ui.update_status(findings=len(findings_store))

    terminal_ui.narration(
        "Starting triage: working the Windows kill chain from initial access "
        "through persistence, lateral movement, and command-and-control.")

    _messages, stop = await run_phase(
        mcp_client,
        anthropic,
        system=TRIAGE_SYSTEM,
        tools=tools,
        messages=messages,
        budget=budget_guard,
        ui=terminal_ui,
        ledger_via_client=mcp_client,
        phase_name="triage",
        config=config,
        stop_between_turns=stop_at_triage_cap,
        on_tool_result=ingest_findings,
    )
    return stop


async def _emit_budget_event(mcp_client: Any, budget_guard: Any) -> None:
    """Write the triage soft-cap budget_event through the control plane."""
    try:
        await mcp_client.log_event(
            "budget_event", budget_guard.budget_event_payload("triage_soft_cap"))
    except Exception:  # noqa: BLE001 - ledger convenience; never crash the run
        pass
