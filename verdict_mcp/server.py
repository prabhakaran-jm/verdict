"""FastMCP app - 13 tool definitions + phase metadata + _log_event control plane.

Spec ref: spec.md > MCP Server > Tool definitions (server.py, tools/).
Skeleton built by checklist item 3; tools registered in items 4 and 10.

Model-visible tools (all params Pydantic-validated, narrowing params required
where the underlying data is large):
  1 evidence_inventory   (tools/inventory.py)      - item 4
  2 fs_list              (tools/fs.py)             - item 10
  3 fs_extract           (tools/fs.py)             - item 10
  4 mft_query            (tools/mft.py)            - item 10
  5 evtx_query           (tools/evtx.py)           - item 4
  6 registry_query       (tools/registry.py)       - item 4
  7 execution_evidence   (tools/execution.py)      - item 4
  8 timeline_query       (tools/timeline.py)       - item 10
  9 mem_analyze          (tools/memory.py)         - item 10
 10 yara_scan            (tools/yara_scan.py)      - item 4
 11 read_artifact        (tools/artifacts.py)      - item 4
 12 record_finding       (tools/findings_tools.py) - item 4 (triage only)
 13 record_verdict       (tools/findings_tools.py) - item 4 (verify only)

Orchestrator-only (NEVER exposed to the model): _log_event - the control-plane
channel for orchestrator events into the server-written ledger, preserving the
single-writer claim (spec.md > Key Technical Decisions #4).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from verdict_mcp.ledger import Ledger
from verdict_mcp.pathguard import PathGuard
from verdict_mcp.runner import Runner

SERVER_NAME = "verdict-mcp"

#: Orchestrator-side events that flow through _log_event. Tool-side events
#: (tool_called/tool_result/tool_rejected/finding_recorded/verdict_recorded)
#: are written by the server itself and are NOT accepted here.
ControlPlaneEvent = Literal[
    "run_started", "api_usage", "budget_event", "run_interrupted", "run_ended",
]


@dataclass
class AppContext:
    """Per-run singletons shared by every registered tool.

    Constructed once in build_app(); tool modules receive it via
    tools.register_tools(app, ctx) and close over it - there is exactly one
    Ledger (the single writer), one PathGuard, one Runner per server process.
    """

    case_dir: Path  # evidence root: read-only
    run_dir: Path  # run root: the only write target
    run_id: str
    ledger: Ledger
    pathguard: PathGuard
    runner: Runner


def build_app(case_dir: str | Path, run_dir: str | Path) -> tuple[FastMCP, AppContext]:
    """Validate roots, build the singletons, register tools; returns (app, ctx).

    Raises ValueError on a missing/invalid directory - the entry point turns
    that into a clean stderr message + nonzero exit before any ledger exists.
    """
    case = Path(case_dir).resolve()
    run = Path(run_dir).resolve()
    if not case.is_dir():
        raise ValueError(f"--case is not an existing directory: {case}")
    if not run.is_dir():
        raise ValueError(f"--run is not an existing directory: {run}")

    run_id = run.name  # runs/<UTC-timestamp>/ - the folder name IS the run id
    ledger = Ledger(run, run_id)
    ctx = AppContext(
        case_dir=case,
        run_dir=run,
        run_id=run_id,
        ledger=ledger,
        pathguard=PathGuard(case, run),
        runner=Runner(run, ledger),
    )

    app = FastMCP(
        SERVER_NAME,
        instructions=(
            "Typed, read-only forensic tools for one DFIR run. Evidence is "
            "read-only; all writes land in the run directory; every action "
            "is recorded in an append-only audit ledger."
        ),
    )

    @app.tool(name="_log_event", structured_output=True)
    def _log_event(event: ControlPlaneEvent,
                   payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """ORCHESTRATOR-ONLY control plane - never in the model's tools array.

        Writes one orchestrator-side event (run_started / api_usage /
        budget_event / run_interrupted / run_ended) through the server's
        single ledger writer. It is registered on this server so that every
        ledger line has exactly one writer, but the orchestrator NEVER
        includes `_log_event` in the tools array sent to the model
        (spec.md > Phase tool allowlists): the agent has no tool that can
        write the ledger. `payload` carries the event-specific fields, e.g.
        api_usage -> {"input_tokens": ..., "output_tokens": ...,
        "cache_read_tokens": ..., "cost_usd": ...}.
        """
        seq = ctx.ledger.write(event, **(payload or {}))
        return {"seq": seq}

    # Registration seam: items 4 and 10 fill tools/ and this call wires them.
    from verdict_mcp.tools import register_tools

    register_tools(app, ctx)
    return app, ctx
