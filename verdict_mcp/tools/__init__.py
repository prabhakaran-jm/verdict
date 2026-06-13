"""Typed tool implementations registered by server.py.

Loose-artifact + recording tools (checklist item 4, DONE): inventory, evtx,
registry, execution, yara_scan, artifacts, findings_tools.
Image-backed tools (checklist item 10, DONE): fs, mft, timeline, memory.

Also the single home of the phase allowlists (spec.md > Architecture
Overview > Phase tool allowlists) - the orchestrator imports TRIAGE_TOOLS /
VERIFY_TOOLS from here so the canonical lists exist in exactly one place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import cycle guard: server.py imports this module
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

#: Spec tool numbering 1-13. Triage gets 1-12 (record_finding, no
#: record_verdict); verify gets 2-11 + record_verdict (no record_finding,
#: no evidence_inventory). `_log_event` is in neither - the model never
#: sees the control plane.
ALL_TOOLS: tuple[str, ...] = (
    "evidence_inventory",  # 1   triage only
    "fs_list",             # 2
    "fs_extract",          # 3
    "mft_query",           # 4
    "evtx_query",          # 5
    "registry_query",      # 6
    "execution_evidence",  # 7
    "timeline_query",      # 8
    "mem_analyze",         # 9
    "yara_scan",           # 10
    "read_artifact",       # 11
    "record_finding",      # 12  triage only
    "record_verdict",      # 13  verify only
)

TRIAGE_TOOLS: tuple[str, ...] = ALL_TOOLS[0:12]
VERIFY_TOOLS: tuple[str, ...] = ALL_TOOLS[1:11] + ("record_verdict",)


def register_tools(app: "FastMCP", ctx: "AppContext") -> None:
    """Register every model-visible tool on the FastMCP app.

    Contract: each tool module exposes `register(app, ctx)`, decorates its
    functions with `@app.tool()` and closes over `ctx` (the per-run Ledger /
    PathGuard / Runner singletons - see server.AppContext).

    Per-tool rules (spec.md > MCP Server > Tool definitions): pathguard
    every model-supplied path, run binaries only via ctx.runner.run_tool(),
    pure-Python tools ledger through common.pure_tool_call(). The rejection
    boundary installed last guarantees the PRD acceptance behavior: every
    refused call (schema violation, unknown tool/param, path escape,
    semantic Rejection) is ledgered `tool_rejected` and returns a clean
    error - never a traceback (prd.md > Constrained Tooling).
    """
    from verdict_mcp.tools import (
        artifacts,
        evtx,
        execution,
        findings_tools,
        fs,
        inventory,
        memory,
        mft,
        registry,
        timeline,
        yara_scan,
    )
    from verdict_mcp.tools.common import install_rejection_boundary

    inventory.register(app, ctx)        # 1
    fs.register(app, ctx)                 # 2-3
    mft.register(app, ctx)                # 4
    evtx.register(app, ctx)             # 5
    registry.register(app, ctx)         # 6
    execution.register(app, ctx)        # 7
    timeline.register(app, ctx)         # 8
    memory.register(app, ctx)           # 9
    yara_scan.register(app, ctx)        # 10
    artifacts.register(app, ctx)        # 11
    findings_tools.register(app, ctx)   # 12-13

    install_rejection_boundary(app, ctx)
