"""Typed tool implementations registered by server.py.

Loose-artifact + recording tools (checklist item 4): inventory, evtx, registry,
execution, yara_scan, artifacts, findings_tools.
Image-backed tools (checklist item 10): fs, mft, timeline, memory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import cycle guard: server.py imports this module
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext


def register_tools(app: "FastMCP", ctx: "AppContext") -> None:
    """Register every model-visible tool on the FastMCP app.

    THE registration seam for items 4 and 10. Contract: each tool module
    exposes `register(app, ctx)` decorating its functions with `@app.tool()`
    and closing over `ctx` (the per-run Ledger / PathGuard / Runner
    singletons - see server.AppContext). This function just calls them:

        from verdict_mcp.tools import artifacts, evtx, ...
        artifacts.register(app, ctx)   # item 4
        ...
        fs.register(app, ctx)          # item 10

    Per-tool rules (spec.md > MCP Server > Tool definitions): pathguard every
    model-supplied path, run binaries only via ctx.runner.run_tool(), and on
    validation/path refusal call ctx.ledger.tool_rejected() before returning
    the error. Nothing is registered yet - item 3 ships only the _log_event
    control plane (defined in server.py, never shown to the model).
    """
    # item 4:  inventory, evtx, registry, execution, yara_scan, artifacts,
    #          findings_tools
    # item 10: fs, mft, timeline, memory
