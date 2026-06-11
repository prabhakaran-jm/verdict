"""MCP client - stdio spawn, schema conversion, phase allowlists.

Spec ref: spec.md > Orchestrator > MCP client (mcp_client.py).
Filled in by checklist item 6.

Spawns the server (`python -m verdict_mcp --case <dir> --run <run_dir>`) and holds
the ClientSession. Converts MCP inputSchema -> Anthropic tool definitions
(deterministic sorted serialization for prompt-cache stability) and enforces the
per-phase tool allowlist as the double gate.
"""

from __future__ import annotations

# Phase tool allowlists (spec.md > Architecture Overview > Phase tool allowlists).
# Triage: tools 1-12 (includes record_finding).
# Verify: tools 2-11 + record_verdict (no record_finding, no evidence_inventory).
# _log_event is orchestrator-only and never appears in the model's tools array.
TRIAGE_TOOLS: list[str] = []  # TODO(item 6): populate from server list_tools()
VERIFY_TOOLS: list[str] = []  # TODO(item 6): populate from server list_tools()


class MCPClient:
    """Owns the stdio ClientSession to verdict_mcp. TODO(item 6)."""

    def __init__(self, case_dir: str, run_dir: str) -> None:
        # TODO(item 6): spawn `python -m verdict_mcp --case ... --run ...` over stdio.
        raise NotImplementedError("Implemented in checklist item 6.")

    async def list_anthropic_tools(self, phase: str) -> list[dict]:
        """list_tools() -> Anthropic tool definitions, filtered to the phase allowlist."""
        raise NotImplementedError("Implemented in checklist item 6.")

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Allowlist check -> session.call_tool -> stringified result for tool_result."""
        raise NotImplementedError("Implemented in checklist item 6.")
