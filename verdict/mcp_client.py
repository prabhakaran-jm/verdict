"""MCP client - stdio spawn, schema conversion, phase allowlists.

Spec ref: spec.md > Orchestrator > MCP client (mcp_client.py).
Built by checklist item 6; consumed by the agent loop in item 7.

Spawns the server (`python -m verdict_mcp --case <dir> --run <run_dir>`) with the
SAME interpreter running the orchestrator (sys.executable, so the venv is
inherited) and holds the mcp.ClientSession over stdio. On enter:
session.initialize() -> list_tools() -> convert each MCP inputSchema into an
Anthropic tool definition ({"name", "description", "input_schema"}).

Two invariants the rest of the system leans on:

1. PROMPT-CACHE STABILITY (spec.md > Agent loop > Prompt caching): the converted
   tool schemas are serialized DETERMINISTICALLY - every dict is rebuilt with
   recursively sorted keys - so the tools-array bytes are byte-identical across
   runs and processes. A single reordered key would invalidate the cache prefix.

2. THE PHASE ALLOWLIST DOUBLE GATE (spec.md > Architecture Overview > Phase tool
   allowlists): set_phase("triage"|"verify") chooses an allowlist
   (TRIAGE_TOOLS / VERIFY_TOOLS, imported from verdict_mcp.tools - the single
   source of truth). call_tool() refuses any name not in the current phase's
   allowlist WITHOUT touching the server (a typed PhaseRefusal). list_tools()
   exposes only the phase-allowed tools to the model. `_log_event` is never
   converted, so the control-plane channel is never visible to the model.
"""

from __future__ import annotations

import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Single source of truth for the phase allowlists (spec.md > Architecture
# Overview > Phase tool allowlists). Re-exported so item 7 can import either
# from here or from verdict_mcp.tools - the lists are identical by construction.
from verdict_mcp.tools import TRIAGE_TOOLS, VERIFY_TOOLS

__all__ = ["MCPClient", "PhaseRefusal", "TRIAGE_TOOLS", "VERIFY_TOOLS"]

#: Tools that flow through `_log_event` are orchestrator-only; the model never
#: sees the control plane (spec.md > Key Technical Decisions #4). We exclude it
#: from the converted Anthropic tool list entirely.
_CONTROL_PLANE_TOOLS = frozenset({"_log_event"})

#: Valid phase names for set_phase(); maps to the allowlist used by the gate.
_PHASE_ALLOWLISTS: dict[str, frozenset[str]] = {
    "triage": frozenset(TRIAGE_TOOLS),
    "verify": frozenset(VERIFY_TOOLS),
}


class PhaseRefusal(Exception):
    """The double gate fired: a tool call was refused before reaching the server.

    Raised by call_tool() when the model names a tool not in the current
    phase's allowlist (or when no phase is set). The orchestrator/agent loop
    catches this, ledgers it as a refusal, and returns the message to the model
    as a tool_result - the server is never contacted. This is the
    orchestrator-side half of the double gate (the server enforces the other
    half independently).
    """


def _sorted_json_value(value: Any) -> Any:
    """Recursively rebuild a JSON value with every dict's keys sorted.

    Determinism for prompt caching (spec.md > Agent loop > Prompt caching):
    json.dumps(..., sort_keys=True) sorts keys at serialization time, but we
    also rebuild the structure so any consumer that re-serializes (or compares
    dicts) sees the same canonical ordering. Lists keep their order - element
    order is semantically meaningful in JSON Schema (e.g. `required`, `enum`).
    """
    if isinstance(value, dict):
        return {key: _sorted_json_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_sorted_json_value(item) for item in value]
    return value


def _to_anthropic_tool(name: str, description: str | None,
                       input_schema: dict[str, Any]) -> dict[str, Any]:
    """One MCP tool -> one Anthropic tool definition, deterministically ordered.

    Anthropic's tool shape is {"name", "description", "input_schema"} (see
    shared/tool-use-concepts.md). The input_schema is the MCP tool's
    inputSchema with keys recursively sorted so the serialized bytes are stable
    across processes - the agent loop puts these straight into the `tools`
    array, and prompt caching keys on the exact bytes.
    """
    return {
        "name": name,
        "description": description or "",
        "input_schema": _sorted_json_value(input_schema),
    }


def canonical_tool_json(tools: list[dict[str, Any]]) -> str:
    """Byte-stable serialization of a converted tool list (cache-stability probe).

    The agent loop never needs this directly - it's the deterministic
    serialization that proves two independent conversions produce identical
    bytes (tests/orchestrator_check.py asserts this). sort_keys here is
    belt-and-suspenders: the structure is already canonical from
    _sorted_json_value, but sorting again guarantees identical output even if a
    caller hand-builds a tool dict.
    """
    return json.dumps(tools, sort_keys=True, ensure_ascii=False, default=str)


class MCPClient:
    """Async context-manager owning the stdio ClientSession to verdict_mcp.

    Lifecycle (spec.md > Orchestrator > MCP client):
      async with MCPClient(case_dir, run_dir) as client:
          client.set_phase("triage")
          tools = client.list_anthropic_tools()      # phase-filtered, cache-stable
          result = await client.call_tool(name, args)  # double-gated, stringified

    Spawn-on-enter / clean-shutdown-on-exit: the server subprocess is launched
    with sys.executable (inheriting the venv) and torn down by closing the
    stdio streams; the SDK's stdio_client terminates the child and drains its
    stderr on exit.
    """

    def __init__(self, case_dir: str | Path, run_dir: str | Path,
                 *, python_executable: str | None = None) -> None:
        self.case_dir = Path(case_dir).resolve()
        self.run_dir = Path(run_dir).resolve()
        # Same interpreter as the orchestrator so the child inherits the venv
        # (spec.md > Runtime & Deployment env note); overridable for tests.
        self._python = python_executable or sys.executable
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None
        # All model-visible tools, Anthropic-format, keyed by name. Built once
        # on enter; never mutated - set_phase() only changes which subset is
        # exposed, so the underlying schema bytes (and thus the cache) are stable.
        self._tools_by_name: dict[str, dict[str, Any]] = {}
        self._phase: str | None = None

    # ----------------------------------------------------------- lifecycle

    async def __aenter__(self) -> "MCPClient":
        self._stack = AsyncExitStack()
        params = StdioServerParameters(
            command=self._python,
            args=["-m", "verdict_mcp", "--case", str(self.case_dir),
                  "--run", str(self.run_dir)],
        )
        # stdio_client spawns the subprocess and yields (read, write) streams;
        # entering it on the exit stack guarantees the child is terminated and
        # its stderr drained when we close the stack (spec.md > MCP client:
        # clean shutdown - terminate the subprocess, drain stderr).
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self._session = session
        await self._load_tools()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        stack, self._stack = self._stack, None
        self._session = None
        if stack is not None:
            await stack.aclose()

    async def _load_tools(self) -> None:
        """list_tools() -> convert each model-visible tool, deterministically.

        `_log_event` is dropped here so it is never offered to the model: the
        agent has no tool that can write the ledger (spec.md > Key Technical
        Decisions #4).
        """
        assert self._session is not None
        listed = await self._session.list_tools()
        converted: dict[str, dict[str, Any]] = {}
        for tool in listed.tools:
            if tool.name in _CONTROL_PLANE_TOOLS:
                continue
            converted[tool.name] = _to_anthropic_tool(
                tool.name, tool.description, dict(tool.inputSchema or {}))
        self._tools_by_name = converted

    # ----------------------------------------------------------- phase gate

    def set_phase(self, phase: str) -> None:
        """Select the active phase allowlist for the double gate.

        `phase` must be "triage" or "verify" (spec.md > Architecture Overview >
        Phase tool allowlists). Anything else is an orchestrator programming
        error - raise loudly rather than silently allow/deny.
        """
        if phase not in _PHASE_ALLOWLISTS:
            raise ValueError(
                f"unknown phase '{phase}' (expected one of: "
                f"{', '.join(sorted(_PHASE_ALLOWLISTS))})"
            )
        self._phase = phase

    @property
    def phase(self) -> str | None:
        """The currently selected phase, or None before set_phase()."""
        return self._phase

    def _allowed_names(self) -> frozenset[str]:
        """Tool names allowed in the current phase (intersected with what the
        server actually registered, so a phase list can never expose a tool the
        server didn't ship)."""
        if self._phase is None:
            return frozenset()
        return _PHASE_ALLOWLISTS[self._phase] & frozenset(self._tools_by_name)

    def list_anthropic_tools(self, phase: str | None = None) -> list[dict[str, Any]]:
        """Anthropic-format tool definitions filtered to the phase allowlist.

        This is exactly what the agent loop (item 7) drops into the `tools`
        array. Pass `phase` to query a specific phase without mutating state;
        omit it to use the phase set via set_phase(). Order is deterministic
        (sorted by tool name) so the serialized `tools` array is cache-stable
        turn over turn.
        """
        active = phase or self._phase
        if active is None:
            raise PhaseRefusal(
                "no phase selected; call set_phase('triage'|'verify') before "
                "requesting the tool list"
            )
        if active not in _PHASE_ALLOWLISTS:
            raise ValueError(f"unknown phase '{active}'")
        allowed = _PHASE_ALLOWLISTS[active] & frozenset(self._tools_by_name)
        return [self._tools_by_name[name] for name in sorted(allowed)]

    # ---------------------------------------------------------- tool calls

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        """Double gate -> session.call_tool -> stringified tool_result content.

        The gate (spec.md > Architecture Overview): if `name` is not in the
        current phase's allowlist, raise PhaseRefusal WITHOUT contacting the
        server. Otherwise call the server and stringify the structured result
        for an Anthropic tool_result block. The server independently enforces
        the same allowlist plus path/param constraints - this is the
        orchestrator-side half of the double gate.
        """
        if self._session is None:
            raise RuntimeError("MCPClient is not connected (use 'async with')")
        if self._phase is None:
            raise PhaseRefusal(
                f"tool '{name}' refused: no phase selected "
                f"(call set_phase first)"
            )
        if name not in self._allowed_names():
            raise PhaseRefusal(
                f"tool '{name}' is not in the '{self._phase}' phase allowlist; "
                f"refused before reaching the server. Allowed: "
                f"{', '.join(sorted(self._allowed_names())) or '(none)'}"
            )
        result = await self._session.call_tool(name, arguments or {})
        return self._stringify_result(result)

    @staticmethod
    def _stringify_result(result: Any) -> str:
        """One string for an Anthropic tool_result block from a CallToolResult.

        Prefer the structured content (the dict our tools return) so the model
        sees the typed payload (excerpt, output_path, output_sha256, cite_seq,
        ...); fall back to the text content blocks the SDK always populates.
        Structured content is serialized with sorted keys so identical results
        stringify identically (matters for the verifier's replay-drift check,
        spec.md > Open Issues #5).
        """
        structured = getattr(result, "structuredContent", None)
        if structured:
            return json.dumps(structured, sort_keys=True, ensure_ascii=False,
                              default=str)
        parts: list[str] = []
        for block in getattr(result, "content", None) or []:
            text = getattr(block, "text", None)
            if text is not None:
                parts.append(text)
            else:
                parts.append(json.dumps(
                    getattr(block, "model_dump", lambda: str(block))(),
                    sort_keys=True, ensure_ascii=False, default=str))
        return "\n".join(parts)
