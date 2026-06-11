"""Manual agentic loop shared by triage and verify phases.

Spec ref: spec.md > Orchestrator > Agent loop (agent/loop.py).
Filled in by checklist item 7.

Key decisions baked in (spec.md > Key Technical Decisions #1):
- Manual loop over Claude Agent SDK: the API request contains ONLY the typed MCP
  tools for the current phase - no bash tool, no file-write tool, not disabled
  but absent.
- Prompt caching: breakpoint on the last system block (tools + system) and on the
  newest message turn.
- Resilience: SDK default retries for 429/5xx; ~2 min of failed backoff -> partial
  report, run marked INTERRUPTED, exit 2.
"""

from __future__ import annotations


async def run_agent_loop(client, mcp_client, *, model: str, system: list,
                         phase_tools: list[dict], messages: list,
                         budget_guard, terminal_ui) -> list:
    """Drive one phase conversation to end_turn; returns the final message history.

    Pseudocode per spec:
        while True:
            response = client.messages.create(model, max_tokens=8192,
                thinking={"type": "adaptive"}, output_config={"effort": "medium"},
                system=[...cache_control...], tools=phase_tools, messages=history)
            track cost from response.usage -> budget guard check
            if stop_reason == "end_turn": break
            for tool_use block: narrate -> execute via MCP client -> append tool_result
    """
    # TODO(item 7): implement per the spec pseudocode above.
    raise NotImplementedError("Implemented in checklist item 7.")
