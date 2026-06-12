"""Manual agentic loop shared by triage and verify phases.

Spec ref: spec.md > Orchestrator > Agent loop (agent/loop.py).
Built by checklist item 7; reused by the verifier in item 8.

Key decisions baked in (spec.md > Key Technical Decisions #1):
- Manual loop over Claude Agent SDK: the API request contains ONLY the typed MCP
  tools for the current phase - no bash tool, no file-write tool, not disabled
  but absent.
- Prompt caching: a cache_control breakpoint on the last system block (caches
  tools + system) and on the newest message turn's last block.
- Resilience: the SDK's default retries cover 429/5xx; if the API is still
  failing after ~2 min of backoff the loop raises LoopInterrupted so the CLI can
  write a partial report, mark the run INTERRUPTED, and exit 2.
- Tool resilience: a failed tool call is retried once, then routed around - one
  broken tool never kills the run (spec.md > Failure & Empty-Case Behavior).

The loop is phase-agnostic: triage.py and verifier.py both call run_phase with
their own system prompt, tool list, and sub-budget gate. Model + effort live in
LoopConfig so item 8 and smoke calibration can tune them in one place.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from verdict.mcp_client import PhaseRefusal

#: Default model + effort knobs (spec.md > Stack: Sonnet 4.6, effort medium,
#: thinking adaptive). One place to tune for item 8 + smoke calibration.
DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_EFFORT = "medium"
DEFAULT_MAX_TOKENS = 8192

#: How long to keep accepting the SDK's retried failures before declaring the
#: API down and interrupting the run (~2 minutes, spec.md > Agent loop >
#: Resilience). The SDK does its own 429/5xx backoff inside each create() call;
#: this wall-clock window bounds how long the loop tolerates repeated create()
#: failures across turns before giving up gracefully.
API_OUTAGE_WINDOW_S = 120.0


class LoopInterrupted(Exception):
    """The Anthropic API stayed down past the outage window.

    Raised by run_phase after ~2 min of failing messages.create calls. The CLI
    catches it, writes a partial report from whatever findings exist, marks the
    run INTERRUPTED in the report + ledger, and exits 2 (spec.md > Agent loop >
    Resilience; prd.md > Failure & Empty-Case Behavior). It carries the last
    underlying API error for the operator message.
    """

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


@dataclass
class LoopConfig:
    """Tunable model knobs for the loop (spec.md > Stack; Open Issue #4).

    One small config so triage, the verifier (item 8), and smoke calibration
    tune model/effort/thinking in exactly one place. effort feeds
    output_config={"effort": ...}; thinking_type feeds thinking={"type": ...}.
    """

    model: str = DEFAULT_MODEL
    effort: str = DEFAULT_EFFORT
    max_tokens: int = DEFAULT_MAX_TOKENS
    thinking_type: str = "adaptive"
    #: Wall-clock seconds of repeated create() failure before LoopInterrupted.
    outage_window_s: float = API_OUTAGE_WINDOW_S
    #: Per-tool retry-once-then-route-around budget (spec resilience).
    tool_retries: int = 1
    #: Extra arguments merged into every messages.create call (test seam /
    #: future tuning). Empty by default.
    extra_create_kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass
class StopInfo:
    """Why a phase loop returned (spec pseudocode's `stop info`)."""

    reason: str  # "end_turn" | "budget_cap" | "max_turns"
    turns: int  # number of model turns taken
    total_cost: float  # cumulative spend after the phase, USD


def _anthropic_error_types() -> tuple[type[BaseException], ...]:
    """The anthropic error classes treated as transient API failures.

    Imported lazily so a no-key / no-anthropic environment can still import this
    module and run the fake-client tests (the checklist's $0 constraint). Tests
    inject a fake client whose create() raises one of these; the real run sees
    real anthropic errors. Falls back to a broad tuple if the SDK shape changes.
    """
    try:
        from anthropic import APIConnectionError, APIError, APIStatusError
    except Exception:  # pragma: no cover - anthropic always present in prod
        return (Exception,)
    return (APIError, APIStatusError, APIConnectionError)


def _with_cache_control(system: str | list) -> list:
    """System prompt as content blocks with a cache breakpoint on the last block.

    Sonnet 4.6's minimum cacheable prefix (2048 tokens) is cleared by our system
    text + 12 tool schemas, so caching the system block caches the tools too
    (spec.md > Agent loop > Prompt caching). Accepts either a plain string or a
    pre-built block list.
    """
    if isinstance(system, str):
        blocks: list[dict[str, Any]] = [{"type": "text", "text": system}]
    else:
        blocks = [dict(block) for block in system]
    if blocks:
        blocks[-1] = {**blocks[-1], "cache_control": {"type": "ephemeral"}}
    return blocks


def _mark_newest_turn(messages: list) -> None:
    """Put a cache_control breakpoint on the last block of the newest turn.

    The newest message turn is the second cache breakpoint (spec.md > Agent
    loop > Prompt caching): caching up to and including it lets the next turn
    reuse the whole conversation prefix. Mutates `messages` in place. Tolerates
    string content (wraps it into a single text block first).
    """
    if not messages:
        return
    last = messages[-1]
    content = last.get("content")
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
        last["content"] = content
    if not isinstance(content, list) or not content:
        return
    block = content[-1]
    if isinstance(block, dict):
        content[-1] = {**block, "cache_control": {"type": "ephemeral"}}


def _strip_cache_control(messages: list) -> None:
    """Remove cache_control from every block in every turn.

    Only the SINGLE newest turn carries the message-side breakpoint at a time;
    before stamping the new newest turn we clear stale ones so we never exceed
    the 4-breakpoint cap and the cached prefix keeps growing cleanly.
    """
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for i, block in enumerate(content):
            if isinstance(block, dict) and "cache_control" in block:
                content[i] = {k: v for k, v in block.items()
                              if k != "cache_control"}


def _content_blocks(response: Any) -> list:
    """The assistant response's content blocks (SDK objects or dicts)."""
    return list(getattr(response, "content", None) or [])


def _block_attr(block: Any, name: str, default: Any = None) -> Any:
    """Attribute from a response block whether it's an SDK object or a dict."""
    if isinstance(block, dict):
        return block.get(name, default)
    return getattr(block, name, default)


def _serialize_block(block: Any) -> dict[str, Any]:
    """One assistant content block -> a plain dict for the message history.

    The assistant turn must be echoed back verbatim in `messages`, so text /
    thinking / tool_use blocks are preserved. SDK objects expose model_dump();
    dicts pass through. Unknown shapes degrade to a text block rather than
    crashing the loop.
    """
    if isinstance(block, dict):
        return dict(block)
    dump = getattr(block, "model_dump", None)
    if callable(dump):
        return {k: v for k, v in dump(exclude_none=True).items()}
    return {"type": "text", "text": str(block)}


async def run_phase(
    client: Any,
    anthropic: Any,
    *,
    system: str | list,
    tools: list[dict],
    messages: list,
    budget: Any,
    ui: Any,
    ledger_via_client: Any,
    phase_name: str,
    config: LoopConfig | None = None,
    max_tokens: int | None = None,
    stop_between_turns: Callable[[], Awaitable[bool] | bool] | None = None,
    on_tool_result: Callable[[str, dict, str, bool], None] | None = None,
) -> tuple[list, StopInfo]:
    """Drive one phase conversation to end_turn (or a between-turn stop).

    Pseudocode (spec.md > Agent loop):
        while True:
            response = anthropic.messages.create(model, max_tokens,
                thinking={"type": "adaptive"},
                output_config={"effort": <config>},
                system=[...cache_control...], tools=phase_tools, messages=history)
            track cost from response.usage -> budget guard check
            if stop_reason == "end_turn": break
            for tool_use block: ui.tool_line -> client.call_tool ->
                append tool_result (is_error when the server rejected)
            cache_control on the newest turn's last block

    Args:
      client:   the MCPClient (call_tool_result / log_event); `mcp_client` in the
                spec signature.
      anthropic: the AsyncAnthropic client (or a fake with .messages.create).
      system:   the phase system prompt (str or block list); cached.
      tools:    the phase's Anthropic tool definitions.
      messages: the running message history; mutated and returned.
      budget:   a BudgetGuard.
      ui:       the TerminalUI (tool_line / narration / update_status).
      ledger_via_client: the object whose .log_event(event, payload) writes the
                control-plane ledger lines (api_usage / budget_event). Usually
                the same MCPClient as `client`; named separately to match the
                spec signature and let a caller route ledger writes elsewhere.
      phase_name: "triage" | "verify" - for the budget-cap transition signal and
                report notes.
      config:   LoopConfig (model/effort/thinking/retries); defaults applied.
      max_tokens: overrides config.max_tokens for this phase.
      stop_between_turns: optional async/sync predicate checked BETWEEN turns; if
                it returns True the loop stops gracefully (used by triage to
                transition at the budget soft cap - never a mid-tool kill).
      on_tool_result: optional observer called after every tool dispatch with
                (tool_name, args, result_text, is_error). Triage uses it to
                ingest record_finding results into the FindingsStore as the loop
                observes them - the store mirrors what the server returned rather
                than reading the ledger back (spec.md > Findings store).

    Returns (messages, StopInfo). Raises LoopInterrupted if the API stays down
    past the outage window.
    """
    cfg = config or LoopConfig()
    tokens = max_tokens or cfg.max_tokens
    transient_errors = _anthropic_error_types()

    turns = 0
    outage_started: float | None = None

    while True:
        # --- between-turn graceful stop (budget soft cap / caller predicate).
        # NEVER mid-tool: we only check here, at the top of a turn.
        if stop_between_turns is not None:
            should_stop = stop_between_turns()
            if hasattr(should_stop, "__await__"):
                should_stop = await should_stop
            if should_stop:
                return messages, StopInfo("budget_cap", turns, budget.total_cost)

        system_blocks = _with_cache_control(system)
        try:
            response = await anthropic.messages.create(
                model=cfg.model,
                max_tokens=tokens,
                thinking={"type": cfg.thinking_type},
                output_config={"effort": cfg.effort},
                system=system_blocks,
                tools=tools,
                messages=messages,
                **cfg.extra_create_kwargs,
            )
        except transient_errors as exc:
            # The SDK already retried 429/5xx internally; reaching here means a
            # create() raised anyway. Tolerate repeated failures for up to the
            # outage window, then interrupt gracefully (spec resilience).
            now = time.monotonic()
            if outage_started is None:
                outage_started = now
            elapsed = now - outage_started
            if elapsed >= cfg.outage_window_s:
                raise LoopInterrupted(
                    f"Anthropic API unavailable for ~{int(elapsed)}s during "
                    f"the {phase_name} phase ({type(exc).__name__}: {exc}); "
                    f"writing a partial report.",
                    cause=exc,
                ) from exc
            continue
        outage_started = None  # a successful create() resets the outage clock
        turns += 1

        # --- cost tracking + ledger the usage line (api_usage control plane).
        usage = getattr(response, "usage", None)
        if usage is not None:
            budget.track(usage)
            await _ledger_api_usage(ledger_via_client, usage, budget)
        ui.update_status(cost_usd=budget.total_cost)

        # --- echo the assistant turn into history.
        content = _content_blocks(response)
        assistant_blocks = [_serialize_block(b) for b in content]
        messages.append({"role": "assistant", "content": assistant_blocks})

        # --- narrate any plain-text reasoning the model emitted this turn.
        for block in content:
            if _block_attr(block, "type") == "text":
                text = (_block_attr(block, "text") or "").strip()
                if text:
                    ui.narration(text)

        stop_reason = getattr(response, "stop_reason", None)
        tool_uses = [b for b in content if _block_attr(b, "type") == "tool_use"]

        if stop_reason == "end_turn" or not tool_uses:
            # Model is done (or asked for no tools) - phase complete.
            return messages, StopInfo("end_turn", turns, budget.total_cost)

        # --- dispatch every tool_use block -> a tool_result block.
        tool_results: list[dict[str, Any]] = []
        for block in tool_uses:
            result_block = await _dispatch_tool(client, ui, budget, cfg, block)
            if on_tool_result is not None:
                on_tool_result(
                    _block_attr(block, "name"),
                    _block_attr(block, "input") or {},
                    result_block["content"],
                    result_block["is_error"],
                )
            tool_results.append(result_block)

        # --- append the tool results as the next user turn; cache-stamp it.
        messages.append({"role": "user", "content": tool_results})
        _strip_cache_control(messages)
        _mark_newest_turn(messages)


async def _dispatch_tool(client: Any, ui: Any, budget: Any,
                         cfg: LoopConfig, block: Any) -> dict[str, Any]:
    """Run one tool_use block -> a tool_result block, with retry/route-around.

    Renders one ui.tool_line per attempt. A server rejection/error
    (is_error=True) is retried once (cfg.tool_retries); if it still fails the
    error text is returned to the model as an is_error tool_result so the model
    can route around it - the loop never raises out on a single bad tool call
    (spec.md > Failure & Empty-Case Behavior). A PhaseRefusal (hallucinated /
    out-of-phase tool) is caught and returned to the model as an is_error result
    too, never crashing the run.
    """
    tool_use_id = _block_attr(block, "id")
    name = _block_attr(block, "name")
    args = _block_attr(block, "input") or {}

    text = ""
    is_error = True
    attempts = cfg.tool_retries + 1
    for attempt in range(attempts):
        start = time.monotonic()
        try:
            text, is_error = await client.call_tool_result(name, args)
        except PhaseRefusal as exc:
            # Out-of-phase / hallucinated tool: ledgered server-side as a
            # rejection on the real path; here (gate refused pre-server) we hand
            # the message back to the model. Not retryable - the tool is not
            # available this phase.
            text, is_error = str(exc), True
            ui.tool_line(name, args, duration_s=time.monotonic() - start,
                         total_cost=budget.total_cost)
            break
        duration = time.monotonic() - start
        sha = _extract_sha(text)
        ui.tool_line(name, args, duration_s=duration, sha=sha,
                     total_cost=budget.total_cost)
        if not is_error:
            break
        # is_error and we have a retry left: try once more (the run is static,
        # so a transient parser hiccup may clear; otherwise we route around).
        if attempt < attempts - 1:
            continue

    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": text,
        "is_error": is_error,
    }


def _extract_sha(text: str) -> str | None:
    """Pull output_sha256 out of a stringified tool result for the tool line.

    Tool results are JSON with an output_sha256 field (spec.md > Subprocess
    runner). Best-effort: returns None if the result isn't JSON or has no sha
    (e.g. record_finding, a refusal) so the tool line just shows '----'.
    """
    import json
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        sha = data.get("output_sha256")
        return sha if isinstance(sha, str) else None
    return None


async def _ledger_api_usage(ledger_via_client: Any, usage: Any,
                            budget: Any) -> None:
    """Write one api_usage ledger line for a turn's token usage + cost.

    Through the control-plane log_event (never a model-visible tool). Best-effort
    - a control-plane failure must not crash the investigation, so we swallow it
    (the ledger is convenience here; the budget total is authoritative for the
    cap). The real cost lands in the budget ticker regardless.
    """
    from verdict.budget import usage_cost

    payload = {
        "input_tokens": _u(usage, "input_tokens"),
        "output_tokens": _u(usage, "output_tokens"),
        "cache_read_tokens": _u(usage, "cache_read_input_tokens"),
        "cache_write_tokens": _u(usage, "cache_creation_input_tokens"),
        "cost_usd": round(usage_cost(usage), 6),
        "cumulative_cost_usd": round(budget.total_cost, 6),
    }
    try:
        await ledger_via_client.log_event("api_usage", payload)
    except Exception:  # noqa: BLE001 - ledger is convenience; never fatal here
        pass


def _u(usage: Any, name: str) -> int:
    if isinstance(usage, dict):
        value = usage.get(name)
    else:
        value = getattr(usage, name, None)
    return int(value) if value else 0
