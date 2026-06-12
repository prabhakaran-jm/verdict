"""Agent-loop check for checklist item 7 - loop, budget guard, triage, findings.

Plain stdlib + asyncio (no pytest), same style as orchestrator_check.py /
tools_check.py / foundation_check.py. CRITICAL: NO real Anthropic API calls and
NO ANTHROPIC_API_KEY required - the entire agentic loop is driven by a
FakeAnthropic that returns scripted responses (tool_use blocks, usage numbers,
stop_reason). This proves the loop logic offline for $0; the first REAL run is
the learner's job on the SIFT VM at checkpoint 3.

The fake drives the REAL MCPClient against the REAL verdict_mcp server
subprocess pointed at cases/smoke, so tool calls actually execute and ledger.

Checks:
  1. happy path: narration + evidence tool (read_artifact on the decoy) ->
     record_finding citing the real tool_result seq -> end_turn. Asserts the
     loop dispatches tools, renders tool_lines, tracks cost from fake usage,
     records >=1 finding into findings.json, and terminates on end_turn.
  2. cost math: a known token count prices to the exact Sonnet 4.6 rate.
  3. budget cap: usage crossing the triage 60% cap trips over_triage_cap, a
     budget_event is ledgered, and triage transitions (no crash).
  4. retry/route-around: a tool the server rejects (bad params) is retried once
     then the run proceeds to end_turn (the loop never raises out).
  5. API outage: messages.create raising a simulated APIError repeatedly ->
     LoopInterrupted surfaced (no unhandled crash) so the CLI would exit 2.
  6. cache breakpoints: cache_control is set on the system block AND on the
     newest message turn in the args FakeAnthropic received.

Run:  python tests/agent_check.py
Prints PASS/FAIL per check; exits nonzero on any FAIL.
"""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import tempfile
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from verdict.agent.loop import (  # noqa: E402
    DEFAULT_MODEL,
    LoopConfig,
    LoopInterrupted,
    run_phase,
)
from verdict.agent.triage import run_triage  # noqa: E402
from verdict.budget import (  # noqa: E402
    PRICE_CACHE_READ,
    PRICE_INPUT,
    PRICE_OUTPUT,
    BudgetGuard,
    usage_cost,
)
from verdict.cli import create_run_dir  # noqa: E402
from verdict.findings import FindingsStore  # noqa: E402
from verdict.mcp_client import MCPClient  # noqa: E402

SMOKE = REPO_ROOT / "cases" / "smoke"
FAILURES: list[str] = []


def run_check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        FAILURES.append(name)
        print(f"FAIL  {name}")
        print("      " + traceback.format_exc().strip().replace("\n", "\n      "))
    else:
        print(f"PASS  {name}")


# --------------------------------------------------------- fake Anthropic


class Usage:
    """Minimal stand-in for anthropic.types.Usage (only the fields we price)."""

    def __init__(self, input_tokens=0, output_tokens=0,
                 cache_read_input_tokens=0, cache_creation_input_tokens=0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


class Block:
    """A response content block. type is 'text' or 'tool_use'.

    model_dump() mirrors the anthropic SDK so the loop can echo the assistant
    turn into history exactly as a real block would serialize.
    """

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def model_dump(self, exclude_none=True):
        d = dict(self.__dict__)
        if exclude_none:
            d = {k: v for k, v in d.items() if v is not None}
        return d


class Response:
    def __init__(self, content, stop_reason, usage):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage


def text_block(text):
    return Block(type="text", text=text)


def tool_use_block(tool_id, name, inp):
    return Block(type="tool_use", id=tool_id, name=name, input=inp)


def _latest_cite_seq(messages):
    """Pull a cite_seq out of the most recent tool_result in the history.

    The fake reacts to REAL server output: after an evidence tool runs, its
    tool_result (a JSON string) carries cite_seq. The fake reads it so the
    record_finding it then emits cites a real tool_result ledger seq - proving
    the loop fed the live server result back into the conversation.
    """
    for message in reversed(messages):
        if message.get("role") != "user":
            continue
        for block in message.get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_result":
                try:
                    data = json.loads(block["content"])
                except (ValueError, TypeError, KeyError):
                    continue
                if isinstance(data, dict) and "cite_seq" in data:
                    return data["cite_seq"]
    return None


class FakeAnthropic:
    """Scripted async messages.create driving the loop with no real API.

    `script` is a list of callables; each takes the create() kwargs and returns
    a Response (or raises, to simulate an API error). The fake records every
    kwargs dict it received in `.calls` so the test can inspect cache_control,
    tools, system, and messages. A reactive script step can read the live
    messages (e.g. the latest cite_seq) to emit a record_finding that the real
    server will accept.
    """

    def __init__(self, script):
        self._script = list(script)
        self._i = 0
        self.calls = []
        self.messages = self  # so anthropic.messages.create(...) resolves here

    async def create(self, **kwargs):
        # Snapshot the kwargs AS SENT - the loop mutates `messages` in place
        # across turns, so a deep copy is needed to inspect the cache_control /
        # message state at the moment of THIS call (not the final state).
        self.calls.append(copy.deepcopy(kwargs))
        if self._i >= len(self._script):
            # Default tail: end the turn so a loop never spins forever.
            return Response([text_block("done")], "end_turn", Usage(10, 5))
        step = self._script[self._i]
        self._i += 1
        # The script step sees the LIVE kwargs (so it can read live cite_seqs).
        return step(kwargs)


class FakeAPIError(Exception):
    """Stand-in for an anthropic APIError. The loop treats anthropic's real
    error types as transient; we register this one for the outage test."""


# --------------------------------------------------------------- ui stub


class StubUI:
    """Captures what the loop renders without a real terminal."""

    def __init__(self):
        self.tool_lines = []
        self.narrations = []
        self.findings = 0
        self.cost = 0.0

    def tool_line(self, tool, args=None, *, duration_s=None, sha=None,
                  total_cost=None, ts=None):
        self.tool_lines.append((tool, args, sha))

    def narration(self, text):
        self.narrations.append(text)

    def update_status(self, *, findings=None, cost_usd=None):
        if findings is not None:
            self.findings = findings
        if cost_usd is not None:
            self.cost = cost_usd

    def start_status(self):
        pass

    def stop_status(self):
        pass


# ------------------------------------------------------ 1. happy path


def check_happy_path() -> None:
    """narration + read_artifact -> record_finding -> end_turn, end to end."""

    def turn1(_kw):
        # Narrate, then read the decoy file (a real pure-Python tool on smoke).
        return Response(
            [text_block("The filename mimikatz.exe is suspicious; reading its "
                        "contents to test the credential-theft hypothesis."),
             tool_use_block("t1", "read_artifact",
                            {"path": str(SMOKE / "mimikatz.exe"),
                             "length": 100})],
            "tool_use", Usage(1200, 300, cache_read_input_tokens=0))

    def turn2(kw):
        # React to the real tool_result: cite its seq in a record_finding.
        cite = _latest_cite_seq(kw["messages"])
        assert cite is not None, "no cite_seq surfaced from the read_artifact result"
        return Response(
            [tool_use_block("t2", "record_finding",
                            {"claim": "A file named mimikatz.exe is present in "
                                      "the case folder.",
                             "severity": "high", "attack_id": "T1003",
                             "cites": [cite]})],
            "tool_use", Usage(1500, 200))

    def turn3(_kw):
        return Response([text_block("Recorded one finding; triage complete.")],
                        "end_turn", Usage(800, 120))

    fake = FakeAnthropic([turn1, turn2, turn3])
    ui = StubUI()

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)
                store = FindingsStore(run_dir)
                # Use raw inventory text as the kickoff; survey already ran it in
                # production, but triage only needs the string here.
                client.set_phase("triage")
                inv = await client.call_tool("evidence_inventory", {})
                stop = await run_triage(
                    fake, client, inventory_json=inv, budget_guard=budget,
                    findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))

            # terminated on end_turn
            assert stop.reason == "end_turn", stop
            # tool lines rendered for both dispatched tools
            tools_seen = [t for t, _a, _s in ui.tool_lines]
            assert "read_artifact" in tools_seen, tools_seen
            assert "record_finding" in tools_seen, tools_seen
            # narration captured
            assert any("mimikatz" in n for n in ui.narrations), ui.narrations
            # cost tracked from fake usage (sum of all turns' usage > 0)
            assert budget.total_cost > 0, budget.total_cost
            # >=1 finding ingested + flushed to findings.json
            assert len(store) >= 1, len(store)
            on_disk = json.loads(store.path.read_text(encoding="utf-8"))
            assert on_disk and on_disk[0]["id"] == "F-001", on_disk
            assert on_disk[0]["attack_id"] == "T1003"
            assert on_disk[0]["verdict"] is None  # verifier (item 8) fills this
            # the finding cites a real tool_result seq -> server accepted it
            ledger = [json.loads(l) for l in
                      (run_dir / "ledger.jsonl").read_text(
                          encoding="utf-8").splitlines() if l.strip()]
            recorded = [l for l in ledger if l["event"] == "finding_recorded"]
            assert recorded and recorded[-1]["finding_id"] == "F-001", recorded
            # api_usage lines were ledgered through the control plane
            usage_lines = [l for l in ledger if l["event"] == "api_usage"]
            assert usage_lines, "no api_usage ledger lines written"

    asyncio.run(scenario())


# ------------------------------------------------------ 2. cost math


def check_cost_math() -> None:
    # Known token counts -> exact Sonnet 4.6 price, no rounding surprises.
    u = Usage(input_tokens=1_000_000, output_tokens=0)
    assert abs(usage_cost(u) - PRICE_INPUT) < 1e-9, usage_cost(u)
    u = Usage(input_tokens=0, output_tokens=1_000_000)
    assert abs(usage_cost(u) - PRICE_OUTPUT) < 1e-9, usage_cost(u)
    u = Usage(cache_read_input_tokens=1_000_000)
    assert abs(usage_cost(u) - PRICE_CACHE_READ) < 1e-9, usage_cost(u)
    # mixed: 1200 in + 300 out + 900 cache-read (the foundation_check numbers)
    u = Usage(input_tokens=1200, output_tokens=300, cache_read_input_tokens=900)
    expected = (1200 * PRICE_INPUT + 300 * PRICE_OUTPUT
                + 900 * PRICE_CACHE_READ) / 1_000_000
    assert abs(usage_cost(u) - expected) < 1e-12, (usage_cost(u), expected)

    # BudgetGuard.track is additive and feeds total_cost
    b = BudgetGuard(5.00)
    b.track(Usage(input_tokens=1_000_000))   # $3.00
    b.track(Usage(output_tokens=1_000_000))  # +$15.00
    assert abs(b.total_cost - (PRICE_INPUT + PRICE_OUTPUT)) < 1e-9, b.total_cost
    # sub-budget API
    assert abs(b.triage_cap() - 3.00) < 1e-12   # 60% of 5.00
    assert abs(b.verify_cap() - 4.50) < 1e-12   # 90% of 5.00
    assert abs(b.report_reserve() - 0.50) < 1e-12  # 10% of 5.00


# ------------------------------------------------------ 3. budget cap


def check_budget_cap() -> None:
    """Usage crossing the triage 60% cap trips the flag, ledgers a budget_event,
    and triage transitions (StopInfo budget_cap) instead of crashing."""

    # budget 5.00 -> triage cap 3.00. One turn at 1.2M output tokens = $18 way
    # over the cap; the loop checks BETWEEN turns, so turn 1 runs, cost is
    # tracked, then turn 2's pre-check sees the cap and stops gracefully.
    def turn1(_kw):
        # call a real (cheap) tool so the turn dispatches, then heavy usage.
        return Response(
            [tool_use_block("t1", "read_artifact",
                            {"path": str(SMOKE / "mimikatz.exe"), "length": 50})],
            "tool_use", Usage(input_tokens=0, output_tokens=1_200_000))

    def turn_should_not_run(_kw):
        raise AssertionError("loop kept going past the triage budget cap")

    fake = FakeAnthropic([turn1, turn_should_not_run])
    ui = StubUI()

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)
                store = FindingsStore(run_dir)
                client.set_phase("triage")
                inv = await client.call_tool("evidence_inventory", {})
                stop = await run_triage(
                    fake, client, inventory_json=inv, budget_guard=budget,
                    findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))

            assert budget.over_triage_cap(), budget.total_cost
            assert stop.reason == "budget_cap", stop
            # exactly one model turn ran (turn1); turn2's pre-check stopped it
            assert stop.turns == 1, stop
            # a budget_event ledger line was written via the control plane
            ledger = [json.loads(l) for l in
                      (run_dir / "ledger.jsonl").read_text(
                          encoding="utf-8").splitlines() if l.strip()]
            budget_events = [l for l in ledger if l["event"] == "budget_event"]
            assert budget_events, "no budget_event ledger line on cap"
            assert budget_events[-1]["kind"] == "triage_soft_cap", budget_events
            # a report note was recorded for the report generator (item 9)
            assert any("soft budget cap" in n for n in budget.notes), budget.notes

    asyncio.run(scenario())


# ------------------------------------------------ 4. retry / route-around


def check_retry_route_around() -> None:
    """A tool the server rejects (bad params) is retried once, then the run
    proceeds to end_turn - the loop never raises out on a bad tool call."""

    def turn1(_kw):
        # read_artifact with an out-of-range length -> server rejects it
        # (is_error). The loop retries once, then routes around.
        return Response(
            [tool_use_block("t1", "read_artifact",
                            {"path": str(SMOKE / "mimikatz.exe"),
                             "length": 999999})],
            "tool_use", Usage(900, 100))

    def turn2(_kw):
        return Response([text_block("Tool failed; routing around. Done.")],
                        "end_turn", Usage(400, 60))

    fake = FakeAnthropic([turn1, turn2])
    ui = StubUI()

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)
                store = FindingsStore(run_dir)
                client.set_phase("triage")
                inv = await client.call_tool("evidence_inventory", {})
                # must NOT raise out of the loop
                stop = await run_triage(
                    fake, client, inventory_json=inv, budget_guard=budget,
                    findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))

            assert stop.reason == "end_turn", stop
            # the bad tool was attempted (retry-once = 2 attempts -> 2 tool_lines)
            ra_lines = [t for t, _a, _s in ui.tool_lines if t == "read_artifact"]
            assert len(ra_lines) == 2, (
                f"expected 1 retry (2 attempts), got {len(ra_lines)}")
            # the run produced no finding (clean - bad tool routed around)
            assert len(store) == 0, len(store)
            # the rejection was ledgered server-side as tool_rejected
            ledger = [json.loads(l) for l in
                      (run_dir / "ledger.jsonl").read_text(
                          encoding="utf-8").splitlines() if l.strip()]
            rejected = [l for l in ledger if l["event"] == "tool_rejected"
                        and l["tool"] == "read_artifact"]
            assert rejected, "bad read_artifact was not ledgered tool_rejected"

    asyncio.run(scenario())


# ---------------------------------------------------- 5. API outage


def check_api_outage() -> None:
    """messages.create raising a transient API error repeatedly -> the loop
    surfaces LoopInterrupted (not an unhandled crash) so the CLI exits 2."""
    import verdict.agent.loop as loop_mod

    # Make the loop treat FakeAPIError as a transient API failure, and shrink
    # the outage window to ~0 so the test doesn't wait two minutes.
    orig_types = loop_mod._anthropic_error_types
    loop_mod._anthropic_error_types = lambda: (FakeAPIError,)
    try:
        def always_fail(_kw):
            raise FakeAPIError("503 service unavailable")

        # infinite supply of failures
        class AlwaysFail(FakeAnthropic):
            async def create(self, **kwargs):
                self.calls.append(kwargs)
                raise FakeAPIError("503 service unavailable")

        fake = AlwaysFail([])
        ui = StubUI()
        budget = BudgetGuard(5.00)
        messages = [{"role": "user", "content": "go"}]

        async def scenario():
            with tempfile.TemporaryDirectory() as td:
                run_dir = create_run_dir(Path(td) / "runs")
                async with MCPClient(SMOKE, run_dir) as client:
                    client.set_phase("triage")
                    tools = client.list_anthropic_tools("triage")
                    raised = False
                    try:
                        await run_phase(
                            client, fake, system="s", tools=tools,
                            messages=messages, budget=budget, ui=ui,
                            ledger_via_client=client, phase_name="triage",
                            config=LoopConfig(model="fake", outage_window_s=0.0))
                    except LoopInterrupted as exc:
                        raised = True
                        assert "unavailable" in str(exc), str(exc)
                        assert isinstance(exc.cause, FakeAPIError), exc.cause
                    assert raised, "LoopInterrupted was not raised on API outage"
                    # at least one create() attempt was made before giving up
                    assert fake.calls, "no create() attempt before interrupt"

        asyncio.run(scenario())
    finally:
        loop_mod._anthropic_error_types = orig_types


# ------------------------------------------------ 6. cache breakpoints


def check_cache_breakpoints() -> None:
    """cache_control on the system block AND on the newest message turn in the
    kwargs FakeAnthropic received."""

    def turn1(_kw):
        return Response(
            [tool_use_block("t1", "read_artifact",
                            {"path": str(SMOKE / "mimikatz.exe"), "length": 20})],
            "tool_use", Usage(500, 50))

    def turn2(_kw):
        return Response([text_block("done")], "end_turn", Usage(100, 10))

    fake = FakeAnthropic([turn1, turn2])
    ui = StubUI()
    budget = BudgetGuard(5.00)
    messages = [{"role": "user", "content": "kick off"}]

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                client.set_phase("triage")
                tools = client.list_anthropic_tools("triage")
                await run_phase(
                    client, fake, system="system prompt text", tools=tools,
                    messages=messages, budget=budget, ui=ui,
                    ledger_via_client=client, phase_name="triage",
                    config=LoopConfig(model="fake"))

        assert len(fake.calls) >= 2, len(fake.calls)
        # every create() carries a cache_control on the LAST system block
        for call in fake.calls:
            system = call["system"]
            assert isinstance(system, list) and system, system
            assert system[-1].get("cache_control") == {"type": "ephemeral"}, \
                system[-1]
            assert system[-1]["type"] == "text"

        # the SECOND create() (after a tool turn) has a cache_control on the
        # newest message turn's last block (the tool_result turn).
        second = fake.calls[1]
        last_turn = second["messages"][-1]
        assert last_turn["role"] == "user", last_turn
        content = last_turn["content"]
        assert isinstance(content, list) and content, content
        assert content[-1].get("cache_control") == {"type": "ephemeral"}, \
            content[-1]
        # thinking + effort knobs are passed through to the API
        assert second["thinking"] == {"type": "adaptive"}, second["thinking"]
        assert second["output_config"] == {"effort": "medium"}, \
            second["output_config"]

    asyncio.run(scenario())


# ----------------------------------------------------------------- harness


def main() -> int:
    checks = [
        ("happy path: tool dispatch -> record_finding -> end_turn, findings.json",
         check_happy_path),
        ("budget: exact Sonnet 4.6 cost math + sub-budget API",
         check_cost_math),
        ("budget: triage 60% cap trips, budget_event ledgered, transitions",
         check_budget_cap),
        ("resilience: rejected tool retried once then routed around (no raise)",
         check_retry_route_around),
        ("resilience: repeated APIError -> LoopInterrupted (CLI would exit 2)",
         check_api_outage),
        ("cache: cache_control on system block + newest message turn; knobs",
         check_cache_breakpoints),
    ]
    for name, fn in checks:
        run_check(name, fn)
    total, failed = len(checks), len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed"
          + (f" - FAILED: {', '.join(FAILURES)}" if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
