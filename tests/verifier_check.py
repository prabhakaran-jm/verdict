"""Verifier-pass check for checklist item 8 - the REFUTED flip.

Plain stdlib + asyncio (no pytest), same style as agent_check.py /
orchestrator_check.py. CRITICAL: NO real Anthropic API calls and NO
ANTHROPIC_API_KEY required - a FakeAnthropic returns scripted responses
(tool_use blocks, usage, stop_reason) and drives the REAL MCPClient against the
REAL verdict_mcp server subprocess pointed at cases/smoke. The real smoke run
that shows the live REFUTED flip is the learner's job on the SIFT VM.

The verifier needs findings that the server's record_verdict will accept, and
those findings must cite real tool_result seqs. So each scenario first runs a
scripted TRIAGE (FakeAnthropic) that records findings via the server's
record_finding (same server process, so record_verdict later finds them), then
runs the verifier (a second FakeAnthropic) over the same client.

Checks:
  1. happy path: two findings - a content-supported one (VERIFIED) and the
     mimikatz.exe decoy (REFUTED via reading the 12-byte ASCII content). Asserts
     each finding gets a verdict in findings.json, verdict_recorded ledger lines
     are written, ui.verdict_flip fired per finding, and the decoy is REFUTED.
  2. phase gate: in the verify phase the client refuses record_finding and
     evidence_inventory (out of the verify allowlist) WITHOUT hitting the server.
  3. SHA drift: the verifier re-runs a cited query but the fresh output SHA
     differs from the cited SHA -> the drift is detected and surfaced (in the
     verdict reason / a drift note), not silently ignored.
  4. verify sub-budget: usage that exhausts verify_cap mid-pass -> the remaining
     findings are marked UNCONFIRMED (budget) and the pass ends gracefully (no
     crash, no blank verdicts).

Run:  python tests/verifier_check.py
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

from verdict.agent.loop import LoopConfig  # noqa: E402
from verdict.agent.triage import run_triage  # noqa: E402
from verdict.agent.verifier import (  # noqa: E402
    build_cited_entries,
    run_verifier,
)
from verdict.budget import BudgetGuard  # noqa: E402
from verdict.cli import create_run_dir  # noqa: E402
from verdict.findings import FindingsStore  # noqa: E402
from verdict.mcp_client import MCPClient, PhaseRefusal  # noqa: E402

SMOKE = REPO_ROOT / "cases" / "smoke"
DECOY = SMOKE / "mimikatz.exe"
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
    def __init__(self, input_tokens=0, output_tokens=0,
                 cache_read_input_tokens=0, cache_creation_input_tokens=0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


class Block:
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
    """Pull a cite_seq out of the most recent tool_result in the history."""
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
    a Response. Records every kwargs dict received in `.calls` (deep-copied so
    the in-place message mutation across turns is captured at call time). A
    reactive step can read the live messages (e.g. the latest cite_seq).
    """

    def __init__(self, script):
        self._script = list(script)
        self._i = 0
        self.calls = []
        self.messages = self

    async def create(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        if self._i >= len(self._script):
            return Response([text_block("done")], "end_turn", Usage(10, 5))
        step = self._script[self._i]
        self._i += 1
        return step(kwargs)


# --------------------------------------------------------------- ui stub


class StubUI:
    def __init__(self):
        self.tool_lines = []
        self.narrations = []
        self.flips = []  # (finding_id, verdict, reason)
        self.findings = 0
        self.cost = 0.0

    def tool_line(self, tool, args=None, *, duration_s=None, sha=None,
                  total_cost=None, ts=None):
        self.tool_lines.append((tool, args, sha))

    def narration(self, text):
        self.narrations.append(text)

    def verdict_flip(self, finding_id, verdict, reason):
        self.flips.append((finding_id, verdict, reason))

    def update_status(self, *, findings=None, cost_usd=None):
        if findings is not None:
            self.findings = findings
        if cost_usd is not None:
            self.cost = cost_usd

    def start_status(self):
        pass

    def stop_status(self):
        pass


# ----------------------------------------------------- shared triage seed


def _seed_two_findings(fake_triage, client, store, ui, budget):
    """Run a scripted triage that records two real, cited findings.

    Returns nothing; mutates the store. Finding 1 cites a read_artifact of the
    decoy's real 12-byte content; finding 2 (the decoy claim) cites the same
    kind of evidence. Both cite real tool_result seqs so the server accepts
    them and so record_verdict (same process) can later find them.
    """

    async def go():
        client.set_phase("triage")
        inv = await client.call_tool("evidence_inventory", {})
        await run_triage(
            fake_triage, client, inventory_json=inv, budget_guard=budget,
            findings_store=store, terminal_ui=ui,
            config=LoopConfig(model="fake-model"))

    return go


def _triage_script_two():
    """Triage that reads the decoy, records F-001 (benign-ish) and F-002
    (the decoy capability claim), each citing a real read_artifact seq."""

    def t1(_kw):
        return Response(
            [text_block("Reading the decoy file content for two hypotheses."),
             tool_use_block("a1", "read_artifact",
                            {"path": str(DECOY), "length": 100})],
            "tool_use", Usage(1000, 200))

    def t2(kw):
        cite = _latest_cite_seq(kw["messages"])
        assert cite is not None
        return Response(
            [tool_use_block("a2", "record_finding",
                            {"claim": "A file named mimikatz.exe is present in "
                                      "the case folder (filename only).",
                             "severity": "low", "attack_id": "T1083",
                             "cites": [cite]})],
            "tool_use", Usage(800, 120))

    def t3(_kw):
        return Response(
            [tool_use_block("a3", "read_artifact",
                            {"path": str(DECOY), "length": 100})],
            "tool_use", Usage(800, 120))

    def t4(kw):
        cite = _latest_cite_seq(kw["messages"])
        assert cite is not None
        return Response(
            [tool_use_block("a4", "record_finding",
                            {"claim": "mimikatz.exe is a staged credential-"
                                      "dumping tool (credential access) that "
                                      "was tested on this host.",
                             "severity": "critical", "attack_id": "T1003.001",
                             "cites": [cite]})],
            "tool_use", Usage(900, 150))

    def t5(_kw):
        return Response([text_block("Two findings recorded; triage done.")],
                        "end_turn", Usage(400, 60))

    return [t1, t2, t3, t4, t5]


# ------------------------------------------------------ 1. happy path


def check_happy_path() -> None:
    """Two findings -> VERIFIED + REFUTED (decoy), verdicts in findings.json,
    verdict_recorded ledgered, verdict_flip fired."""

    # Verifier script: F-001 re-runs read_artifact then records VERIFIED;
    # F-002 (decoy) re-runs read_artifact, reads 12 bytes of ASCII -> REFUTED.
    def v_reread(tag, path):
        def step(_kw):
            return Response(
                [text_block(f"Re-running the cited evidence for {tag}."),
                 tool_use_block(f"{tag}r", "read_artifact",
                                {"path": path, "length": 100})],
                "tool_use", Usage(300, 60))
        return step

    def v_verdict(tag, fid, verdict, reason):
        def step(_kw):
            return Response(
                [tool_use_block(f"{tag}v", "record_verdict",
                                {"finding_id": fid, "verdict": verdict,
                                 "reason": reason})],
                "tool_use", Usage(200, 40))
        return step

    def v_end(_kw):
        return Response([text_block("verdict recorded")], "end_turn",
                        Usage(50, 10))

    # Two fresh conversations back-to-back (the verifier opens one per finding);
    # FakeAnthropic just serves the next step regardless of which conversation.
    verify_script = [
        v_reread("F-001", str(DECOY)),
        v_verdict("F-001", "F-001", "VERIFIED",
                  "Reproduced: a file by that name is present in the case dir."),
        v_end,
        v_reread("F-002", str(DECOY)),
        v_verdict("F-002", "F-002", "REFUTED",
                  "Filename implies a credential-theft tool; content is 12 "
                  "bytes of ASCII text, not an executable - no credential-"
                  "access capability."),
        v_end,
    ]

    ui = StubUI()

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)
                store = FindingsStore(run_dir)

                # seed two real findings via a scripted triage
                await _seed_two_findings(
                    FakeAnthropic(_triage_script_two()), client, store, ui,
                    budget)()
                assert len(store) == 2, len(store)

                # now the verifier
                await run_verifier(
                    FakeAnthropic(verify_script), client, run_dir=run_dir,
                    budget_guard=budget, findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))

            # every finding got a verdict in findings.json
            on_disk = {f["id"]: f for f in
                       json.loads(store.path.read_text(encoding="utf-8"))}
            assert on_disk["F-001"]["verdict"] == "VERIFIED", on_disk["F-001"]
            assert on_disk["F-002"]["verdict"] == "REFUTED", on_disk["F-002"]
            assert "12 bytes" in on_disk["F-002"]["verdict_reason"], \
                on_disk["F-002"]
            # the decoy flip is the wow moment
            verdicts = {fid: v for fid, v, _r in ui.flips}
            assert verdicts.get("F-002") == "REFUTED", ui.flips
            assert verdicts.get("F-001") == "VERIFIED", ui.flips
            # verdict_recorded ledger lines written for both
            ledger = [json.loads(l) for l in
                      (run_dir / "ledger.jsonl").read_text(
                          encoding="utf-8").splitlines() if l.strip()]
            recorded = {l["finding_id"]: l["verdict"] for l in ledger
                        if l["event"] == "verdict_recorded"}
            assert recorded == {"F-001": "VERIFIED", "F-002": "REFUTED"}, recorded

    asyncio.run(scenario())


# ------------------------------------------------------ 2. phase gate


def check_verify_phase_gate() -> None:
    """In the verify phase the client refuses record_finding and
    evidence_inventory WITHOUT hitting the server."""

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                ledger_path = run_dir / "ledger.jsonl"

                def ledger_len():
                    if not ledger_path.exists():
                        return 0
                    return sum(1 for l in ledger_path.read_text(
                        encoding="utf-8").splitlines() if l.strip())

                client.set_phase("verify")
                # record_finding is triage-only -> refused off-server
                before = ledger_len()
                try:
                    await client.call_tool("record_finding", {
                        "claim": "x", "severity": "high",
                        "attack_id": "T1059", "cites": [1]})
                except PhaseRefusal as exc:
                    assert "verify" in str(exc) and "record_finding" in str(exc)
                else:
                    raise AssertionError("record_finding allowed in verify")
                assert ledger_len() == before, "refused call touched the server"

                # evidence_inventory is triage-only -> refused off-server
                try:
                    await client.call_tool("evidence_inventory", {})
                except PhaseRefusal as exc:
                    assert "evidence_inventory" in str(exc), str(exc)
                else:
                    raise AssertionError("evidence_inventory allowed in verify")
                assert ledger_len() == before, "refused call touched the server"

                # record_verdict IS allowed through the gate (reaches server;
                # fails there for an unknown finding -> proves the gate passed it)
                raw = await client.call_tool("record_verdict", {
                    "finding_id": "F-999", "verdict": "VERIFIED",
                    "reason": "x"})
                assert "unknown finding_id" in raw or "F-999" in raw, raw

    asyncio.run(scenario())


# ------------------------------------------------------ 3. SHA drift


def check_sha_drift() -> None:
    """The verifier re-runs a cited query but the fresh output SHA differs from
    the cited SHA -> drift is detected and surfaced, not silently ignored.

    Deterministic mechanism: the cited evidence is read_artifact(length=100);
    the verifier re-runs read_artifact with a DIFFERENT length (the decoy is 12
    bytes, so length=5 returns fewer bytes -> a different output payload ->
    different output_sha256). Same tool, mismatching SHA == replay drift."""

    def t1(_kw):
        return Response(
            [tool_use_block("a1", "read_artifact",
                            {"path": str(DECOY), "length": 100})],
            "tool_use", Usage(900, 120))

    def t2(kw):
        cite = _latest_cite_seq(kw["messages"])
        assert cite is not None
        return Response(
            [tool_use_block("a2", "record_finding",
                            {"claim": "The decoy file content is exactly the "
                                      "full 12-byte string seen at offset 0.",
                             "severity": "low", "attack_id": "T1083",
                             "cites": [cite]})],
            "tool_use", Usage(700, 100))

    def t3(_kw):
        return Response([text_block("done")], "end_turn", Usage(300, 40))

    # verifier: re-run read_artifact with a DIFFERENT length (SHA will differ),
    # then (without mentioning drift) record VERIFIED. The orchestrator must
    # surface drift in the reason regardless.
    def vr(_kw):
        return Response(
            [tool_use_block("vr1", "read_artifact",
                            {"path": str(DECOY), "length": 5})],
            "tool_use", Usage(200, 40))

    def vv(_kw):
        return Response(
            [tool_use_block("vv1", "record_verdict",
                            {"finding_id": "F-001", "verdict": "VERIFIED",
                             "reason": "Content reproduced as described."})],
            "tool_use", Usage(150, 30))

    def ve(_kw):
        return Response([text_block("done")], "end_turn", Usage(50, 10))

    ui = StubUI()

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)
                store = FindingsStore(run_dir)
                client.set_phase("triage")
                inv = await client.call_tool("evidence_inventory", {})
                await run_triage(
                    FakeAnthropic([t1, t2, t3]), client, inventory_json=inv,
                    budget_guard=budget, findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))
                assert len(store) == 1, len(store)

                await run_verifier(
                    FakeAnthropic([vr, vv, ve]), client, run_dir=run_dir,
                    budget_guard=budget, findings_store=store, terminal_ui=ui,
                    config=LoopConfig(model="fake-model"))

            f = store.get("F-001")
            # drift surfaced somewhere: the recorded reason carries the note,
            # OR a drift narration line was emitted (not silently ignored).
            reason = f["verdict_reason"].lower()
            narrated = any("drift" in n.lower() for n in ui.narrations)
            assert ("drift" in reason or narrated), \
                (f["verdict_reason"], ui.narrations)

    asyncio.run(scenario())


def check_sha_drift_unit() -> None:
    """build_cited_entries + the drift compare on hand-built ledger records:
    a fresh SHA that differs from the cited SHA for the same tool is drift; an
    equal SHA is not."""
    from verdict.agent.verifier import _detect_drift

    records = [
        {"seq": 1, "event": "tool_called", "tool": "evtx_query",
         "params": {"log": "Security.evtx", "event_ids": [4624]}},
        {"seq": 2, "event": "tool_result", "tool": "evtx_query",
         "output_sha256": "a" * 64, "output_path": "outputs/0001_evtx_query.json"},
    ]
    entries = build_cited_entries(records, [2])
    assert len(entries) == 1, entries
    assert entries[0]["tool"] == "evtx_query"
    assert entries[0]["params"] == {"log": "Security.evtx",
                                    "event_ids": [4624]}, entries[0]
    assert entries[0]["output_sha256"] == "a" * 64

    matched: set[str] = set()
    # identical SHA -> no drift
    assert _detect_drift("evtx_query", "a" * 64, entries, matched) is None
    # differing SHA on the same tool -> drift note
    note = _detect_drift("evtx_query", "b" * 64, entries, matched)
    assert note is not None and "DRIFT" in note, note
    # a tool that was not cited -> ignored
    assert _detect_drift("registry_query", "c" * 64, entries, matched) is None


# ------------------------------------------------ 4. verify sub-budget


def check_verify_budget_degrades() -> None:
    """Usage exhausting verify_cap mid-pass -> remaining findings UNCONFIRMED
    (budget) and the pass ends gracefully (no crash, no blank verdicts)."""

    ui = StubUI()

    # verifier: F-001 re-runs then records a verdict with a HUGE usage that
    # blows past verify_cap; F-002 must then be marked UNCONFIRMED (budget)
    # WITHOUT any model turn (its verification is never opened).
    def vr(_kw):
        return Response(
            [tool_use_block("vr1", "read_artifact",
                            {"path": str(DECOY), "length": 50})],
            "tool_use", Usage(100, 20))

    def vv(_kw):
        # massive output usage -> pushes cumulative cost over verify_cap (4.50)
        return Response(
            [tool_use_block("vv1", "record_verdict",
                            {"finding_id": "F-001", "verdict": "VERIFIED",
                             "reason": "reproduced."})],
            "tool_use", Usage(input_tokens=0, output_tokens=1_000_000))

    def ve(_kw):
        return Response([text_block("done")], "end_turn", Usage(10, 5))

    def explode(_kw):
        raise AssertionError(
            "verifier opened a model turn for F-002 after the verify cap")

    async def scenario():
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(SMOKE, run_dir) as client:
                budget = BudgetGuard(5.00)  # verify_cap == 4.50
                store = FindingsStore(run_dir)

                await _seed_two_findings(
                    FakeAnthropic(_triage_script_two()), client, store, ui,
                    budget)()
                assert len(store) == 2, len(store)

                # F-001 verification spends > verify_cap; F-002 must degrade.
                await run_verifier(
                    FakeAnthropic([vr, vv, ve, explode]), client,
                    run_dir=run_dir, budget_guard=budget, findings_store=store,
                    terminal_ui=ui, config=LoopConfig(model="fake-model"))

            on_disk = {f["id"]: f for f in
                       json.loads(store.path.read_text(encoding="utf-8"))}
            # F-001 got its real verdict
            assert on_disk["F-001"]["verdict"] == "VERIFIED", on_disk["F-001"]
            # F-002 degraded to UNCONFIRMED (budget) - never blank
            assert on_disk["F-002"]["verdict"] == "UNCONFIRMED", on_disk["F-002"]
            assert "budget" in on_disk["F-002"]["verdict_reason"].lower(), \
                on_disk["F-002"]
            # no blank verdicts anywhere
            assert all(f["verdict"] for f in on_disk.values()), on_disk
            # the budget degradation note was recorded for the report
            assert any("verify_budget_exhausted" in n for n in budget.notes), \
                budget.notes
            # both findings flipped on the terminal (the budget one too)
            flipped = {fid for fid, _v, _r in ui.flips}
            assert {"F-001", "F-002"} <= flipped, ui.flips

    asyncio.run(scenario())


# ----------------------------------------------------------------- harness


def main() -> int:
    checks = [
        ("happy path: two findings -> VERIFIED + decoy REFUTED; findings.json "
         "+ verdict_recorded + verdict_flip", check_happy_path),
        ("phase gate: verify refuses record_finding + evidence_inventory "
         "off-server; record_verdict passes through", check_verify_phase_gate),
        ("SHA drift: re-run SHA differs from cited SHA -> surfaced, not silent",
         check_sha_drift),
        ("SHA drift (unit): build_cited_entries + _detect_drift compare",
         check_sha_drift_unit),
        ("verify sub-budget: cap mid-pass -> remaining UNCONFIRMED (budget), "
         "graceful, no blank verdicts", check_verify_budget_degrades),
    ]
    for name, fn in checks:
        run_check(name, fn)
    total, failed = len(checks), len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed"
          + (f" - FAILED: {', '.join(FAILURES)}" if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
