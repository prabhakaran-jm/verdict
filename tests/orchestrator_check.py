"""Orchestrator check for checklist item 6 - CLI, MCP client, terminal UI.

Plain stdlib (no pytest), same style as tools_check.py / foundation_check.py.
Exercises, on Windows or Linux:

  1. case validation (verdict.cli.validate_case_dir):
       - a tempdir with one loose artifact (a registry hive) -> valid
       - an empty tempdir -> CaseValidationError (the exit-1 path), clear message
       - a nonexistent path -> CaseValidationError, clear message
       - a folder of only-"other" files -> CaseValidationError (not evidence)

  2. run-folder creation (verdict.cli.create_run_dir):
       - creates runs/<ts>/ with outputs/ artifacts/ scratch/ bodyfile/
       - a second call yields a DIFFERENT folder (never overwrites a prior run)

  3. mcp_client end-to-end against the REAL server subprocess pointed at
     cases/smoke/:
       - initialize + list_tools -> the 13 MODEL tools, NOT _log_event
       - call evidence_inventory -> a sensible stringified result
       - schema serialization is byte-identical across two independent
         conversions (the cache-stability assertion the agent loop relies on)
       - phase gate: phase "verify" + record_finding -> refused WITHOUT hitting
         the server; phase "triage" + record_finding -> allowed through the gate
         (it then fails server-side on a bad cite, proving the gate let it pass)

  4. terminal.py: instantiate TerminalUI on a StringIO console, drive every
     render method with sample data (no exceptions; output captured).

Run:  python tests/orchestrator_check.py
Prints PASS/FAIL per check; exits nonzero on any FAIL. Spawns the real
verdict_mcp server over stdio - no forensic binaries needed, evidence_inventory
is pure Python.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
import tempfile
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from rich.console import Console  # noqa: E402

from verdict.cli import (  # noqa: E402
    CaseValidationError,
    RUN_SUBDIRS,
    create_run_dir,
    validate_case_dir,
)
from verdict.mcp_client import (  # noqa: E402
    MCPClient,
    PhaseRefusal,
    canonical_tool_json,
)

FAILURES: list[str] = []

#: regf magic so inventory.classify() recognizes a registry hive without a real
#: hive on disk (matches tools_check.py's fixtures).
_REGF = b"regf" + b"\x00" * 124


def run_check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        FAILURES.append(name)
        print(f"FAIL  {name}")
        print("      " + traceback.format_exc().strip().replace("\n", "\n      "))
    else:
        print(f"PASS  {name}")


# ----------------------------------------------------- 1. case validation


def check_case_validation() -> None:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)

        # valid: one recognized loose artifact (a registry hive)
        valid_case = base / "valid"
        valid_case.mkdir()
        (valid_case / "SOFTWARE").write_bytes(_REGF)
        resolved = validate_case_dir(valid_case)
        assert resolved == valid_case.resolve(), resolved

        # empty tempdir -> exit-1 path, clear message
        empty_case = base / "empty"
        empty_case.mkdir()
        try:
            validate_case_dir(empty_case)
        except CaseValidationError as exc:
            assert "no recognized evidence" in str(exc), str(exc)
        else:
            raise AssertionError("empty case folder was accepted")

        # nonexistent path -> exit-1 path, clear message
        missing = base / "does-not-exist"
        try:
            validate_case_dir(missing)
        except CaseValidationError as exc:
            assert "does not exist" in str(exc), str(exc)
        else:
            raise AssertionError("nonexistent case folder was accepted")

        # folder of only-"other" files is NOT evidence (honest empty case)
        junk_case = base / "junk"
        junk_case.mkdir()
        (junk_case / "notes.txt").write_bytes(b"just some text, not evidence")
        try:
            validate_case_dir(junk_case)
        except CaseValidationError as exc:
            assert "no recognized evidence" in str(exc), str(exc)
        else:
            raise AssertionError("all-'other' case folder was accepted")


def check_smoke_case_is_valid() -> None:
    # The bundled smoke case must validate - it's the judge/host smoke path.
    resolved = validate_case_dir(REPO_ROOT / "cases" / "smoke")
    assert resolved.is_dir()


# ------------------------------------------------- 2. run-folder creation


def check_run_folder_creation() -> None:
    with tempfile.TemporaryDirectory() as td:
        parent = Path(td) / "runs"
        run1 = create_run_dir(parent)
        assert run1.is_dir(), run1
        assert run1.parent == parent.resolve()
        # timestamp shape yyyymmddTHHMMSSZ (optionally -NN on collision)
        stem = run1.name.split("-")[0]
        assert len(stem) == len("20260612T120000Z"), run1.name
        assert stem.endswith("Z") and "T" in stem, run1.name
        for sub in RUN_SUBDIRS:
            assert (run1 / sub).is_dir(), f"missing subdir {sub} in {run1}"

        # a second call must yield a DIFFERENT folder - never overwrite a prior
        # run trail (prd.md > Audit Ledger). Even within the same UTC second the
        # disambiguation suffix guarantees uniqueness.
        run2 = create_run_dir(parent)
        assert run2 != run1, f"second run reused the folder: {run1}"
        assert run2.is_dir()
        # both still exist, untouched
        assert run1.is_dir() and run2.is_dir()


# --------------------------------------------- 3. mcp_client end-to-end


def check_mcp_client_end_to_end() -> None:
    smoke = REPO_ROOT / "cases" / "smoke"

    async def scenario() -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(smoke, run_dir) as client:
                # --- initialize + list_tools: 13 model tools, NOT _log_event
                client.set_phase("triage")
                triage_tools = client.list_anthropic_tools()
                client.set_phase("verify")
                verify_tools = client.list_anthropic_tools()
                all_names = {t["name"] for t in triage_tools} | \
                    {t["name"] for t in verify_tools}
                assert "_log_event" not in all_names, \
                    "control-plane tool leaked into the model's tool list"
                assert all_names == {
                    "evidence_inventory", "fs_list", "fs_extract", "mft_query",
                    "evtx_query", "registry_query", "execution_evidence",
                    "timeline_query", "mem_analyze", "yara_scan",
                    "read_artifact", "record_finding", "record_verdict",
                }, f"unexpected model tool set: {sorted(all_names)}"
                # Anthropic tool shape is correct.
                for tool in triage_tools:
                    assert set(tool) == {"name", "description", "input_schema"}, tool
                    assert isinstance(tool["input_schema"], dict)

                # phase filtering: record_finding triage-only, record_verdict
                # verify-only, evidence_inventory not in verify.
                triage_names = {t["name"] for t in triage_tools}
                verify_names = {t["name"] for t in verify_tools}
                assert "record_finding" in triage_names
                assert "record_finding" not in verify_names
                assert "record_verdict" in verify_names
                assert "record_verdict" not in triage_names
                assert "evidence_inventory" in triage_names
                assert "evidence_inventory" not in verify_names

                # --- call evidence_inventory -> sensible stringified result
                client.set_phase("triage")
                raw = await client.call_tool("evidence_inventory", {})
                assert isinstance(raw, str), type(raw)
                inv = json.loads(raw)
                assert inv["is_error"] is False, inv
                assert inv["total_files"] >= 1, inv
                paths = {f["path"] for f in inv["files"]}
                # the smoke case ships these (cases/smoke/)
                assert "Security.evtx" in paths, sorted(paths)
                assert "NTUSER.DAT" in paths, sorted(paths)
                by_path = {f["path"]: f for f in inv["files"]}
                assert by_path["Security.evtx"]["type"] == "evtx"
                assert by_path["NTUSER.DAT"]["type"] == "registry_hive"

                # --- cache-stability: two INDEPENDENT conversions byte-identical.
                # Re-list and re-convert in a fresh client; the serialized tools
                # array must match byte for byte (spec.md > Agent loop > Prompt
                # caching - the cache prefix keys on these exact bytes).
                first_blob = canonical_tool_json(client.list_anthropic_tools("triage"))

            # second, fully independent server process + conversion
            run_dir2 = create_run_dir(Path(td) / "runs2")
            async with MCPClient(smoke, run_dir2) as client2:
                client2.set_phase("triage")
                second_blob = canonical_tool_json(
                    client2.list_anthropic_tools("triage"))
            assert first_blob == second_blob, (
                "tool-schema serialization is NOT byte-stable across "
                "processes - prompt caching would break")

    asyncio.run(scenario())


def check_phase_gate_double() -> None:
    smoke = REPO_ROOT / "cases" / "smoke"

    async def scenario() -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = create_run_dir(Path(td) / "runs")
            async with MCPClient(smoke, run_dir) as client:
                ledger_path = run_dir / "ledger.jsonl"

                def ledger_len() -> int:
                    if not ledger_path.exists():
                        return 0
                    return sum(1 for line in
                               ledger_path.read_text(encoding="utf-8").splitlines()
                               if line.strip())

                # phase "verify": record_finding is NOT allowed -> refused
                # WITHOUT hitting the server (no new ledger line written).
                client.set_phase("verify")
                before = ledger_len()
                try:
                    await client.call_tool("record_finding", {
                        "claim": "x", "severity": "high",
                        "attack_id": "T1059", "cites": [1]})
                except PhaseRefusal as exc:
                    assert "verify" in str(exc), str(exc)
                    assert "record_finding" in str(exc), str(exc)
                else:
                    raise AssertionError(
                        "record_finding was NOT refused in the verify phase")
                after = ledger_len()
                assert after == before, (
                    f"refused call still touched the server "
                    f"(ledger grew {before}->{after})")

                # phase "triage": record_finding IS allowed through the gate.
                # It then fails server-side (cite 999999 isn't a tool_result),
                # which proves the gate let the call REACH the server - the
                # server's own rejection is the second half of the double gate.
                #
                # Wire behavior worth noting for item 7: over stdio, a server
                # ToolError comes back as a CallToolResult(isError=True) whose
                # content is the error text - the SDK's call_tool does NOT raise
                # on the client side (unlike the in-process app.call_tool used
                # in tools_check.py). So a NON-PhaseRefusal outcome here proves
                # the gate passed the call through; we then confirm the server
                # rejected it (returned reason + tool_rejected ledger line).
                client.set_phase("triage")
                before_triage = ledger_len()
                try:
                    raw = await client.call_tool("record_finding", {
                        "claim": "x", "severity": "high",
                        "attack_id": "T1059", "cites": [999999]})
                except PhaseRefusal:
                    raise AssertionError(
                        "record_finding was wrongly gated in the triage phase")
                # the gate passed it through; the server rejected it server-side
                assert "tool_result" in raw or "cite" in raw, \
                    f"unexpected server reply: {raw!r}"
                lines = [json.loads(l) for l in
                         ledger_path.read_text(encoding="utf-8").splitlines()
                         if l.strip()]
                rejected = [l for l in lines if l["event"] == "tool_rejected"
                            and l["tool"] == "record_finding"]
                assert rejected, (
                    "triage record_finding reached the server but no "
                    "tool_rejected line was written")
                assert ledger_len() > before_triage, (
                    "triage call did not reach the server (ledger unchanged)")

    asyncio.run(scenario())


# ------------------------------------------------------- 4. terminal.py


def check_terminal_ui() -> None:
    from verdict.terminal import TerminalUI

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=100,
                      color_system=None)
    ui = TerminalUI(console=console)

    # inventory table
    ui.inventory_table(
        [{"path": "Security.evtx", "type": "evtx", "size": 1024,
          "sha256": "ab12cd34" * 8},
         {"path": "mimikatz.exe", "type": "other", "size": 12,
          "sha256": "ffff0000" * 8}],
        case_dir="/cases/smoke",
        counts={"evtx": 1, "other": 1},
    )
    ui.plan("triage across the kill chain -> verify -> report")

    # status bar lifecycle + tool lines + narration above it
    ui.start_status()
    ui.update_status(findings=0, cost_usd=0.0)
    ui.tool_line("evtx_query", {"log": "C:\\evt\\Security.evtx",
                                "event_ids": [4624]},
                 duration_s=1.2, sha="ab12cd34ef", total_cost=0.43, ts="09:14:03")
    ui.narration("Service install at 09:10 points at a Run-key persistence path; "
                 "pivoting to the registry.")
    ui.update_status(findings=2, cost_usd=0.87)
    ui.tool_line("registry_query", {"hive": "NTUSER.DAT", "plugin": "run_keys"},
                 duration_s=0.4, sha="9988aabb")

    # verdict flips - one of each color path
    ui.verdict_flip("F-001", "VERIFIED", "reproduced from cited 7045 + prefetch")
    ui.verdict_flip("F-002", "REFUTED",
                    "filename suggests mimikatz; content is 12 bytes of ASCII text")
    ui.verdict_flip("F-003", "UNCONFIRMED", "tool output ambiguous; no contradiction")
    ui.verdict_flip("F-004", "BOGUS", "unknown verdict must not crash the demo")

    # completion summary (also stops the status bar) + empty-findings path
    ui.summary_table(
        [{"finding_id": "F-002", "severity": "critical", "attack_id": "T1003",
          "verdict": "REFUTED", "claim": "decoy credential tool present"},
         {"finding_id": "F-001", "severity": "high", "attack_id": "T1543.003",
          "verdict": "VERIFIED", "claim": "service persistence via update.exe"},
         {"finding_id": "F-003", "severity": "low", "attack_id": "T1059",
          "verdict": "UNCONFIRMED", "claim": "ambiguous shell activity"}],
        artifacts={"report.html": "/runs/x/report.html",
                   "ledger.jsonl": "/runs/x/ledger.jsonl"},
    )

    out = buffer.getvalue()
    # output sanity: the load-bearing strings made it to the console
    assert "Evidence inventory" in out, out
    assert "Security.evtx" in out, out
    assert "evtx_query" in out, out
    assert "09:14:03" in out, out
    assert "$0.43" in out, out
    assert "Security.evtx" in out  # path basenamed in tool_line, full in table
    assert "REFUTED" in out and "VERIFIED" in out and "UNCONFIRMED" in out, out
    assert "Findings summary" in out, out
    assert "F-002" in out and "F-001" in out, out
    assert "report.html" in out, out

    # honest empty report path renders without exceptions
    buffer2 = io.StringIO()
    ui2 = TerminalUI(console=Console(file=buffer2, force_terminal=False,
                                     width=100, color_system=None))
    ui2.summary_table([], artifacts=None)
    assert "no findings" in buffer2.getvalue(), buffer2.getvalue()


# ----------------------------------------------------------------- harness


def main() -> int:
    checks = [
        ("case validation: valid / empty / missing / all-other folders",
         check_case_validation),
        ("case validation: bundled cases/smoke validates",
         check_smoke_case_is_valid),
        ("run folder: <ts>/ + subdirs; second call never overwrites",
         check_run_folder_creation),
        ("mcp_client: real server, 13 model tools (no _log_event), inventory, "
         "byte-stable schema", check_mcp_client_end_to_end),
        ("mcp_client: phase double gate - verify refuses record_finding "
         "off-server; triage passes it through", check_phase_gate_double),
        ("terminal: tool line / narration / status bar / verdict flip / summary",
         check_terminal_ui),
    ]
    for name, fn in checks:
        run_check(name, fn)
    total, failed = len(checks), len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed"
          + (f" - FAILED: {', '.join(FAILURES)}" if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
