"""Foundation check for checklist item 3 - ledger / pathguard / runner / server.

Plain stdlib (no pytest). Exercises, on Windows or Linux:
  1. ledger writes all 10 event types; lines parse as JSON; seq monotonic
  2. kill-mid-write: hard-kill a child writing ledger lines; the file on disk
     is valid JSONL up to the kill point (prd.md > Audit Ledger)
  3. pathguard: read inside case/run OK; reads/writes outside refused;
     ..\\..\\ traversal, shared-prefix sibling, and symlink escapes refused
  4. runner: full output file + SHA-256 + 8 KiB excerpt + truncated flag +
     tool_called/tool_result ledger pair (filename seq == tool_called seq)
  5. runner error paths: nonzero exit and timeout -> is_error, ledgered
  6. character-safe UTF-8 truncation at the 8192-byte boundary
  7. server skeleton: _log_event control plane writes through the ledger

Run:  python tests/foundation_check.py
Prints PASS/FAIL per check; exits nonzero on any FAIL.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from verdict_mcp.ledger import EVENT_TYPES, Ledger  # noqa: E402
from verdict_mcp.pathguard import PathGuard, PathViolation  # noqa: E402
from verdict_mcp.runner import EXCERPT_CAP_BYTES, Runner, _excerpt  # noqa: E402

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

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


def read_ledger_lines(run_dir: Path) -> list[dict]:
    text = (run_dir / "ledger.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# --------------------------------------------------------------- 1. ledger


def check_ledger_all_events() -> None:
    with tempfile.TemporaryDirectory() as td:
        run = Path(td)
        with Ledger(run, "testrun") as led:
            led.write("run_started", case_dir="cases/smoke", budget_usd=5.0)
            called_seq = led.tool_called("evtx_query",
                                         {"log": "Security.evtx", "limit": 50})
            led.tool_result("evtx_query", duration_ms=1180,
                            output_sha256="ab12" * 16,
                            output_path="outputs/0002_evtx_query.json",
                            truncated=True, exit_code=0)
            led.tool_rejected("read_artifact",
                              "read of path='../../etc/shadow' refused")
            led.write("finding_recorded", finding_id="F1",
                      claim="persistence via run key", severity="high",
                      attack_id="T1547.001", cites=[3])
            led.write("verdict_recorded", finding_id="F1", verdict="VERIFIED",
                      reason="reproduced from cited hive")
            led.write("api_usage", input_tokens=1200, output_tokens=300,
                      cache_read_tokens=900, cost_usd=0.012)
            led.write("budget_event", kind="triage_soft_cap",
                      spent_usd=3.0, budget_usd=5.0)
            led.write("run_interrupted", reason="api outage")
            led.write("run_ended", findings=1, total_cost_usd=3.21)

            assert called_seq == 2, f"tool_called seq {called_seq} != 2"
            # unknown event types and reserved-key collisions must be refused
            for bad_call in (lambda: led.write("made_up_event"),
                             lambda: led.write("api_usage", seq=999)):
                try:
                    bad_call()
                except ValueError:
                    pass
                else:
                    raise AssertionError("invalid write() was accepted")

        lines = read_ledger_lines(run)
        assert len(lines) == 10, f"expected 10 lines, got {len(lines)}"
        events_seen = {rec["event"] for rec in lines}
        assert events_seen == set(EVENT_TYPES), (
            f"missing event types: {set(EVENT_TYPES) - events_seen}")
        for i, rec in enumerate(lines):
            assert rec["seq"] == i + 1, f"seq not monotonic at line {i + 1}"
            assert rec["run_id"] == "testrun"
            assert TS_RE.match(rec["ts"]), f"bad ts format: {rec['ts']}"
        result = next(r for r in lines if r["event"] == "tool_result")
        assert result["exit_code"] == 0 and result["truncated"] is True


# -------------------------------------------------------- 2. kill-mid-write

CHILD_SRC = """
import sys
sys.path.insert(0, {root!r})
from verdict_mcp.ledger import Ledger
led = Ledger({run!r}, "killrun")
i = 0
while True:
    i += 1
    led.write("budget_event", note="line %d" % i)
"""


def check_ledger_survives_kill() -> None:
    with tempfile.TemporaryDirectory() as td:
        run = Path(td)
        src = CHILD_SRC.format(root=str(REPO_ROOT), run=str(run))
        proc = subprocess.Popen([sys.executable, "-c", src],
                                stderr=subprocess.PIPE)
        ledger_path = run / "ledger.jsonl"
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    err = (proc.stderr.read() or b"").decode(errors="replace")
                    raise AssertionError(f"child died on its own: {err[:500]}")
                if ledger_path.exists() and ledger_path.stat().st_size > 4096:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("child never wrote 4 KiB of ledger")
        finally:
            proc.kill()  # hard kill: TerminateProcess on Windows, SIGKILL on Linux
            proc.wait(timeout=10)

        raw = ledger_path.read_bytes()
        assert raw, "ledger.jsonl is empty after kill"
        body, _, tail = raw.rpartition(b"\n")
        # tail (bytes after the last newline) may be a torn final line from the
        # kill landing mid-write; every newline-terminated line must be valid.
        complete = body.split(b"\n") if body else []
        assert len(complete) >= 10, f"only {len(complete)} complete lines"
        for i, line in enumerate(complete):
            rec = json.loads(line)  # raises -> FAIL: corruption before the kill
            assert rec["seq"] == i + 1, f"seq gap at line {i + 1}"
            assert rec["event"] == "budget_event"
        print(f"      [kill test: {len(complete)} intact lines, "
              f"{len(tail)} torn trailing bytes]")


# ------------------------------------------------------------ 3. pathguard


def check_pathguard() -> None:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        case = base / "caseroot"
        evil = base / "caseroot-evil"  # sibling sharing a string prefix
        run = base / "runfolder"
        run_evil = base / "runfolder-evil"
        for d in (case, evil, run, run_evil, run / "outputs"):
            d.mkdir(parents=True)
        (case / "evidence.bin").write_bytes(b"evidence")
        (evil / "secret.txt").write_bytes(b"secret")
        (run / "outputs" / "0001_x.txt").write_bytes(b"output")

        guard = PathGuard(case, run)

        # allowed reads: case dir, run dir (verifier re-reads stored outputs)
        assert guard.resolve_read(case / "evidence.bin").name == "evidence.bin"
        assert guard.resolve_read(str(case / "sub" / ".." / "evidence.bin"))
        assert guard.resolve_read(run / "outputs" / "0001_x.txt")
        # allowed writes: run dir only
        assert guard.resolve_write(run / "outputs" / "new.json")

        traversal_read = os.path.join(str(case), "..", "caseroot-evil",
                                      "secret.txt")
        traversal_write = os.path.join(str(run), "..", "..", "anywhere.txt")
        refused = [
            ("read outside both roots", lambda: guard.resolve_read(base / "x")),
            ("read sibling shared-prefix dir",
             lambda: guard.resolve_read(evil / "secret.txt")),
            ("read ..\\..\\ traversal escape",
             lambda: guard.resolve_read(traversal_read)),
            ("read raw string prefix trick",
             lambda: guard.resolve_read(str(case) + "-evil")),
            ("write into evidence dir",
             lambda: guard.resolve_write(case / "implant.txt")),
            ("write outside run dir", lambda: guard.resolve_write(base / "x")),
            ("write ..\\..\\ traversal escape",
             lambda: guard.resolve_write(traversal_write)),
            ("write run-dir shared-prefix sibling",
             lambda: guard.resolve_write(run_evil / "x.txt")),
        ]
        for label, attempt in refused:
            try:
                attempt()
            except PathViolation as exc:
                assert str(exc), f"{label}: empty violation message"
            else:
                raise AssertionError(f"{label}: was NOT refused")

        # symlink escape (needs privilege on Windows; skip gracefully if denied)
        link = case / "link_out"
        try:
            os.symlink(evil / "secret.txt", link)
        except (OSError, NotImplementedError):
            print("      [symlink escape: creation not permitted on this host "
                  "- skipped; traversal/prefix escapes covered above]")
        else:
            try:
                guard.resolve_read(link)
            except PathViolation:
                pass
            else:
                raise AssertionError("symlink escape was NOT refused")


# -------------------------------------------------------------- 4. runner


def _make_runner(run: Path) -> tuple[Runner, Ledger]:
    led = Ledger(run, "runnertest")
    runner = Runner(run, led, extra_argv={
        # test-only capability entries: fixed, harmless argv prefixes
        "echo_test": (sys.executable, "-c", "print('x' * 20000)"),
        "fail_test": (sys.executable, "-c",
                      "import sys; sys.stderr.write('boom: parser exploded'); "
                      "print('partial'); sys.exit(3)"),
        "sleep_test": (sys.executable, "-c", "import time; time.sleep(30)"),
    })
    return runner, led


def check_runner_success() -> None:
    with tempfile.TemporaryDirectory() as td:
        run = Path(td)
        runner, led = _make_runner(run)
        with led:
            res = runner.run_tool("echo_test", [], params={"demo": True})

            assert not res.is_error and res.exit_code == 0
            # output file named by the tool_called seq, zero-padded to 4
            expected_name = f"{res.seq:04d}_echo_test.txt"
            assert res.output_path.name == expected_name, res.output_path.name
            assert res.output_rel == f"outputs/{expected_name}"
            data = res.output_path.read_bytes()
            assert data.rstrip(b"\r\n") == b"x" * 20000, "full output mangled"
            assert res.output_sha256 == hashlib.sha256(data).hexdigest()
            assert res.truncated is True
            excerpt_bytes = len(res.excerpt.encode("utf-8"))
            assert excerpt_bytes <= EXCERPT_CAP_BYTES, excerpt_bytes
            assert res.excerpt == "x" * EXCERPT_CAP_BYTES
            payload = res.payload()
            assert payload["truncated"] and payload["output_path"] == res.output_rel

        lines = read_ledger_lines(run)
        called = next(r for r in lines if r["event"] == "tool_called")
        result = next(r for r in lines if r["event"] == "tool_result")
        assert called["seq"] == res.seq and called["tool"] == "echo_test"
        assert called["params"] == {"demo": True}
        assert result["seq"] == res.result_seq
        assert result["exit_code"] == 0
        assert result["output_path"] == res.output_rel
        assert result["output_sha256"] == res.output_sha256
        assert result["truncated"] is True
        assert "is_error" not in result


def check_runner_errors() -> None:
    with tempfile.TemporaryDirectory() as td:
        run = Path(td)
        runner, led = _make_runner(run)
        with led:
            # nonzero exit -> structured error result, still ledgered
            res = runner.run_tool("fail_test", [])
            assert res.is_error and res.exit_code == 3
            assert "boom" in res.stderr_excerpt
            assert res.truncated is False
            assert res.output_path.exists()  # partial stdout still persisted
            payload = res.payload()
            assert payload["is_error"] and "boom" in payload["stderr"]

            # timeout -> killed, is_error, exit_code None, timed_out ledgered
            t0 = time.monotonic()
            slow = runner.run_tool("sleep_test", [], timeout_s=1)
            assert time.monotonic() - t0 < 15, "timeout did not trigger"
            assert slow.is_error and slow.timed_out and slow.exit_code is None
            assert "timed out" in (slow.error or "")

        lines = read_ledger_lines(run)
        results = [r for r in lines if r["event"] == "tool_result"]
        assert len(results) == 2
        assert results[0]["exit_code"] == 3 and results[0]["is_error"] is True
        assert results[1]["timed_out"] is True and results[1]["is_error"] is True
        assert results[1]["exit_code"] is None


# ------------------------------------------- 5. character-safe truncation


def check_excerpt_truncation() -> None:
    # 3-byte char so the 8192-byte cap lands mid-character (8192 % 3 != 0)
    data = ("✓" * 4000).encode("utf-8")  # 12000 bytes
    text, truncated = _excerpt(data)
    assert truncated is True
    encoded = len(text.encode("utf-8"))
    assert encoded <= EXCERPT_CAP_BYTES, encoded
    assert "�" not in text, "truncation split a UTF-8 character"
    assert set(text) == {"✓"}
    # under the cap: untouched
    text2, truncated2 = _excerpt(b"hello")
    assert text2 == "hello" and truncated2 is False


# ------------------------------------------------------ 6. server skeleton


def check_server_skeleton() -> None:
    from verdict_mcp.server import build_app

    with tempfile.TemporaryDirectory() as case_td, \
            tempfile.TemporaryDirectory() as run_td:
        app, ctx = build_app(case_td, run_td)
        try:
            tools = asyncio.run(app.list_tools())
            names = [t.name for t in tools]
            # Item 3 shipped only _log_event; items 4/10 register the model
            # tools. The skeleton check cares that the control plane exists.
            assert "_log_event" in names, (
                f"_log_event control plane missing; registered: {names}")

            asyncio.run(app.call_tool("_log_event", {
                "event": "api_usage",
                "payload": {"input_tokens": 1200, "output_tokens": 300,
                            "cache_read_tokens": 900, "cost_usd": 0.012},
            }))
            lines = read_ledger_lines(Path(run_td))
            assert len(lines) == 1 and lines[0]["event"] == "api_usage"
            assert lines[0]["cost_usd"] == 0.012 and lines[0]["seq"] == 1

            # tool-side events are NOT accepted on the control plane
            try:
                asyncio.run(app.call_tool("_log_event",
                                          {"event": "tool_called"}))
            except Exception:
                pass
            else:
                raise AssertionError("_log_event accepted a tool-side event")
            assert len(read_ledger_lines(Path(run_td))) == 1

            # invalid dirs are refused before any ledger exists
            try:
                build_app(Path(case_td) / "nope", run_td)
            except ValueError:
                pass
            else:
                raise AssertionError("build_app accepted a missing --case dir")
        finally:
            ctx.ledger.close()


# ----------------------------------------------------------------- harness


def main() -> int:
    checks = [
        ("ledger: all event types, JSON lines, monotonic seq, Z timestamps",
         check_ledger_all_events),
        ("ledger: intact JSONL after hard kill mid-write",
         check_ledger_survives_kill),
        ("pathguard: containment, traversal/prefix/symlink escapes refused",
         check_pathguard),
        ("runner: full output + sha256 + 8KiB excerpt + ledger pair",
         check_runner_success),
        ("runner: nonzero exit + timeout -> structured errors, ledgered",
         check_runner_errors),
        ("runner: character-safe UTF-8 excerpt truncation",
         check_excerpt_truncation),
        ("server: _log_event control plane writes through the single ledger writer",
         check_server_skeleton),
    ]
    for name, fn in checks:
        run_check(name, fn)
    total, failed = len(checks), len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed"
          + (f" - FAILED: {', '.join(FAILURES)}" if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
