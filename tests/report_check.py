"""Report-generator check for checklist item 9.

Plain stdlib + asyncio (no pytest), same style as verifier_check.py /
agent_check.py. CRITICAL: NO real Anthropic API calls and NO ANTHROPIC_API_KEY
required - a FakeAnthropic returns scripted prose (executive summary + attack
narrative as the JSON the prose contract specifies). The single real end-to-end
smoke run is the learner's job on the SIFT VM.

Each check builds a self-contained runs/<id>/ dir on disk (findings.json +
ledger.jsonl + a couple of outputs/<seq>_<tool>.* files to excerpt), drives
generate_report with a fake prose client, and asserts the produced report.html.

Checks:
  1. mixed run: VERIFIED + UNCONFIRMED + REFUTED. report.html is ONE
     self-contained file (no <script src>, no external <link> stylesheet, inline
     <style> only); the findings table has the VERIFIED+UNCONFIRMED rows and NOT
     the REFUTED one; Appendix A contains the REFUTED finding + its
     verdict_reason; every finding cite seq renders as href="#ledger-<seq>" AND a
     matching id="ledger-<seq>" exists in the embedded ledger (citations resolve
     offline); Appendix D methodology text present; header shows cost + model;
     the fake prose (summary + footnoted narrative) is rendered.
  2. clean case: zero findings -> valid HTML, exec summary / clean statement
     present, empty findings table rendered (no exception), appendices present.
  3. PDF chain: attempt_pdf with no chromium/wkhtmltopdf on PATH returns None and
     logs the manual-fallback message WITHOUT raising (report.html untouched).
  4. budget note: a budget_event ledger line surfaces a one-line note.

Run:  python tests/report_check.py
Prints PASS/FAIL per check; exits nonzero on any FAIL.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from verdict.report.generator import (  # noqa: E402
    PDF_MANUAL_FALLBACK,
    attempt_pdf,
    generate_report,
)

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


class Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class Response:
    def __init__(self, content):
        self.content = content
        self.stop_reason = "end_turn"
        self.usage = None


class FakeAnthropic:
    """Scripted async messages.create returning canned prose; records calls.

    `prose` is the dict the prose contract asks for; we serialize it into a
    single text block. Records each create() kwargs in `.calls`.
    """

    def __init__(self, prose: dict | None):
        self._prose = prose
        self.calls: list[dict] = []
        self.messages = self

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._prose is None:
            return Response([Block(type="text", text="")])
        return Response([Block(type="text",
                               text=json.dumps(self._prose))])


# --------------------------------------------------------- run-dir builder


def _write_run(td: Path) -> Path:
    """Build a realistic run dir: outputs + ledger + findings.json. Returns it."""
    run_dir = td / "20260613T000000Z"
    (run_dir / "outputs").mkdir(parents=True)

    # Two stored tool outputs the findings will excerpt.
    (run_dir / "outputs" / "0002_evidence_inventory.json").write_text(
        json.dumps({
            "case_dir": "C:/cases/smoke", "total_files": 2,
            "counts": {"registry_hive": 1, "other": 1},
            "files": [
                {"path": "NTUSER.DAT", "type": "registry_hive", "size": 8192,
                 "sha256": "f" * 64},
                {"path": "mimikatz.exe", "type": "other", "size": 12,
                 "sha256": "a" * 64},
            ],
        }), encoding="utf-8")
    (run_dir / "outputs" / "0004_registry_query.json").write_text(
        json.dumps({"plugin": "run_keys", "output_sha256": "c" * 64,
                    "hits": [{"value": "update",
                              "data": "C:/Users/Public/update.exe"}]}),
        encoding="utf-8")
    (run_dir / "outputs" / "0006_read_artifact.json").write_text(
        json.dumps({"path": "mimikatz.exe", "returned_bytes": 12,
                    "mode": "text", "content": "hello world\n",
                    "output_sha256": "d" * 64}), encoding="utf-8")

    ledger = [
        {"seq": 1, "ts": "2026-06-13T00:00:00Z", "run_id": run_dir.name,
         "event": "run_started", "case_dir": "C:/cases/smoke",
         "budget_usd": 5.0, "model": "claude-sonnet-4-6"},
        {"seq": 2, "ts": "2026-06-13T00:00:01Z", "run_id": run_dir.name,
         "event": "tool_result", "tool": "evidence_inventory",
         "output_sha256": "e" * 64,
         "output_path": "outputs/0002_evidence_inventory.json",
         "truncated": False, "exit_code": 0},
        {"seq": 3, "ts": "2026-06-13T00:00:02Z", "run_id": run_dir.name,
         "event": "tool_called", "tool": "registry_query",
         "params": {"hive": "NTUSER.DAT", "plugin": "run_keys"}},
        {"seq": 4, "ts": "2026-06-13T00:00:03Z", "run_id": run_dir.name,
         "event": "tool_result", "tool": "registry_query",
         "output_sha256": "c" * 64,
         "output_path": "outputs/0004_registry_query.json",
         "truncated": False, "exit_code": 0},
        {"seq": 5, "ts": "2026-06-13T00:00:04Z", "run_id": run_dir.name,
         "event": "tool_called", "tool": "read_artifact",
         "params": {"path": "mimikatz.exe", "length": 100}},
        {"seq": 6, "ts": "2026-06-13T00:00:05Z", "run_id": run_dir.name,
         "event": "tool_result", "tool": "read_artifact",
         "output_sha256": "d" * 64,
         "output_path": "outputs/0006_read_artifact.json",
         "truncated": False, "exit_code": 0},
        {"seq": 7, "ts": "2026-06-13T00:00:06Z", "run_id": run_dir.name,
         "event": "finding_recorded", "finding_id": "F-001",
         "claim": "Run-key persistence"},
        {"seq": 8, "ts": "2026-06-13T00:00:07Z", "run_id": run_dir.name,
         "event": "verdict_recorded", "finding_id": "F-001",
         "verdict": "VERIFIED", "reason": "reproduced"},
        {"seq": 9, "ts": "2026-06-13T00:00:08Z", "run_id": run_dir.name,
         "event": "api_usage", "cost_usd": 0.12, "cumulative_cost_usd": 0.34},
        {"seq": 10, "ts": "2026-06-13T00:00:09Z", "run_id": run_dir.name,
         "event": "run_ended", "findings": 3, "total_cost_usd": 0.34},
    ]
    (run_dir / "ledger.jsonl").write_text(
        "\n".join(json.dumps(e) for e in ledger) + "\n", encoding="utf-8")
    return run_dir


_FINDINGS_MIXED = [
    {"id": "F-001",
     "claim": "A Run key launches C:/Users/Public/update.exe at logon.",
     "severity": "high", "attack_id": "T1547.001", "cites": [4],
     "verdict": "VERIFIED", "verdict_reason": "Reproduced the run_keys plugin "
     "output; the value points at update.exe in a world-writable path."},
    {"id": "F-002",
     "claim": "An event-log gap suggests possible log tampering.",
     "severity": "medium", "attack_id": "T1070.001", "cites": [2],
     "verdict": "UNCONFIRMED", "verdict_reason": "Could not fully reproduce the "
     "gap; no contradiction found."},
    {"id": "F-003",
     "claim": "mimikatz.exe is a staged credential-dumping tool.",
     "severity": "critical", "attack_id": "T1003.001", "cites": [6],
     "verdict": "REFUTED", "verdict_reason": "Filename implies a credential-"
     "theft tool; content is 12 bytes of ASCII text ('hello world'), not an "
     "executable - no credential-access capability."},
]


# --------------------------------------------------------- 1. mixed run


def check_mixed_run() -> None:
    prose = {
        "executive_summary": (
            "An attacker established a foothold and set up a way to survive "
            "reboots. The intrusion was caught during automated triage and "
            "confirmed by an independent re-check. One claim of attacker "
            "tooling did not hold up and was discarded. The confirmed activity "
            "is rated high. No data theft was established from the evidence."),
        "attack_narrative": [
            {"text": "The attacker arranged for a program to start "
                     "automatically each time the user logs in.",
             "finding_id": "F-001"},
            {"text": "A gap in the activity records may indicate an attempt to "
                     "cover tracks.", "finding_id": "F-002"},
            # A sentence citing an excluded/refuted id must be dropped:
            {"text": "This sentence cites a refuted finding and must be dropped.",
             "finding_id": "F-003"},
            {"text": "This sentence cites a nonexistent finding.",
             "finding_id": "F-999"},
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        run_dir = _write_run(Path(td))
        path = generate_report(
            str(run_dir), _FINDINGS_MIXED, str(run_dir / "ledger.jsonl"),
            case_name="smoke", model="claude-sonnet-4-6", total_cost=0.34,
            wall_time="2m 13s", anthropic_client=FakeAnthropic(prose))
        html = Path(path).read_text(encoding="utf-8")

    # self-contained: inline style, no external script/link
    assert "<style>" in html, "no inline <style>"
    assert "<script src" not in html and "<script>" not in html, "has JS"
    assert not re.search(r'<link[^>]+rel=["\']stylesheet', html), \
        "external stylesheet link present"
    assert "http://" not in html and "https://" not in html, \
        "external URL present (must be self-contained / offline)"

    # findings table has VERIFIED+UNCONFIRMED, NOT the refuted one in the table.
    # The refuted F-003 claim text must NOT appear before Appendix A.
    appendix_a_idx = html.index("Appendix A")
    table_region = html[:appendix_a_idx]
    assert "F-001" in table_region and "F-002" in table_region
    assert "credential-dumping tool" not in table_region, \
        "refuted claim leaked into the headline"
    # F-003 detail anchor must not be in the headline detail region either.
    assert 'id="F-003"' in html[appendix_a_idx:], \
        "refuted finding not anchored in appendix"

    # Appendix A has the refuted finding + its refutation reason.
    appendix_a = html[appendix_a_idx:html.index("Appendix B")]
    assert "F-003" in appendix_a
    assert "12 bytes of ASCII text" in appendix_a, "refutation reason missing"

    # citations resolve offline: each headline finding's cite seq is an
    # href="#ledger-<seq>" AND a matching id="ledger-<seq>" exists.
    for f in _FINDINGS_MIXED:
        if f["verdict"] == "REFUTED":
            continue
        for seq in f["cites"]:
            assert f'href="#ledger-{seq}"' in html, f"no cite anchor seq {seq}"
            assert f'id="ledger-{seq}"' in html, f"no ledger target seq {seq}"
    # every href="#ledger-N" has a matching id="ledger-N" target present.
    for seq in set(int(m) for m in re.findall(r'href="#ledger-(\d+)"', html)):
        assert f'id="ledger-{seq}"' in html, f"dangling cite anchor seq {seq}"

    # Appendix D methodology present.
    assert "Appendix D" in html and "no tool that accepts an arbitrary" in html

    # header shows cost + model.
    assert "claude-sonnet-4-6" in html and "0.3400" in html

    # fake prose rendered: exec summary + a footnoted narrative sentence whose
    # anchor points at F-001; the dropped (refuted / nonexistent) sentences must
    # NOT carry a finding anchor.
    assert "survive reboots" in html, "exec summary prose missing"
    assert "starts" in html or "automatically each time" in html, \
        "narrative prose missing"
    assert 'href="#F-001"' in html, "narrative footnote anchor missing"
    assert "cites a nonexistent finding" not in html, \
        "narrative with invented finding id was not dropped"

    # excerpt pulled from the cited output file (the run_keys hit).
    assert "update.exe" in html, "cited artifact excerpt missing"


# --------------------------------------------------------- 2. clean case


def check_clean_case() -> None:
    with tempfile.TemporaryDirectory() as td:
        run_dir = _write_run(Path(td))
        # zero findings; no prose client -> deterministic honest-empty summary.
        path = generate_report(
            str(run_dir), [], str(run_dir / "ledger.jsonl"),
            case_name="clean", model="claude-sonnet-4-6", total_cost=0.10,
            anthropic_client=None)
        html = Path(path).read_text(encoding="utf-8")

    assert "<html" in html and "</html>" in html, "not valid-ish HTML"
    assert "no indicators of compromise" in html.lower(), \
        "clean statement missing from exec summary"
    # empty findings table rendered gracefully (no crash, a graceful row).
    assert "examined and found clean" in html, "empty table row missing"
    # appendices still present (inventory + ledger + methodology).
    assert "Appendix B" in html and "Appendix C" in html and "Appendix D" in html
    # inventory still listed from the stored evidence_inventory output.
    assert "NTUSER.DAT" in html, "inventory not rendered on clean case"


# --------------------------------------------------------- 3. PDF chain


def check_pdf_fallback() -> None:
    """attempt_pdf with no engine on PATH -> None + manual message, no raise."""
    import io
    from contextlib import redirect_stdout

    import verdict.report.generator as gen

    real_which = gen.shutil.which
    gen.shutil.which = lambda name: None  # no chromium/wkhtmltopdf anywhere
    try:
        with tempfile.TemporaryDirectory() as td:
            html = Path(td) / "report.html"
            html.write_text("<html><body>x</body></html>", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = attempt_pdf(str(html))
            assert result is None, result
            assert PDF_MANUAL_FALLBACK in buf.getvalue(), buf.getvalue()
            # report.html untouched / still present
            assert html.exists()
    finally:
        gen.shutil.which = real_which


# --------------------------------------------------------- 4. budget note


def check_budget_note() -> None:
    with tempfile.TemporaryDirectory() as td:
        run_dir = _write_run(Path(td))
        # append a budget_event line to the ledger.
        with (run_dir / "ledger.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "seq": 11, "ts": "2026-06-13T00:00:10Z",
                "run_id": run_dir.name, "event": "budget_event",
                "kind": "triage_cap", "spent_usd": 3.01,
                "budget_usd": 5.0}) + "\n")
        # explicit caller note too (BudgetGuard.notes path).
        path = generate_report(
            str(run_dir), _FINDINGS_MIXED, str(run_dir / "ledger.jsonl"),
            case_name="smoke", model="claude-sonnet-4-6", total_cost=3.10,
            anthropic_client=None,
            budget_notes=["Triage reached its soft budget cap; "
                          "transitioned to verification."])
        html = Path(path).read_text(encoding="utf-8")

    assert "Budget guard:" in html, "budget note not surfaced"
    assert "soft budget cap" in html, "caller note text missing"
    # the budget_event line is in the embedded tool-call index.
    assert "budget_event" in html, "budget_event not in ledger rendering"


# ----------------------------------------------------------------- harness


def main() -> int:
    checks = [
        ("mixed run: self-contained HTML; VERIFIED+UNCONFIRMED in table, "
         "REFUTED in Appendix A; cites resolve to ledger anchors; methodology + "
         "header; fake prose footnoted", check_mixed_run),
        ("clean case: zero findings -> valid honest-empty report, appendices "
         "present, no crash", check_clean_case),
        ("PDF chain: no engine on PATH -> None + manual message, no raise",
         check_pdf_fallback),
        ("budget note: budget_event ledger line + caller note surfaced",
         check_budget_note),
    ]
    for name, fn in checks:
        run_check(name, fn)
    total, failed = len(checks), len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed"
          + (f" - FAILED: {', '.join(FAILURES)}" if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
