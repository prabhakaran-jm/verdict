"""Tools check for checklist item 4 - the 8 loose-artifact + recording tools.

Plain stdlib (no pytest), same style as foundation_check.py. Exercises, on
Windows or Linux, WITHOUT real forensic binaries: the runner's extra_argv
test seam wires the "evtx" / "registry" / "execution" / "yara" capabilities
to stub scripts that emit canned realistic output, so the full pipeline
(pydantic validation -> pathguard -> runner -> ledger -> filtering) runs
end to end. In-process parsers that need optional modules (pyscca,
yara-python) are SKIPped cleanly when not importable - the real paths get
exercised on the SIFT VM at checkpoint 2.

Per tool: one successful call (sensible output + tool_called/tool_result
ledger pair; for runner-backed tools the output file + SHA-256 exist) and
deliberately malformed calls (tool_rejected ledger line + clean error, no
traceback). Plus the three required edge rejections: record_finding citing
a non-tool_result seq, record_verdict on an unknown finding_id, and
read_artifact escaping the allowed roots.

Run:  python tests/tools_check.py
Prints PASS/FAIL/SKIP per check; exits nonzero on any FAIL.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import traceback
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

FAILURES: list[str] = []
SKIPS: list[tuple[str, str]] = []
ENV: SimpleNamespace | None = None


def run_check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        FAILURES.append(name)
        print(f"FAIL  {name}")
        print("      " + traceback.format_exc().strip().replace("\n", "\n      "))
    else:
        print(f"PASS  {name}")


def skip(name: str, reason: str) -> None:
    SKIPS.append((name, reason))
    print(f"SKIP  {name} ({reason})")


# ------------------------------------------------------------ environment

STUB_EVTX = r"""
import json
RECORDS = [
    {"Event": {"System": {"EventID": 4624,
        "TimeCreated": {"#attributes": {"SystemTime": "2026-06-10 09:00:00.000000 UTC"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        "Channel": "Security", "Computer": "CASTLE"},
        "EventData": {"LogonType": 3, "TargetUserName": "svc-deploy",
                      "IpAddress": "10.0.0.99"}}},
    {"Event": {"System": {"EventID": 4624,
        "TimeCreated": {"#attributes": {"SystemTime": "2026-06-10 09:05:00.000000 UTC"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        "Channel": "Security", "Computer": "CASTLE"},
        "EventData": {"LogonType": 3, "TargetUserName": "administrator",
                      "IpAddress": "10.0.0.99"}}},
    {"Event": {"System": {"EventID": {"#text": 7045, "#attributes": {"Qualifiers": 16384}},
        "TimeCreated": {"#attributes": {"SystemTime": "2026-06-10 09:10:00.000000 UTC"}},
        "Provider": {"#attributes": {"Name": "Service Control Manager"}},
        "Channel": "System", "Computer": "CASTLE"},
        "EventData": {"ServiceName": "UpdaterSvc",
                      "ImagePath": "C:\\Users\\Public\\update.exe",
                      "StartType": "auto start"}}},
    {"Event": {"System": {"EventID": 4688,
        "TimeCreated": {"#attributes": {"SystemTime": "2026-06-10 09:15:00.000000 UTC"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        "Channel": "Security", "Computer": "CASTLE"},
        "EventData": {"NewProcessName": "C:\\Windows\\System32\\cmd.exe"}}},
    {"Event": {"System": {"EventID": 4688,
        "TimeCreated": {"#attributes": {"SystemTime": "2026-06-10 09:20:00.000000 UTC"}},
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        "Channel": "Security", "Computer": "CASTLE"},
        "EventData": {"NewProcessName": "C:\\Users\\Public\\update.exe"}}},
]
for record in RECORDS:
    print(json.dumps(record))
"""

STUB_REGISTRY = r"""
print("run v.20200511")
print("(Software, NTUSER.DAT) [Autostart] Get autostart key contents")
print("")
print("Microsoft\\Windows\\CurrentVersion\\Run")
print("LastWrite Time 2026-06-10 09:12:00Z")
print("  Updater - C:\\Users\\Public\\update.exe")
print("  OneDrive - C:\\Users\\victim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
"""

STUB_EXECUTION = r"""
print("amcache v.20180311")
print("(All) Parse Amcache.hve file")
print("")
print("File Path: c:\\users\\public\\update.exe")
print("SHA1: aabbccddeeff00112233445566778899aabbccdd")
print("Last Mod Time: 2026-06-10 09:11:30Z")
print("")
print("File Path: c:\\windows\\system32\\notepad.exe")
print("SHA1: 1122334455667788990011223344556677889900")
print("Last Mod Time: 2026-01-05 10:00:00Z")
"""

STUB_YARA = r"""
import sys
target = sys.argv[-1]
print("smoke_placeholder " + target)
print("0x0:$marker: 56 45 52 44 49 43 54")
"""


def build_env(base: Path) -> SimpleNamespace:
    from verdict_mcp.server import build_app

    case = base / "case"
    run = base / "run"
    stubs = base / "stubs"
    prefetch_dir = case / "prefetch"
    for d in (case, run, stubs, prefetch_dir):
        d.mkdir(parents=True)

    (case / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    regf = b"regf" + b"\x00" * 124
    (case / "SOFTWARE").write_bytes(regf)
    (case / "Amcache.hve").write_bytes(regf)
    (prefetch_dir / "UPDATE.EXE-1A2B3C4D.pf").write_bytes(
        b"MAM\x04" + b"\x00" * 32)
    (case / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 16)
    (case / "mimikatz.exe").write_bytes(b"this is text")  # the decoy shape
    (case / "disk.dd").write_bytes(b"\x00" * 32)
    (case / "memory.vmem").write_bytes(b"\x00" * 32)

    for name, source in (("evtx", STUB_EVTX), ("registry", STUB_REGISTRY),
                         ("execution", STUB_EXECUTION), ("yara", STUB_YARA)):
        (stubs / f"stub_{name}.py").write_text(source, encoding="utf-8")

    app, ctx = build_app(case, run)
    for name in ("evtx", "registry", "execution", "yara"):
        ctx.runner.add_capability_override(
            name, (sys.executable, str(stubs / f"stub_{name}.py")))
    return SimpleNamespace(base=base, case=case, run=run, app=app, ctx=ctx)


# ----------------------------------------------------------------- helpers


def call(name: str, args: dict | None = None) -> dict:
    result = asyncio.run(ENV.app.call_tool(name, args or {}))
    assert isinstance(result, tuple), (
        f"{name}: expected (content, structured) tuple, got {type(result)}")
    _content, structured = result
    return structured


def read_ledger() -> list[dict]:
    text = (ENV.run / "ledger.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def assert_pair_and_artifact(tool: str, response: dict,
                             since: int = 0) -> tuple[dict, dict]:
    """The newest tool_called/tool_result pair for `tool` + on-disk artifact."""
    lines = read_ledger()[since:]
    called = [l for l in lines if l["event"] == "tool_called" and l["tool"] == tool]
    results = [l for l in lines if l["event"] == "tool_result" and l["tool"] == tool]
    assert called and results, f"missing ledger pair for {tool}"
    result = results[-1]
    out_path = ENV.run / result["output_path"]
    assert out_path.is_file(), f"output artifact missing: {out_path}"
    on_disk = hashlib.sha256(out_path.read_bytes()).hexdigest()
    assert on_disk == result["output_sha256"], "artifact SHA-256 mismatch"
    assert response["output_sha256"] == result["output_sha256"]
    assert response["cite_seq"] == result["seq"], (
        f"cite_seq {response['cite_seq']} != tool_result seq {result['seq']}")
    return called[-1], result


def expect_rejected(tool: str, args: dict, fragment: str | None = None) -> str:
    before = len(read_ledger())
    try:
        call(tool, args)
    except ToolError as exc:
        message = str(exc)
    else:
        raise AssertionError(f"{tool} {args!r} was NOT rejected")
    assert "Traceback (most recent call last)" not in message, (
        f"traceback leaked to the model: {message[:200]}")
    new = read_ledger()[before:]
    rejections = [l for l in new
                  if l["event"] == "tool_rejected" and l["tool"] == tool]
    assert rejections, f"no tool_rejected ledger line for {tool}; got {new}"
    assert rejections[-1]["reason"], "tool_rejected line has an empty reason"
    executed = [l for l in new if l["event"] in ("tool_called", "tool_result")]
    assert not executed, f"rejected {tool} call still executed: {executed}"
    if fragment is not None:
        haystack = (message + " " + rejections[-1]["reason"]).lower()
        assert fragment.lower() in haystack, (
            f"'{fragment}' not in rejection: {message!r}")
    return message


# ---------------------------------------------------- 1. evidence_inventory


def check_inventory_success() -> None:
    response = call("evidence_inventory")
    assert response["is_error"] is False
    types = {f["path"]: f["type"] for f in response["files"]}
    expected = {
        "Security.evtx": "evtx",
        "SOFTWARE": "registry_hive",
        "Amcache.hve": "registry_hive",
        "prefetch/UPDATE.EXE-1A2B3C4D.pf": "prefetch",
        "capture.pcap": "pcap",
        "mimikatz.exe": "other",
        "disk.dd": "disk_image",
        "memory.vmem": "memory_image",
    }
    for path, kind in expected.items():
        assert types.get(path) == kind, f"{path}: {types.get(path)} != {kind}"
    assert response["total_files"] >= len(expected)
    assert "never parsed" in response["pcap_note"]
    by_path = {f["path"]: f for f in response["files"]}
    want = hashlib.sha256(b"this is text").hexdigest()
    assert by_path["mimikatz.exe"]["sha256"] == want
    assert by_path["mimikatz.exe"]["size"] == 12
    assert_pair_and_artifact("evidence_inventory", response)
    ENV.inventory_response = response


def check_inventory_malformed() -> None:
    expect_rejected("evidence_inventory", {"bogus": 1},
                    fragment="unknown parameter")


# ------------------------------------------------------------ 2. evtx_query


def check_evtx_success() -> None:
    log = str(ENV.case / "Security.evtx")
    by_id = call("evtx_query", {"log": log, "limit": 10, "event_ids": [7045]})
    assert by_id["is_error"] is False
    assert by_id["total_matches"] == 1, by_id
    record = by_id["records"][0]
    assert record["event_id"] == 7045
    assert "update.exe" in json.dumps(record["data"])
    called, result = assert_pair_and_artifact("evtx_query", by_id)
    assert called["params"]["event_ids"] == [7045]
    ENV.evtx_cite_seq = result["seq"]
    ENV.evtx_called_seq = called["seq"]

    windowed = call("evtx_query", {"log": log, "limit": 10,
                                   "event_ids": [4624],
                                   "after": "2026-06-10T09:04:00Z"})
    assert windowed["total_matches"] == 1, windowed
    assert windowed["records"][0]["time"].startswith("2026-06-10 09:05")

    limited = call("evtx_query", {"log": log, "limit": 1})
    assert limited["total_matches"] == 5 and limited["returned"] == 1
    assert limited["truncated"] is True

    keyworded = call("evtx_query", {"log": log, "limit": 10,
                                    "keyword": "update.exe"})
    assert keyworded["total_matches"] == 2, keyworded


def check_evtx_malformed() -> None:
    log = str(ENV.case / "Security.evtx")
    expect_rejected("evtx_query", {"log": log, "limit": 9999},
                    fragment="limit")
    expect_rejected("evtx_query", {"log": log}, fragment="limit")
    expect_rejected("evtx_query",
                    {"log": log, "limit": 10, "after": "not-a-date"},
                    fragment="after")
    expect_rejected("evtx_query",
                    {"log": str(ENV.case / "nope.evtx"), "limit": 10},
                    fragment="not an existing file")


# -------------------------------------------------------- 3. registry_query


def check_registry_success() -> None:
    response = call("registry_query", {"hive": str(ENV.case / "SOFTWARE"),
                                       "plugin": "run_keys"})
    assert response["is_error"] is False
    assert response["hive_type"] == "software"
    assert "RegRipper" in response["parser"]
    assert "update.exe" in response["text"]
    assert_pair_and_artifact("registry_query", response)


def check_registry_malformed() -> None:
    hive = str(ENV.case / "SOFTWARE")
    expect_rejected("registry_query", {"hive": hive, "plugin": "frobnicate"},
                    fragment="plugin")
    expect_rejected("registry_query", {"hive": hive, "plugin": "sam_users"},
                    fragment="SAM")


# ---------------------------------------------------- 4. execution_evidence


def check_execution_amcache() -> None:
    response = call("execution_evidence",
                    {"source": str(ENV.case / "Amcache.hve"),
                     "name_contains": "update"})
    assert response["is_error"] is False
    assert response["source_type"] == "amcache"
    assert response["total_entries"] == 1, response
    assert "update.exe" in response["entries"][0]
    assert "notepad" not in response["entries"][0]
    assert_pair_and_artifact("execution_evidence", response)


def check_execution_prefetch_and_malformed() -> None:
    expect_rejected("execution_evidence",
                    {"source": str(ENV.case / "mimikatz.exe")},
                    fragment="neither")
    prefetch_dir = str(ENV.case / "prefetch")
    try:
        import pyscca  # noqa: F401
    except ImportError:
        # Clean rejection is the required behavior on a host without pyscca;
        # the real parse runs on the SIFT VM at checkpoint 2.
        expect_rejected("execution_evidence", {"source": prefetch_dir},
                        fragment="pyscca")
        skip("execution_evidence: pyscca prefetch parse",
             "pyscca not installed; exercised the clean rejection instead")
    else:
        response = call("execution_evidence", {"source": prefetch_dir})
        assert response["source_type"] == "prefetch"
        assert response["is_error"] is False  # fake .pf -> parse_errors list
        assert response["total_matches"] == 0 and response["parse_errors"]
        assert_pair_and_artifact("execution_evidence", response)


# -------------------------------------------------------------- 5. yara_scan


def check_yara_success() -> None:
    response = call("yara_scan", {"target": str(ENV.case / "mimikatz.exe"),
                                  "ruleset": "smoke"})
    assert response["is_error"] is False
    assert response["engine"] == "yara-cli"
    assert response["total_matches"] == 1, response
    match = response["matches"][0]
    assert match["rule"] == "smoke_placeholder"
    assert match["strings"][0]["offset"] == 0
    assert match["strings"][0]["identifier"] == "$marker"
    assert_pair_and_artifact("yara_scan", response)
    try:
        import yara  # noqa: F401
    except ImportError:
        skip("yara_scan: yara-python in-process fallback",
             "yara-python not installed; CLI path stubbed; real fallback "
             "at checkpoint 2")


def check_yara_malformed() -> None:
    target = str(ENV.case / "mimikatz.exe")
    expect_rejected("yara_scan", {"target": target, "ruleset": "nonexistent"},
                    fragment="ruleset")
    expect_rejected("yara_scan", {"target": str(ENV.case / "missing.bin"),
                                  "ruleset": "smoke"},
                    fragment="exist")


# ----------------------------------------------------------- 6. read_artifact


def check_read_artifact_success() -> None:
    decoy = str(ENV.case / "mimikatz.exe")
    text = call("read_artifact", {"path": decoy, "length": 100})
    assert text["is_error"] is False
    assert text["content"] == "this is text"
    assert text["file_size"] == 12 and text["returned_bytes"] == 12
    assert text["eof"] is True and text["mode"] == "text"
    assert_pair_and_artifact("read_artifact", text)

    hexed = call("read_artifact", {"path": decoy, "length": 8, "offset": 5,
                                   "mode": "hex"})
    assert hexed["content"].startswith("00000005")
    assert "69 73 20 74 65 78 74" in hexed["content"]  # "is text"
    assert "|is text|" in hexed["content"]
    assert hexed["returned_bytes"] == 7 and hexed["eof"] is True

    # the verifier's path: re-read a stored tool output from the run dir
    stored = str(ENV.run / ENV.inventory_response["output_path"])
    reread = call("read_artifact", {"path": stored, "length": 200})
    assert reread["content"].lstrip().startswith("{")


def check_read_artifact_malformed() -> None:
    decoy = str(ENV.case / "mimikatz.exe")
    expect_rejected("read_artifact", {"path": decoy, "length": 9000},
                    fragment="length")
    expect_rejected("read_artifact", {"path": decoy, "length": 10,
                                      "mode": "binary"}, fragment="mode")
    expect_rejected("read_artifact", {"path": decoy, "length": 10,
                                      "offset": -1}, fragment="offset")
    expect_rejected("read_artifact", {"path": decoy}, fragment="length")


def check_read_artifact_escape() -> None:
    outside = str(ENV.base / "escape.txt")
    expect_rejected("read_artifact", {"path": outside, "length": 10},
                    fragment="outside")
    traversal = str(ENV.case / ".." / ".." / "etc" / "shadow")
    expect_rejected("read_artifact", {"path": traversal, "length": 10},
                    fragment="refused")


# --------------------------------------------------------- 7. record_finding


def check_record_finding_success() -> None:
    first = call("record_finding", {
        "claim": "Service 'UpdaterSvc' installed from C:\\Users\\Public\\"
                 "update.exe (event 7045) - persistence via new service.",
        "severity": "high",
        "attack_id": "T1543.003",
        "cites": [ENV.evtx_cite_seq],
    })
    assert first["finding_id"] == "F-001"
    assert first["cites"] == [ENV.evtx_cite_seq]
    lines = read_ledger()
    recorded = [l for l in lines if l["event"] == "finding_recorded"]
    assert recorded and recorded[-1]["finding_id"] == "F-001"
    assert recorded[-1]["attack_id"] == "T1543.003"
    assert recorded[-1]["cites"] == [ENV.evtx_cite_seq]
    assert recorded[-1]["severity"] == "high"

    second = call("record_finding", {
        "claim": "mimikatz.exe present in the case folder.",
        "severity": "critical",
        "attack_id": "T1003",
        "cites": [ENV.inventory_response["cite_seq"]],
    })
    assert second["finding_id"] == "F-002"


def check_record_finding_malformed() -> None:
    good = {"claim": "x", "severity": "high", "attack_id": "T1059",
            "cites": [ENV.evtx_cite_seq]}
    expect_rejected("record_finding", {**good, "attack_id": "1059"},
                    fragment="attack_id")
    expect_rejected("record_finding", {**good, "cites": []}, fragment="cites")
    expect_rejected("record_finding", {**good, "severity": "catastrophic"},
                    fragment="severity")
    expect_rejected("record_finding", {**good, "claim": ""}, fragment="claim")


def check_record_finding_bad_cite() -> None:
    # a real seq, but a tool_called line - cites must hit tool_result entries
    expect_rejected("record_finding",
                    {"claim": "x", "severity": "low", "attack_id": "T1059",
                     "cites": [ENV.evtx_called_seq]},
                    fragment="tool_result")
    expect_rejected("record_finding",
                    {"claim": "x", "severity": "low", "attack_id": "T1059",
                     "cites": [999999]},
                    fragment="tool_result")


# --------------------------------------------------------- 8. record_verdict


def check_record_verdict_success() -> None:
    response = call("record_verdict", {
        "finding_id": "F-002",
        "verdict": "REFUTED",
        "reason": "filename suggests credential-theft tool; content is "
                  "12 bytes of ASCII text",
    })
    assert response["verdict"] == "REFUTED"
    assert response["finding_id"] == "F-002"
    lines = read_ledger()
    verdicts = [l for l in lines if l["event"] == "verdict_recorded"]
    assert verdicts and verdicts[-1]["finding_id"] == "F-002"
    assert verdicts[-1]["verdict"] == "REFUTED"
    assert verdicts[-1]["reason"].startswith("filename suggests")


def check_record_verdict_malformed() -> None:
    expect_rejected("record_verdict",
                    {"finding_id": "F-999", "verdict": "VERIFIED",
                     "reason": "x"},
                    fragment="unknown finding_id")
    expect_rejected("record_verdict",
                    {"finding_id": "F-001", "verdict": "MAYBE",
                     "reason": "x"},
                    fragment="verdict")
    expect_rejected("record_verdict",
                    {"finding_id": "F-001", "verdict": "VERIFIED",
                     "reason": ""},
                    fragment="reason")


# ------------------------------------------------- phase metadata + schemas


def check_phase_allowlists() -> None:
    from verdict_mcp.tools import ALL_TOOLS, TRIAGE_TOOLS, VERIFY_TOOLS

    assert len(ALL_TOOLS) == 13
    assert len(TRIAGE_TOOLS) == 12 and len(VERIFY_TOOLS) == 11
    assert TRIAGE_TOOLS == ALL_TOOLS[:12]
    assert "record_finding" in TRIAGE_TOOLS and "record_finding" not in VERIFY_TOOLS
    assert "evidence_inventory" in TRIAGE_TOOLS
    assert "evidence_inventory" not in VERIFY_TOOLS
    assert "record_verdict" in VERIFY_TOOLS and "record_verdict" not in TRIAGE_TOOLS
    assert "_log_event" not in TRIAGE_TOOLS and "_log_event" not in VERIFY_TOOLS
    assert set(VERIFY_TOOLS) - {"record_verdict"} == set(ALL_TOOLS[1:11])

    tools = asyncio.run(ENV.app.list_tools())
    names = {t.name for t in tools}
    item4 = {"evidence_inventory", "evtx_query", "registry_query",
             "execution_evidence", "yara_scan", "read_artifact",
             "record_finding", "record_verdict"}
    assert item4 <= names, f"missing tools: {item4 - names}"
    assert names - item4 == {"_log_event"}, (
        f"unexpected extra tools: {names - item4 - {'_log_event'}}")

    schemas = {t.name: t.inputSchema for t in tools}
    assert "limit" in schemas["evtx_query"]["required"]
    assert schemas["evtx_query"]["properties"]["limit"]["maximum"] == 500
    assert "length" in schemas["read_artifact"]["required"]
    assert schemas["read_artifact"]["properties"]["length"]["maximum"] == 8192
    ruleset_schema = schemas["yara_scan"]["properties"]["ruleset"]
    # pydantic emits const for a single-value Literal, enum for several
    assert ruleset_schema.get("enum") == ["smoke"] \
        or ruleset_schema.get("const") == "smoke", ruleset_schema
    assert "pattern" in schemas["record_finding"]["properties"]["attack_id"]


# ----------------------------------------------------------------- harness


def main() -> int:
    global ENV
    checks = [
        ("evidence_inventory: classify + SHA-256 + ledger pair + artifact",
         check_inventory_success),
        ("evidence_inventory: unknown parameter -> tool_rejected",
         check_inventory_malformed),
        ("evtx_query: id/time/keyword filters + limit + ledger pair",
         check_evtx_success),
        ("evtx_query: out-of-range/missing limit, bad date, missing file -> rejected",
         check_evtx_malformed),
        ("registry_query: run_keys plugin on SOFTWARE hive + ledger pair",
         check_registry_success),
        ("registry_query: unknown plugin + hive-type mismatch -> rejected",
         check_registry_malformed),
        ("execution_evidence: amcache via runner + name filter + ledger pair",
         check_execution_amcache),
        ("execution_evidence: bogus source -> rejected; prefetch path",
         check_execution_prefetch_and_malformed),
        ("yara_scan: stubbed CLI, match names + offsets + ledger pair",
         check_yara_success),
        ("yara_scan: unknown ruleset + missing target -> rejected",
         check_yara_malformed),
        ("read_artifact: text/hex bounded reads, case + run dir",
         check_read_artifact_success),
        ("read_artifact: bad length/mode/offset -> rejected",
         check_read_artifact_malformed),
        ("read_artifact: path escape -> rejected via pathguard",
         check_read_artifact_escape),
        ("record_finding: F-ids, cites tool_result seqs, ledgered",
         check_record_finding_success),
        ("record_finding: bad attack_id/severity/claim/empty cites -> rejected",
         check_record_finding_malformed),
        ("record_finding: cite to non-tool_result seq -> rejected",
         check_record_finding_bad_cite),
        ("record_verdict: REFUTED ledgered with reason",
         check_record_verdict_success),
        ("record_verdict: unknown finding_id / bad verdict -> rejected",
         check_record_verdict_malformed),
        ("phase allowlists + registered tool set + typed schemas",
         check_phase_allowlists),
    ]
    with tempfile.TemporaryDirectory() as td:
        ENV = build_env(Path(td))
        try:
            for name, fn in checks:
                run_check(name, fn)
        finally:
            ENV.ctx.ledger.close()
    total, failed = len(checks), len(FAILURES)
    summary = f"\n{total - failed}/{total} checks passed"
    if SKIPS:
        summary += f", {len(SKIPS)} optional path(s) skipped"
    if FAILURES:
        summary += f" - FAILED: {', '.join(FAILURES)}"
    print(summary)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
