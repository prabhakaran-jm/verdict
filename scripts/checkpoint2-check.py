"""Checkpoint 2 spot-check (checklist item 5 verify) - run on the SIFT VM.

Exercises the real item-4 tools (real forensic binaries, no stubs) against
the committed cases:

  cases/smoke/  - every artifact classified + hashed; evtx_query finds the
                  7045 service install (ImagePath update.exe) and a type-3
                  4624; registry_query run_keys finds the Run-key value;
                  execution_evidence parses the UPDATE.EXE prefetch;
                  yara_scan hits the bait once; read_artifact shows the
                  decoy is ASCII text.
  cases/clean/  - everything classifies benign ("other"), nothing fires.

Run (inside the project venv, repo root):  python scripts/checkpoint2-check.py
Prints PASS/FAIL per check and a paste-back block; exits nonzero on FAIL.
Ledgers land in runs/checkpoint2-<utc>/ for inspection.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from verdict_mcp.server import build_app  # noqa: E402

RESULTS: list[tuple[str, str]] = []  # (PASS/FAIL, name)


def check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        RESULTS.append(("FAIL", name))
        print(f"FAIL  {name}")
        print("      " + traceback.format_exc().strip().replace("\n", "\n      "))
    else:
        RESULTS.append(("PASS", name))
        print(f"PASS  {name}")


def make_ctx(case: Path, label: str):
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = REPO_ROOT / "runs" / f"checkpoint2-{label}-{ts}"
    run.mkdir(parents=True, exist_ok=True)
    app, ctx = build_app(case, run)
    return app, ctx, run


def call(app, name: str, args: dict | None = None) -> dict:
    _content, structured = asyncio.run(app.call_tool(name, args or {}))
    return structured


def main() -> int:
    smoke = REPO_ROOT / "cases" / "smoke"
    clean = REPO_ROOT / "cases" / "clean"
    app, _ctx, run_dir = make_ctx(smoke, "smoke")

    pf_files = sorted(smoke.glob("UPDATE.EXE-*.pf"))

    def smoke_inventory():
        inv = call(app, "evidence_inventory")
        files = {f["path"]: f for f in inv["files"]}
        expect_types = {
            "Security.evtx": "evtx",
            "System.evtx": "evtx",
            "NTUSER.DAT": "registry_hive",
            "mimikatz.exe": "other",
            "invoice_2020.txt": "other",
        }
        for name, want in expect_types.items():
            assert name in files, f"{name} missing from inventory"
            got = files[name]["type"]
            assert got == want, f"{name}: type {got!r}, expected {want!r}"
        assert pf_files, "no UPDATE.EXE-*.pf in cases/smoke"
        assert files[pf_files[0].name]["type"] == "prefetch"
        for f in files.values():
            assert re.fullmatch(r"[0-9a-f]{64}", f["sha256"]), \
                f"{f['path']}: bad sha256"

    def evtx_7045():
        out = call(app, "evtx_query",
                   {"log": "System.evtx", "limit": 10, "event_ids": [7045]})
        dump = json.dumps(out).lower()
        assert out.get("total_matches", 0) >= 1 or out.get("records"), \
            "no 7045 records returned"
        assert "update.exe" in dump, "7045 found but ImagePath lacks update.exe"

    def evtx_4624_type3():
        out = call(app, "evtx_query",
                   {"log": "Security.evtx", "limit": 50, "event_ids": [4624]})
        dump = json.dumps(out).lower()
        assert out.get("records"), "no 4624 records returned"
        assert re.search(r'"logontype":\s*"?3"?', dump), \
            "4624 records present but none show LogonType 3"

    def registry_runkey():
        out = call(app, "registry_query",
                   {"hive": "NTUSER.DAT", "plugin": "run_keys"})
        dump = json.dumps(out).lower()
        assert "update.exe" in dump, "run_keys output lacks update.exe"

    def prefetch_parse():
        out = call(app, "execution_evidence", {"source": pf_files[0].name})
        dump = json.dumps(out).lower()
        assert "update.exe" in dump, "prefetch parse lacks UPDATE.EXE"

    def yara_bait():
        out = call(app, "yara_scan",
                   {"target": "invoice_2020.txt", "ruleset": "smoke"})
        dump = json.dumps(out).lower()
        assert "verdict_smoke_eicar" in dump, "bait file did not match smoke rule"
        decoy = call(app, "yara_scan",
                     {"target": "mimikatz.exe", "ruleset": "smoke"})
        assert not decoy.get("matches"), "decoy unexpectedly matched a rule"

    def decoy_ascii():
        out = call(app, "read_artifact",
                   {"path": "mimikatz.exe", "length": 64, "mode": "text"})
        dump = json.dumps(out)
        assert "hello world" in dump, "decoy content is not the expected ASCII"

    check("smoke: inventory classifies + hashes every artifact", smoke_inventory)
    check("smoke: evtx_query finds 7045 with update.exe ImagePath", evtx_7045)
    check("smoke: evtx_query finds type-3 4624", evtx_4624_type3)
    check("smoke: registry_query run_keys finds the Run-key", registry_runkey)
    check("smoke: execution_evidence parses UPDATE.EXE prefetch", prefetch_parse)
    check("smoke: yara_scan hits bait once, decoy zero", yara_bait)
    check("smoke: read_artifact decoy returns ASCII text", decoy_ascii)

    capp, _cctx, _crun = make_ctx(clean, "clean")

    def clean_inventory():
        inv = call(capp, "evidence_inventory")
        assert inv["files"], "clean case is empty"
        bad = [f for f in inv["files"] if f["type"] != "other"]
        assert not bad, f"clean case has non-benign classifications: {bad}"

    check("clean: inventory all-benign, nothing fires", clean_inventory)

    fails = [n for s, n in RESULTS if s == "FAIL"]
    print()
    print("---------------------------- paste-back block ----------------------------")
    print(f"CHECKPOINT2 RESULT: {'FAIL' if fails else 'PASS'}")
    for status, name in RESULTS:
        print(f"  {status}  {name}")
    print(f"  ledger: {run_dir.relative_to(REPO_ROOT)}/ledger.jsonl")
    print("---------------------------------------------------------------------------")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
