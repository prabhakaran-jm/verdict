"""Image-backed tools check for checklist item 10.

Plain stdlib + asyncio (no pytest), same style as tools_check.py. Exercises
fs_list, fs_extract, mft_query, timeline_query, and mem_analyze WITHOUT real
Sleuth Kit / Volatility binaries: runner extra_argv stubs emit canned output.
Real-image probes belong on the SIFT VM (checklist item 10 verify criteria).

Run:  python tests/image_tools_check.py
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
ENV: SimpleNamespace | None = None

BODYFILE = "\n".join([
    "0|/Users/Public/update.exe|23-128-1|r/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr|"
    "2020-11-04 02:21:00|2020-11-04 02:21:00|2020-11-04 02:21:00|"
    "2020-11-04 02:21:00|512|0|0|512",
    "0|/Windows/System32/cmd.exe|45-128-1|r/rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr|"
    "2020-11-04 02:35:00|2020-11-04 02:35:00|2020-11-04 02:35:00|"
    "2020-11-04 02:35:00|1024|0|0|1024",
])

STUB_FS = r'''
import sys
args = sys.argv[1:]
# mmls: <image>  (single positional arg, no flags) -> multi-partition table
if len(args) == 1 and not str(args[0]).isdigit():
    print("DOS Partition Table")
    print("Offset Sector: 0")
    print("Units are in 512-byte sectors")
    print("")
    print("      Slot      Start        End          Length       Description")
    print("000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)")
    print("001:  -------   0000000000   0000002047   0000002048   Unallocated")
    print("002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)")
    print("003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)")
    sys.exit(0)
# ifind: [-o N] -p <path> <image>  (-p is immediately followed by a /path)
if "-p" in args and args[args.index("-p") + 1].startswith("/"):
    print("12345")
# icat: [-o N] <image> <inode>
elif len(args) >= 2 and str(args[-1]).isdigit():
    sys.stdout.buffer.write(b"MZ" + b"\x00" * 64)
# fls
else:
    print("r/r * 1234-128-4:\tupdate.exe")
    print("d/d * 5678-128-4:\tWindows")
'''

STUB_MEMORY = r'''
print("Volatility 3 Framework 2.5.0")
print("PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime")
print("3644\t1234\tcoreupdater.exe\t0xabc123\t12\t450\t0\tFalse\t2020-11-04 02:21:00.000000 UTC")
print("5678\t3644\tcmd.exe\t0xdef456\t1\t25\t0\tFalse\t2020-11-04 02:35:00.000000 UTC")
'''

STUB_MFT = r'''
import sys
from pathlib import Path
scratch = Path(sys.argv[-1])
scratch.mkdir(parents=True, exist_ok=True)
(scratch / "MFT_000.csv").write_text(
    "EntryNumber,FullPath,InUse,Created0x10,LastModified0x10\n"
    "23,/Users/Public/update.exe,True,2020-11-04 02:21:00,2020-11-04 02:21:00\n"
    "45,/Windows/System32/cmd.exe,True,2020-11-04 02:35:00,2020-11-04 02:35:00\n",
    encoding="utf-8",
)
print("MFTECmd complete")
'''


def run_check(name: str, fn) -> None:
    try:
        fn()
    except Exception:
        FAILURES.append(name)
        print(f"FAIL  {name}")
        print("      " + traceback.format_exc().strip().replace("\n", "\n      "))
    else:
        print(f"PASS  {name}")


def build_env(base: Path) -> SimpleNamespace:
    from verdict_mcp.server import build_app

    case = base / "case"
    run = base / "run"
    stubs = base / "stubs"
    for d in (case, run, stubs):
        d.mkdir(parents=True)

    (case / "desktop.dd").write_bytes(b"\x00" * 64)
    (case / "capture.vmem").write_bytes(b"\x00" * 64)
    (case / "bodyfile.body").write_text(BODYFILE, encoding="utf-8")

    (stubs / "stub_fs.py").write_text(STUB_FS, encoding="utf-8")
    (stubs / "stub_memory.py").write_text(STUB_MEMORY, encoding="utf-8")
    (stubs / "stub_mft.py").write_text(STUB_MFT, encoding="utf-8")
    (stubs / "stub_timeline.py").write_text(
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if '-m' in args:\n"
        f"    print({BODYFILE!r})\n"
        "else:\n"
        "    print('Mon Nov  4 02:21:00 2020 .. m.. /Users/Public/update.exe')\n"
        "    print('Mon Nov  4 02:35:00 2020 .. m.. /Windows/System32/cmd.exe')\n",
        encoding="utf-8",
    )

    app, ctx = build_app(case, run)
    exe = sys.executable
    for cap in ("fs", "timeline", "memory", "mft"):
        ctx.runner.add_capability_override(
            cap, (exe, str(stubs / f"stub_{cap}.py")))
    return SimpleNamespace(case=case, run=run, app=app, ctx=ctx)


def call(name: str, args: dict) -> dict:
    result = asyncio.run(ENV.app.call_tool(name, args))
    _content, structured = result
    return structured


def read_ledger() -> list[dict]:
    return [json.loads(line) for line in
            (ENV.run / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]


def assert_pair(tool: str, response: dict, since: int = 0) -> None:
    lines = read_ledger()[since:]
    called = [l for l in lines if l["event"] == "tool_called" and l["tool"] == tool]
    results = [l for l in lines if l["event"] == "tool_result" and l["tool"] == tool]
    assert called and results, f"missing ledger pair for {tool}"
    result = results[-1]
    out_path = ENV.run / result["output_path"]
    assert out_path.is_file(), f"missing output: {out_path}"
    assert hashlib.sha256(out_path.read_bytes()).hexdigest() == result["output_sha256"]
    assert response.get("cite_seq") == result["seq"]


def expect_rejected(tool: str, args: dict, fragment: str) -> None:
    before = len(read_ledger())
    try:
        call(tool, args)
    except ToolError as exc:
        assert fragment.lower() in str(exc).lower(), exc
    else:
        raise AssertionError(f"{tool} should have been rejected")
    rejected = [l for l in read_ledger()[before:]
                if l["event"] == "tool_rejected" and l["tool"] == tool]
    assert rejected, f"no tool_rejected ledger line for {tool}"


def check_discover_offset() -> None:
    from verdict_mcp.tools._image_helpers import (
        _parse_mmls_offset,
        discover_partition_offset,
    )

    table = "\n".join([
        "DOS Partition Table",
        "Units are in 512-byte sectors",
        "      Slot      Start        End          Length       Description",
        "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)",
        "001:  -------   0000000000   0000002047   0000002048   Unallocated",
        "002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)",
        "003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)",
    ])
    # Largest-NTFS Start sector wins (22872064 > 716800 -> 718848).
    assert _parse_mmls_offset(table) == 718848, _parse_mmls_offset(table)
    # No NTFS rows -> None.
    assert _parse_mmls_offset("DOS Partition Table\n000:  Meta  0  0  1  unalloc") is None
    # Single partition at 2048 -> None (not a multi-partition disk).
    assert _parse_mmls_offset(
        "000:  000:000   0000002048   0000010000   0000007953   NTFS (0x07)") is None

    image_path = ENV.case / "desktop.dd"
    off = discover_partition_offset(ENV.ctx, image_path)
    assert off == 718848, off
    # Cached: a second call returns the same value without re-probing.
    assert discover_partition_offset(ENV.ctx, image_path) == 718848


def check_fs_list() -> None:
    since = len(read_ledger())
    out = call("fs_list", {"image": "desktop.dd", "path": "/", "recursive": False})
    assert not out.get("is_error"), out
    assert out["returned"] >= 1
    # partition_offset=None -> auto-discovered the largest-NTFS partition.
    assert out["partition_offset"] == 718848, out
    assert out["partition_offset_auto"] is True
    assert_pair("fs_list", out, since)
    # The fls invocation received `-o 718848` (the discovered offset). The last
    # tool_called for fs_list in this window is the real fls listing, after the
    # mmls probe; its recorded argv must carry the discovered offset.
    called = [l for l in read_ledger()[since:]
              if l["event"] == "tool_called" and l["tool"] == "fs_list"]
    fls_argv = [str(a) for a in called[-1]["argv"]]
    assert "-o" in fls_argv and "718848" in fls_argv, fls_argv


def check_fs_list_explicit_offset() -> None:
    out = call("fs_list", {
        "image": "desktop.dd", "path": "/", "partition_offset": 239616})
    assert not out.get("is_error"), out
    # Explicit offset passed through unchanged; no auto-discovery.
    assert out["partition_offset"] == 239616, out
    assert out["partition_offset_auto"] is False


def check_fs_extract_path() -> None:
    since = len(read_ledger())
    out = call("fs_extract", {
        "image": "desktop.dd",
        "target": "/Users/Public/update.exe",
    })
    assert not out.get("is_error"), out
    assert out["artifact_path"].startswith("artifacts/")
    artifact = ENV.run / out["artifact_path"]
    assert artifact.is_file() and artifact.read_bytes()[:2] == b"MZ"
    assert_pair("fs_extract", out, since)


def check_fs_extract_inode() -> None:
    out = call("fs_extract", {"image": "desktop.dd", "target": "12345"})
    assert out["inode"] == "12345"
    assert (ENV.run / out["artifact_path"]).is_file()


def check_mft_bodyfile() -> None:
    out = call("mft_query", {
        "mft_path": "bodyfile.body",
        "path_contains": "update.exe",
    })
    assert out["parser"] == "bodyfile"
    assert out["returned"] == 1
    assert "update.exe" in out["records"][0]["path"]


def check_mft_mftecmd_stub() -> None:
    since = len(read_ledger())
    mft_file = ENV.case / "fake.$MFT"
    mft_file.write_bytes(b"FILE" + b"\x00" * 64)
    out = call("mft_query", {"mft_path": mft_file.name, "path_contains": "cmd"})
    assert out["parser"] == "MFTECmd"
    assert out["returned"] == 1
    assert_pair("mft_query", out, since)


def check_timeline() -> None:
    since = len(read_ledger())
    out = call("timeline_query", {
        "image": "desktop.dd",
        "after": "2020-11-04T00:00:00",
        "before": "2020-11-04T23:59:59",
        "keyword": "update",
    })
    assert not out.get("is_error"), out
    assert out["returned"] >= 1
    assert "bodyfile/" in out["bodyfile"]
    assert_pair("timeline_query", out, since)
    cache = ENV.run / out["bodyfile"]
    assert cache.is_file()


def check_mem_analyze() -> None:
    since = len(read_ledger())
    out = call("mem_analyze", {
        "image": "capture.vmem",
        "plugin": "pslist",
        "filter": "coreupdater",
    })
    assert not out.get("is_error"), out
    assert "coreupdater" in out["excerpt"].lower()
    assert_pair("mem_analyze", out, since)


def check_rejections() -> None:
    expect_rejected("fs_list", {"image": "capture.vmem"}, "not a disk image")
    expect_rejected("mem_analyze", {
        "image": "desktop.dd", "plugin": "pslist"}, "not a memory image")
    expect_rejected("timeline_query", {
        "image": "desktop.dd",
        "after": "2020-11-05T00:00:00",
        "before": "2020-11-04T00:00:00",
    }, "after")
    expect_rejected("mem_analyze", {
        "image": "capture.vmem", "plugin": "evilplugin"}, "invalid parameters")


def main() -> int:
    global ENV
    checks = [
        ("discover_partition_offset: parse + pick largest NTFS + cache",
         check_discover_offset),
        ("fs_list: listing + ledger pair", check_fs_list),
        ("fs_list: explicit partition_offset passthrough",
         check_fs_list_explicit_offset),
        ("fs_extract: path target -> artifacts/", check_fs_extract_path),
        ("fs_extract: inode target", check_fs_extract_inode),
        ("mft_query: bodyfile fallback filter", check_mft_bodyfile),
        ("mft_query: MFTECmd stub path", check_mft_mftecmd_stub),
        ("timeline_query: bodyfile cache + mactime + keyword", check_timeline),
        ("mem_analyze: pslist + filter + ledger pair", check_mem_analyze),
        ("rejections: wrong image type, bad window, bad plugin", check_rejections),
    ]
    with tempfile.TemporaryDirectory() as td:
        ENV = build_env(Path(td))
        try:
            for name, fn in checks:
                run_check(name, fn)
        finally:
            ENV.ctx.ledger.close()
    total = len(checks)
    failed = len(FAILURES)
    print(f"\n{total - failed}/{total} checks passed")
    if FAILURES:
        print(f"FAILED: {', '.join(FAILURES)}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
