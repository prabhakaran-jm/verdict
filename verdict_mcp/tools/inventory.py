"""Tool 1: evidence_inventory (triage only).

Spec ref: spec.md > MCP Server > Tool definitions > #1 evidence_inventory.

Walk the case dir; classify each file (disk image / memory image / loose
artifact by type / pcap - pcap noted, NEVER parsed, per PRD non-goals);
SHA-256 everything. Pure Python (hashlib + a magic-byte sniff standing in
for `file`), ledgered via the pure-tool conventions in common.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from verdict_mcp.tools.common import cap_items, pure_tool_call, sha256_file

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

_DISK_EXTS = {".e01", ".ex01", ".dd", ".img"}
_MEMORY_EXTS = {".mem", ".vmem", ".dmp"}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
_HIVE_NAMES = {"sam", "security", "software", "system", "default",
               "ntuser.dat", "usrclass.dat", "amcache.hve"}

PCAP_NOTE = ("pcap files are inventoried but never parsed "
             "(prd.md non-goal: no deep pcap analysis)")


def _magic(path: Path) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(8)
    except OSError:
        return b""


def classify(path: Path) -> str:
    """One evidence type per file - extension first, magic bytes to settle
    ambiguity (.raw serves both disk and memory in the wild)."""
    name = path.name.lower()
    ext = path.suffix.lower()
    if name in _HIVE_NAMES or ext == ".hve":
        return "registry_hive"
    if ext in _DISK_EXTS:
        return "disk_image"
    if ext in _MEMORY_EXTS:
        return "memory_image"
    if ext == ".raw":  # spec lists .raw under both image kinds; name decides
        return "memory_image" if ("mem" in name or "ram" in name) else "disk_image"
    if ext == ".evtx":
        return "evtx"
    if ext == ".pf":
        return "prefetch"
    if ext in _PCAP_EXTS:
        return "pcap"
    magic = _magic(path)
    if magic[:4] == b"regf":
        return "registry_hive"
    if magic[:8] == b"ElfFile\x00":
        return "evtx"
    if magic[:4] in (b"MAM\x04", b"MAM\x00"):
        return "prefetch"
    if magic[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    return "other"


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def evidence_inventory() -> dict[str, Any]:
        """Walk the case directory and inventory every evidence file:
        type (disk_image, memory_image, evtx, registry_hive, prefetch,
        pcap, other), size in bytes, and SHA-256. The starting point of
        every investigation; pcap files are noted but never parsed.
        No parameters."""

        def compute() -> tuple[Any, dict[str, Any], bool]:
            files = []
            for path in sorted(ctx.case_dir.rglob("*")):
                if not path.is_file():
                    continue
                files.append({
                    "path": path.relative_to(ctx.case_dir).as_posix(),
                    "type": classify(path),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                })
            counts: dict[str, int] = {}
            for entry in files:
                counts[entry["type"]] = counts.get(entry["type"], 0) + 1
            full = {"case_dir": str(ctx.case_dir), "total_files": len(files),
                    "counts": counts, "files": files}
            kept, truncated = cap_items(files)
            response: dict[str, Any] = {
                "case_dir": str(ctx.case_dir),
                "total_files": len(files),
                "counts": counts,
                "files": kept,
            }
            if counts.get("pcap"):
                response["pcap_note"] = PCAP_NOTE
            return full, response, truncated

        return pure_tool_call(ctx, "evidence_inventory", {}, compute)
