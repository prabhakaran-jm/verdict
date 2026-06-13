"""Shared helpers for image-backed tools (checklist item 10).

Classification, fls/ifind parsing, artifact naming, and bodyfile cache keys.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from verdict_mcp.tools.common import Rejection, in_window, parse_event_time
from verdict_mcp.tools.inventory import classify

if TYPE_CHECKING:
    from verdict_mcp.server import AppContext

#: Max entries returned from fs_list / timeline / mft (response budget).
MAX_LIST_ENTRIES = 500

#: When fs_list recursive=True, cap directory depth below `path`.
MAX_RECURSE_DEPTH = 4

_FLS_LINE = re.compile(
    r"^(?P<type>[rdl/+\-\|]+)\s+"
    r"(?P<deleted>\*|\-|\s*)\s*"
    r"(?P<inode>\d+)"
    r"(?:-(?P<gen>\d+)-(?P<par>\d+))?"
    r":\s+(?P<name>.+)$"
)

_IFIND_INODE = re.compile(r"(?:Inode:\s*)?(\d+)\s*$", re.MULTILINE)


def require_disk_image(path: Path, param: str = "image") -> None:
    kind = classify(path)
    if kind != "disk_image":
        raise Rejection(
            f"{param}='{path.name}' is not a disk image (classified as '{kind}'); "
            f"fs_list/fs_extract/timeline_query require a disk image (.E01/.dd/.raw)."
        )


def require_memory_image(path: Path, param: str = "image") -> None:
    kind = classify(path)
    if kind != "memory_image":
        raise Rejection(
            f"{param}='{path.name}' is not a memory image (classified as '{kind}'); "
            f"mem_analyze requires a memory capture (.mem/.vmem/.dmp/.raw)."
        )


def fls_runner_args(image: Path, *, partition_offset: int | None,
                    recursive: bool) -> list[str | Path]:
    args: list[str | Path] = []
    if partition_offset is not None:
        args.extend(["-o", str(partition_offset)])
    args.extend(["-p", "-l"])
    if recursive:
        args.append("-r")
    args.append(image)
    return args


#: Per-resolved-image cache of discovered partition offsets. Keyed by the
#: absolute image path; value is the chosen Start sector (int) or None when no
#: multi-partition NTFS layout was found (caller then runs without -o).
_PARTITION_OFFSET_CACHE: dict[str, int | None] = {}


def _parse_mmls_offset(text: str) -> int | None:
    """Pick the Start sector of the largest NTFS partition in `mmls` output.

    mmls emits a "DOS Partition Table" / "Units are in 512-byte sectors" header
    then rows like:
        003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)
    Column count varies between builds, so we split on whitespace and look for a
    row that has a numeric Start, a numeric Length, and "NTFS" anywhere in the
    trailing description. Among those, the row with the LARGEST Length wins (the
    Windows C: partition dwarfs System Reserved). Returns its Start sector, or
    None if no qualifying NTFS row exists.
    """
    best_start: int | None = None
    best_length = -1
    for raw in text.splitlines():
        line = raw.strip()
        parts = line.split()
        if len(parts) < 5:
            continue
        # Data rows start with a "NNN:" slot id; skip blank lines + header prose
        # ("DOS Partition Table", "Units are in 512-byte sectors", column titles).
        if not parts[0].endswith(":") or not parts[0].rstrip(":").isdigit():
            continue
        # Find the description tail and the numeric Start/Length columns. The
        # last three numeric-looking columns before the description are
        # Start, End, Length; we locate Start as the first all-digit token and
        # Length as the third all-digit token following the CHS/slot fields.
        # Start/End/Length are the 3 all-digit columns before the description;
        # the slot id ("003:") and CHS fields ("000:001") carry colons so they
        # are not picked up here.
        nums: list[tuple[int, int]] = [
            (idx, int(tok)) for idx, tok in enumerate(parts) if tok.isdigit()
        ]
        if len(nums) < 3:
            continue
        start = nums[-3][1]
        length = nums[-1][1]
        desc_start = nums[-1][0] + 1
        description = " ".join(parts[desc_start:])
        if "ntfs" not in description.lower():
            continue
        if length > best_length:
            best_length = length
            best_start = start
    # A single partition starting at 0 or 2048 is not a multi-partition disk;
    # treat tiny/degenerate layouts as "no override needed".
    if best_start is not None and best_start <= 2048:
        return None
    return best_start


def discover_partition_offset(ctx: "AppContext", image_path: Path) -> int | None:
    """Probe `image_path` with mmls and return the main NTFS Start sector.

    Runs `mmls` through the runner (so the probe is ledgered for audit), parses
    its output, and caches the result per absolute image path so repeated
    fs_list/fs_extract/timeline calls don't re-probe. Returns None when mmls
    fails, emits no NTFS rows, or shows a single partition at 0/2048 (caller then
    runs without -o, the prior behavior)."""
    key = str(image_path.resolve())
    if key in _PARTITION_OFFSET_CACHE:
        return _PARTITION_OFFSET_CACHE[key]
    offset: int | None = None
    try:
        run = ctx.runner.run_tool(
            "fs", [image_path], tool="fs_list",
            params={"probe": "mmls", "image": image_path.name},
            ext="txt", component="mmls",
        )
        if not run.is_error:
            text = run.output_path.read_text(encoding="utf-8", errors="replace")
            offset = _parse_mmls_offset(text)
    except Exception:
        # mmls unavailable / unresolvable: fall back to no-offset behavior.
        offset = None
    _PARTITION_OFFSET_CACHE[key] = offset
    return offset


def bodyfile_cache_path(run_dir: Path, image: Path,
                        partition_offset: int | None) -> Path:
    key = f"{image.resolve()}|{partition_offset or 0}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    return run_dir / "bodyfile" / f"{digest}.body"


def safe_artifact_name(target: str) -> str:
    if target.isdigit():
        return f"inode_{target}"
    name = PurePosixPath(target.replace("\\", "/")).name
    if not name or name in (".", ".."):
        return "extracted.bin"
    return name.replace(":", "_")


def parse_ifind_inode(text: str) -> str:
    match = _IFIND_INODE.search(text.strip())
    if not match:
        raise Rejection(
            "ifind did not return an inode for that path (file may not exist "
            "in the image)"
        )
    return match.group(1)


def _norm_path(path: str) -> str:
    p = PurePosixPath(path.replace("\\", "/"))
    if str(p) in ("", "."):
        return "/"
    out = "/" + "/".join(part for part in p.parts if part not in ("", "."))
    return out.rstrip("/") or "/"


def _child_depth(base: str, full: str) -> int:
    base_parts = [p for p in _norm_path(base).split("/") if p]
    full_parts = [p for p in _norm_path(full).split("/") if p]
    if len(full_parts) < len(base_parts):
        return -1
    if full_parts[: len(base_parts)] != base_parts:
        return -1
    return len(full_parts) - len(base_parts)


def parse_fls_listing(text: str, *, path: str, recursive: bool) -> list[dict]:
    """Parse `fls -p -l` output into entry dicts under `path`."""
    base = _norm_path(path)
    entries: list[dict] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("Full Path"):
            continue
        entry: dict | None = None
        if line.startswith("/") or "|" in line[:3]:
            # bodyfile-style path line from some fls builds: 0|/path|...
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    full = _norm_path(parts[1])
                    inode = parts[2].split("-")[0] if len(parts) > 2 else ""
                    entry = {
                        "path": full,
                        "name": PurePosixPath(full).name,
                        "inode": inode,
                        "type": parts[0],
                        "deleted": "d" in parts[0].lower(),
                    }
            else:
                full = _norm_path(line)
                entry = {
                    "path": full,
                    "name": PurePosixPath(full).name,
                    "inode": "",
                    "type": "?",
                    "deleted": False,
                }
        else:
            match = _FLS_LINE.match(line)
            if not match:
                continue
            name = match.group("name").strip()
            full = _norm_path(f"{base}/{name}" if base != "/" else f"/{name}")
            entry = {
                "path": full,
                "name": name,
                "inode": match.group("inode"),
                "type": match.group("type"),
                "deleted": match.group("deleted").strip() == "*",
            }
        if entry is None:
            continue
        full = _norm_path(entry["path"])
        if base != "/":
            if full != base and not full.startswith(base + "/"):
                continue
        depth = _child_depth(base, full)
        if depth < 0:
            continue
        if not recursive and depth > 1:
            continue
        if recursive and depth > MAX_RECURSE_DEPTH:
            continue
        if full in seen:
            continue
        seen.add(full)
        entries.append(entry)
        if len(entries) >= MAX_LIST_ENTRIES:
            break
    return entries


def parse_bodyfile(text: str, *, path_contains: str | None,
                   after: datetime | None, before: datetime | None,
                   deleted_only: bool) -> list[dict]:
    """Parse `fls -m` bodyfile lines with optional filters."""
    needle = path_contains.lower() if path_contains else None
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Md5"):
            continue
        parts = line.split("|")
        if len(parts) < 11:
            continue
        md5, name, inode, mode = parts[0], parts[1], parts[2], parts[3]
        times = parts[4:8]
        deleted = "d" in mode.lower() or md5 == "0"
        if deleted_only and not deleted:
            continue
        if needle and needle not in name.lower():
            continue
        when = parse_event_time(times[0]) or parse_event_time(times[1])
        if not in_window(when, after, before):
            continue
        rows.append({
            "path": name,
            "inode": inode.split("-")[0] if inode else "",
            "mode": mode,
            "deleted": deleted,
            "times": {
                "atime": times[0],
                "mtime": times[1],
                "ctime": times[2],
                "crtime": times[3],
            },
        })
        if len(rows) >= MAX_LIST_ENTRIES:
            break
    return rows


def parse_mactime(text: str, *, keyword: str | None) -> list[dict]:
    needle = keyword.lower() if keyword else None
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Date"):
            continue
        if needle and needle not in line.lower():
            continue
        # mactime: Mon Jun 10 09:00:00 2026 ... /path
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        rows.append({
            "time": " ".join(parts[0:5]),
            "activity": parts[5].split()[0] if len(parts[5].split()) > 1 else "",
            "path": parts[5].split()[-1] if parts[5] else parts[5],
            "raw": line,
        })
        if len(rows) >= MAX_LIST_ENTRIES:
            break
    return rows
