"""Tool 4: mft_query.

Spec ref: spec.md > MCP Server > Tool definitions > #4 mft_query.
Built by checklist item 10.

Parse an extracted $MFT (via fs_extract) or a cached bodyfile with filters:
path_contains?, after?, before?, deleted_only?. Primary: MFTECmd (.NET);
fallback: parse `fls -m` bodyfile lines in Python.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from verdict_mcp import binaries
from verdict_mcp.tools._image_helpers import MAX_LIST_ENTRIES, parse_bodyfile
from verdict_mcp.tools.common import (
    Rejection,
    cap_items,
    clean_params,
    in_window,
    parse_event_time,
    require_file,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext


def _looks_like_bodyfile(path: Path) -> bool:
    try:
        sample = path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return False
    return "|" in sample and ("0|" in sample or "Md5|" in sample)


def _filter_mftecmd_rows(rows: list[dict], *, path_contains: str | None,
                         after: datetime | None, before: datetime | None,
                         deleted_only: bool) -> list[dict]:
    needle = path_contains.lower() if path_contains else None
    kept: list[dict] = []
    for row in rows:
        path = str(row.get("FullPath") or row.get("ParentPath") or "")
        if needle and needle not in path.lower():
            continue
        in_use = str(row.get("InUse", "True")).lower()
        deleted = in_use in ("false", "0", "no")
        if deleted_only and not deleted:
            continue
        when = (parse_event_time(row.get("Created0x10"))
                or parse_event_time(row.get("LastModified0x10"))
                or parse_event_time(row.get("LastAccess0x10")))
        if not in_window(when, after, before):
            continue
        kept.append({
            "path": path,
            "inode": str(row.get("EntryNumber", "")),
            "deleted": deleted,
            "created": row.get("Created0x10"),
            "modified": row.get("LastModified0x10"),
        })
        if len(kept) >= MAX_LIST_ENTRIES:
            break
    return kept


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def mft_query(
        mft_path: str,
        path_contains: Annotated[str | None, Field(
            description="Case-insensitive substring match on the file path")]
            = None,
        after: Annotated[datetime | None, Field(
            description="Only records at/after this ISO timestamp")] = None,
        before: Annotated[datetime | None, Field(
            description="Only records at/before this ISO timestamp")] = None,
        deleted_only: Annotated[bool, Field(
            description="Return only deleted MFT records")] = False,
    ) -> dict[str, Any]:
        """Query an extracted $MFT file or bodyfile with narrowing filters.

        Pass the artifact path from fs_extract (or a cached bodyfile under
        bodyfile/). MFTECmd is used when available; otherwise bodyfile lines
        are filtered in Python."""
        path = require_file(
            ctx.pathguard.resolve_read(mft_path, "mft_path"), "mft_path")
        params = clean_params(mft_path=mft_path, path_contains=path_contains,
                              after=after, before=before,
                              deleted_only=deleted_only)

        resolved = binaries.try_resolve("mft") if not ctx.runner.has_capability_override(
            "mft") else None
        if _looks_like_bodyfile(path):
            text = path.read_text(encoding="utf-8", errors="replace")
            matches = parse_bodyfile(
                text, path_contains=path_contains, after=after,
                before=before, deleted_only=deleted_only,
            )
            kept, capped = cap_items(matches)
            return {
                "mft_path": mft_path,
                "parser": "bodyfile",
                "total_matches": len(matches),
                "returned": len(kept),
                "records": kept,
                "truncated": capped or len(kept) < len(matches),
                "is_error": False,
            }

        use_mftecmd = (
            ctx.runner.has_capability_override("mft")
            or (resolved is not None and resolved.tier == "primary")
        )
        if not use_mftecmd:
            raise Rejection(
                f"mft_path='{path.name}' is not a bodyfile and MFTECmd is "
                f"unavailable on this host; extract $MFT with fs_extract or "
                f"provide a fls -m bodyfile."
            )

        scratch = ctx.run_dir / "scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        args: list[str | Path] = ["-f", path, "--csv", scratch]
        run = ctx.runner.run_tool("mft", args, tool="mft_query", params=params,
                                  ext="csv")
        if run.is_error:
            return run.payload()

        csv_files = sorted(scratch.glob("*_*.csv"))
        if not csv_files:
            out = run.payload()
            out["is_error"] = True
            out["error"] = "MFTECmd produced no CSV output"
            return out

        raw_rows: list[dict] = []
        for csv_path in csv_files:
            with csv_path.open(encoding="utf-8-sig", errors="replace",
                               newline="") as fh:
                raw_rows.extend(list(csv.DictReader(fh)))

        matches = _filter_mftecmd_rows(
            raw_rows, path_contains=path_contains, after=after,
            before=before, deleted_only=deleted_only,
        )
        kept, capped = cap_items(matches)
        return {
            "mft_path": mft_path,
            "parser": "MFTECmd",
            "total_matches": len(matches),
            "returned": len(kept),
            "records": kept,
            "truncated": capped or len(kept) < len(matches),
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
