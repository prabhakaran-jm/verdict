"""Tool 8: timeline_query.

Spec ref: spec.md > MCP Server > Tool definitions > #8 timeline_query.
Built by checklist item 10.

Filesystem timeline pivots. Params: image, after, before (window REQUIRED),
keyword?. Wraps fls -m -> mactime; bodyfile built once per image and cached in
runs/<id>/bodyfile/.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from verdict_mcp.tools._image_helpers import (
    bodyfile_cache_path,
    discover_partition_offset,
    parse_mactime,
    require_disk_image,
)
from verdict_mcp.tools.common import Rejection, cap_items, clean_params, require_file

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext


def _mactime_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def timeline_query(
        image: str,
        after: Annotated[datetime, Field(
            description="Start of the required time window (ISO timestamp)")],
        before: Annotated[datetime, Field(
            description="End of the required time window (ISO timestamp)")],
        keyword: Annotated[str | None, Field(
            description="Case-insensitive substring filter on timeline rows")]
            = None,
        partition_offset: Annotated[int | None, Field(
            ge=0, description="Partition byte offset when the image is split")]
            = None,
    ) -> dict[str, Any]:
        """Filesystem timeline for a disk image within a required time window.

        Builds (or reuses) a cached bodyfile under bodyfile/, runs mactime for
        the requested window, and optionally filters by keyword. Always narrow
        with after/before — never slurp the whole image timeline."""
        if after > before:
            raise Rejection(
                f"after ({after.isoformat()}) must be at or before "
                f"before ({before.isoformat()})"
            )

        image_path = require_file(
            ctx.pathguard.resolve_read(image, "image"), "image")
        require_disk_image(image_path, "image")
        if partition_offset is not None:
            offset, auto = partition_offset, False
        else:
            offset, auto = discover_partition_offset(ctx, image_path), True
        params = clean_params(image=image, after=after, before=before,
                              keyword=keyword,
                              partition_offset=partition_offset)

        cache = bodyfile_cache_path(ctx.run_dir, image_path, offset)
        if not cache.is_file():
            cache.parent.mkdir(parents=True, exist_ok=True)
            fls_args: list[str | Path] = ["-r", "-m", "/"]
            if offset is not None:
                fls_args = ["-o", str(offset), *fls_args]
            fls_args.append(image_path)
            build = ctx.runner.run_tool(
                "timeline", fls_args, tool="timeline_query", params=params,
                ext="body", component="fls",
            )
            if build.is_error:
                return build.payload()
            cache.write_bytes(build.output_path.read_bytes())

        mactime_args: list[str | Path] = [
            "-b", cache,
            "-d", _mactime_date(after),
            "-d", _mactime_date(before),
        ]
        run = ctx.runner.run_tool(
            "timeline", mactime_args, tool="timeline_query", params=params,
            ext="txt", component="mactime",
        )
        if run.is_error:
            return run.payload()

        text = run.output_path.read_text(encoding="utf-8", errors="replace")
        matches = parse_mactime(text, keyword=keyword)
        kept, capped = cap_items(matches)
        return {
            "image": image,
            "after": after.isoformat(),
            "before": before.isoformat(),
            "bodyfile": cache.relative_to(ctx.run_dir).as_posix(),
            "partition_offset": offset,
            "partition_offset_auto": auto,
            "total_matches": len(matches),
            "returned": len(kept),
            "entries": kept,
            "truncated": capped or len(kept) < len(matches),
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
