"""Tools 2-3: fs_list, fs_extract (disk images).

Spec ref: spec.md > MCP Server > Tool definitions > #2 fs_list, #3 fs_extract.
Built by checklist item 10.

fs_list: list files in a disk image path. Params: image, partition_offset?,
path, recursive? (depth-capped). Wraps Sleuth Kit fls (E01 via libewf, native
on SIFT). No mounting - no root needed.

fs_extract: extract one file from an image into runs/<id>/artifacts/ for
downstream parsing. Params: image, partition_offset?, target (inode or path).
Wraps ifind + icat.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from verdict_mcp.tools._image_helpers import (
    discover_partition_offset,
    fls_runner_args,
    parse_fls_listing,
    parse_ifind_inode,
    require_disk_image,
    safe_artifact_name,
)
from verdict_mcp.tools.common import cap_items, clean_params, require_file

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext


def _resolve_offset(ctx: "AppContext", image_path: "Path",
                    partition_offset: int | None) -> tuple[int | None, bool]:
    """Decide the partition offset for an fls/icat/ifind invocation.

    Explicit `partition_offset` (not None) is honored verbatim — the model can
    still force a partition. When None, probe mmls once (cached) to auto-target
    the main Windows/NTFS partition on a multi-partition disk. Returns
    (offset, auto) where `auto` is True iff the offset came from discovery."""
    if partition_offset is not None:
        return partition_offset, False
    return discover_partition_offset(ctx, image_path), True


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def fs_list(
        image: str,
        path: Annotated[str, Field(
            description="Directory path inside the image (e.g. / or /Users/Public)")]
            = "/",
        partition_offset: Annotated[int | None, Field(
            ge=0, description="Partition byte offset when the image is split")]
            = None,
        recursive: Annotated[bool, Field(
            description="Recurse under path (depth-capped server-side)")]
            = False,
    ) -> dict[str, Any]:
        """List files and directories inside a disk image at `path`.

        Uses Sleuth Kit `fls` (E01 supported via libewf). Narrow with `path`
        and optional recursion; results are capped. Returns inode, type, and
        path entries plus a pointer to the full fls output in the run folder."""
        image_path = require_file(
            ctx.pathguard.resolve_read(image, "image"), "image")
        require_disk_image(image_path, "image")
        offset, auto = _resolve_offset(ctx, image_path, partition_offset)
        params = clean_params(image=image, path=path,
                              partition_offset=partition_offset,
                              recursive=recursive)

        run = ctx.runner.run_tool(
            "fs", fls_runner_args(image_path, partition_offset=offset,
                                  recursive=recursive),
            tool="fs_list", params=params, ext="txt", component="fls",
        )
        if run.is_error:
            return run.payload()

        text = run.output_path.read_text(encoding="utf-8", errors="replace")
        entries = parse_fls_listing(text, path=path, recursive=recursive)
        kept, capped = cap_items(entries)
        return {
            "image": image,
            "path": path,
            "recursive": recursive,
            "total_entries": len(entries),
            "returned": len(kept),
            "entries": kept,
            "truncated": capped or len(kept) < len(entries),
            "partition_offset": offset,
            "partition_offset_auto": auto,
            "excerpt": run.excerpt,
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }

    @app.tool(structured_output=True)
    def fs_extract(
        image: str,
        target: Annotated[str, Field(
            description="Inode number or full path inside the image")],
        partition_offset: Annotated[int | None, Field(
            ge=0, description="Partition byte offset when the image is split")]
            = None,
    ) -> dict[str, Any]:
        """Extract one file from a disk image into the run's artifacts/ folder.

        `target` is either a decimal inode or a path (resolved with ifind,
        then extracted with icat). The artifact is written under
        runs/<id>/artifacts/ for downstream tools (registry_query, yara_scan,
        read_artifact). Returns the artifact path and SHA-256."""
        image_path = require_file(
            ctx.pathguard.resolve_read(image, "image"), "image")
        require_disk_image(image_path, "image")
        offset, auto = _resolve_offset(ctx, image_path, partition_offset)
        params = clean_params(image=image, target=target,
                              partition_offset=partition_offset)

        inode = target.strip()
        if not inode.isdigit():
            ifind_args: list[str | Path] = ["-p", target]
            if offset is not None:
                ifind_args = ["-o", str(offset), *ifind_args]
            ifind_args.append(image_path)
            find = ctx.runner.run_tool(
                "fs", ifind_args, tool="fs_extract", params=params,
                ext="txt", component="ifind",
            )
            if find.is_error:
                return find.payload()
            inode = parse_ifind_inode(find.output_path.read_text(
                encoding="utf-8", errors="replace"))

        icat_args: list[str | Path] = []
        if offset is not None:
            icat_args.extend(["-o", str(offset)])
        icat_args.extend([image_path, inode])
        run = ctx.runner.run_tool(
            "fs", icat_args, tool="fs_extract", params=params,
            ext="bin", component="icat",
        )
        if run.is_error:
            return run.payload()

        artifact_name = safe_artifact_name(target)
        artifact_rel = f"artifacts/{artifact_name}"
        dest = ctx.pathguard.resolve_write(artifact_rel, "artifact")
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = run.output_path.read_bytes()
        dest.write_bytes(data)

        return {
            "image": image,
            "target": target,
            "inode": inode,
            "partition_offset": offset,
            "partition_offset_auto": auto,
            "artifact_path": artifact_rel,
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
