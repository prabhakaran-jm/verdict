"""Tool 9: mem_analyze.

Spec ref: spec.md > MCP Server > Tool definitions > #9 mem_analyze.
Built by checklist item 10.

Run one ALLOWED Volatility 3 plugin. Params: image, plugin (enum below),
filter?. Plugin allowlist enforced server-side - arbitrary plugin names
rejected (and the rejection ledgered).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from verdict_mcp.tools._image_helpers import require_memory_image
from verdict_mcp.tools.common import cap_text, clean_params, require_file

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

PLUGIN_ALLOWLIST = (
    "pslist", "pstree", "psscan", "netscan",
    "malfind", "cmdline", "dlllist", "handles",
)

VolPlugin = Literal[
    "pslist", "pstree", "psscan", "netscan",
    "malfind", "cmdline", "dlllist", "handles",
]


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def mem_analyze(
        image: str,
        plugin: Annotated[VolPlugin, Field(
            description="Volatility 3 windows.* plugin name (allowlisted)")],
        filter: Annotated[str | None, Field(
            description="Case-insensitive substring filter on output lines")]
            = None,
    ) -> dict[str, Any]:
        """Run one allowed Volatility 3 plugin against a memory capture.

        Plugins: pslist, pstree, psscan, netscan, malfind, cmdline, dlllist,
        handles. Arbitrary plugin names are refused server-side. Optionally
        narrow with a line filter before the response is capped."""
        image_path = require_file(
            ctx.pathguard.resolve_read(image, "image"), "image")
        require_memory_image(image_path, "image")
        params = clean_params(image=image, plugin=plugin, filter=filter)

        vol_plugin = f"windows.{plugin}"
        args: list[str | Path] = ["-f", image_path, vol_plugin]
        run = ctx.runner.run_tool(
            "memory", args, tool="mem_analyze", params=params, ext="txt",
        )
        if run.is_error:
            return run.payload()

        text = run.output_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if filter:
            needle = filter.lower()
            lines = [line for line in lines if needle in line.lower()]
        filtered = "\n".join(lines)
        excerpt, truncated = cap_text(filtered if filter else text)
        return {
            "image": image,
            "plugin": plugin,
            "vol_plugin": vol_plugin,
            "line_count": len(lines),
            "excerpt": excerpt,
            "truncated": truncated or (filter is not None and len(lines) < len(text.splitlines())),
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
