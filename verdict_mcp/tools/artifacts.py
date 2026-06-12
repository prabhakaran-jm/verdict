"""Tool 11: read_artifact.

Spec ref: spec.md > MCP Server > Tool definitions > #11 read_artifact.

Bounded read of a loose case file OR a stored run-dir output. Params:
path, offset? (>=0), length (REQUIRED, <=8 KiB), mode (text|hex). Pure
Python; the verifier's content-inspection workhorse - this is what reads
the smoke-case mimikatz.exe decoy and finds 12 bytes of ASCII text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import Field

from verdict_mcp.tools.common import clean_params, pure_tool_call, require_file

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

MAX_LENGTH = 8 * 1024


def hexdump(data: bytes, base: int) -> str:
    """Classic 16-bytes-per-line hexdump with absolute file offsets."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def read_artifact(
        path: str,
        length: Annotated[int, Field(
            ge=1, le=MAX_LENGTH,
            description="Bytes to read (required; <=8192)")],
        offset: Annotated[int, Field(
            ge=0, description="Byte offset to start from")] = 0,
        mode: Annotated[Literal["text", "hex"], Field(
            description="text: UTF-8 (bad bytes replaced); hex: hexdump")]
            = "text",
    ) -> dict[str, Any]:
        """Bounded read of a file's raw content - a loose evidence file in
        the case directory or a stored tool output in the run directory.
        Reads at most `length` bytes (<=8192) from `offset`; returns the
        content as UTF-8 text or a hexdump. Use it to inspect what a file
        actually contains before believing its name."""
        resolved = require_file(ctx.pathguard.resolve_read(path), "path")
        params = clean_params(path=path, offset=offset, length=length,
                              mode=mode)

        def compute() -> tuple[Any, dict[str, Any], bool]:
            file_size = resolved.stat().st_size
            with open(resolved, "rb") as fh:
                fh.seek(offset)
                data = fh.read(length)
            if mode == "hex":
                content = hexdump(data, offset)
            else:
                content = data.decode("utf-8", errors="replace")
            payload: dict[str, Any] = {
                "path": path,
                "file_size": file_size,
                "offset": offset,
                "returned_bytes": len(data),
                "eof": offset + len(data) >= file_size,
                "mode": mode,
                "content": content,
            }
            return payload, dict(payload), False

        return pure_tool_call(ctx, "read_artifact", params, compute,
                              ext="json")
