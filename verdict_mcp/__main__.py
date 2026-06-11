"""Entry point: python -m verdict_mcp --case <dir> --run <run_dir>.

Spec ref: spec.md > Orchestrator > MCP client (spawn command) and
spec.md > MCP Server. Filled in by checklist item 3.
"""

from __future__ import annotations

import sys


def main() -> int:
    # TODO(item 3): parse --case/--run, build the FastMCP app from server.py,
    #   run over stdio transport.
    print("verdict_mcp scaffold: server lands in checklist item 3.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
