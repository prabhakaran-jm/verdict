"""Entry point: python -m verdict_mcp --case <dir> --run <run_dir>.

Spec ref: spec.md > Orchestrator > MCP client (spawn command) and
spec.md > MCP Server. The orchestrator spawns this over stdio, once per run.
"""

from __future__ import annotations

import argparse
import sys

from verdict_mcp.server import build_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verdict_mcp",
        description="VERDICT MCP server (stdio transport): typed read-only "
                    "forensic tools + server-written audit ledger.",
    )
    parser.add_argument("--case", required=True,
                        help="evidence directory (read-only root)")
    parser.add_argument("--run", required=True,
                        help="run directory (write root; ledger.jsonl lives here)")
    args = parser.parse_args(argv)

    try:
        app, ctx = build_app(args.case, args.run)
    except ValueError as exc:
        print(f"verdict-mcp: {exc}", file=sys.stderr)
        return 1

    try:
        app.run(transport="stdio")
    finally:
        ctx.ledger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
