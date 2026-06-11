"""Subprocess runner - the single choke point for all external binaries.

Spec ref: spec.md > MCP Server > Subprocess runner (runner.py).
Filled in by checklist item 3.

Fixed executable paths from binaries.py (never from model input), shell=False,
argument lists built from validated params, per-tool timeout (default 120 s;
mem_analyze 600 s), stdout/stderr captured. Full output ->
runs/<id>/outputs/<seq>_<tool>.{json,txt} + SHA-256 -> ledger. The model
receives an excerpt capped at 8 KB plus a pointer to the full artifact.
Nonzero exit -> structured error result (is_error), ledgered; retry once, then
route around - one broken parser never kills the run.
"""

from __future__ import annotations

DEFAULT_TIMEOUT_S = 120
MEM_ANALYZE_TIMEOUT_S = 600
EXCERPT_CAP_BYTES = 8 * 1024


def run_binary(tool: str, argv: list[str], *, run_dir: str, ledger,
               timeout_s: int = DEFAULT_TIMEOUT_S) -> dict:
    """Execute one fixed binary; persist + hash full output; return capped excerpt.

    TODO(item 3): shell=False subprocess, timeout, output file + SHA-256,
    ledger tool_called/tool_result pair, structured error on nonzero exit.
    """
    raise NotImplementedError("Implemented in checklist item 3.")
