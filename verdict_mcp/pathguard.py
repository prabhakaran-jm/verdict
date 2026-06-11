"""Path guard - evidence read-only / run-dir write-only enforcement.

Spec ref: spec.md > MCP Server > Path guard (pathguard.py).
Filled in by checklist item 3.

Resolves every path param to an absolute real path (symlinks resolved). Reads
must fall under the case dir; writes only under the run dir. Violations ->
typed refusal, ledgered as tool_rejected. Evidence files are never opened for
writing anywhere in the server.
"""

from __future__ import annotations


class PathViolation(Exception):
    """Raised when a path escapes its allowed root; always ledgered."""


def assert_readable(path: str, case_dir: str) -> str:
    """Resolve and require path under case_dir (or run dir for outputs). TODO(item 3)."""
    raise NotImplementedError("Implemented in checklist item 3.")


def assert_writable(path: str, run_dir: str) -> str:
    """Resolve and require path under run_dir. TODO(item 3)."""
    raise NotImplementedError("Implemented in checklist item 3.")
