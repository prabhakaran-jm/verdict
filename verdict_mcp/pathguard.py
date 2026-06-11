"""Path guard - evidence read-only / run-dir write-only enforcement.

Spec ref: spec.md > MCP Server > Path guard (pathguard.py).
PRD ref: prd.md > Constrained Tooling.

Every path parameter is resolved to an absolute real path (Path.resolve():
symlinks followed, '..' collapsed) BEFORE containment is checked, so neither
symlink escapes nor `..\\..\\` traversal can slip through. Containment is
component-wise (os.path.commonpath on case-normalized paths), so prefix tricks
like `/case-evil` vs `/case` cannot fool it.

Policy bound to one run:
  reads  -> under the case dir OR the run dir (the verifier re-reads stored
            outputs from the run dir; spec tool #11 `read_artifact` allows both)
  writes -> ONLY under the run dir

Violations raise PathViolation with a clear, model-readable message; the
caller ledgers the refusal as `tool_rejected`. Nothing in the server ever
opens an evidence file for writing.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathViolation(Exception):
    """Raised when a path escapes its allowed root; always ledgered as tool_rejected."""


def _resolve(path: str | Path) -> Path:
    """Absolute real path: symlinks followed, '..' collapsed, drive-normalized."""
    try:
        return Path(path).resolve()
    except OSError as exc:  # e.g. unresolvable junction loops on Windows
        raise PathViolation(
            f"path '{path}' could not be resolved: {exc}"
        ) from exc


def _is_within(target: Path, root: Path) -> bool:
    """True iff resolved `target` is `root` itself or inside it.

    Component-wise comparison (never a raw string prefix), case-normalized for
    Windows; ValueError from commonpath means different drives -> outside.
    Both arguments must already be resolved.
    """
    t = os.path.normcase(str(target))
    r = os.path.normcase(str(root))
    try:
        return os.path.commonpath((t, r)) == r
    except ValueError:
        return False


class PathGuard:
    """Containment policy bound to (case_dir, run_dir) for one server process."""

    def __init__(self, case_dir: str | Path, run_dir: str | Path) -> None:
        self.case_dir = Path(case_dir).resolve()
        self.run_dir = Path(run_dir).resolve()

    def resolve_read(self, path: str | Path, param: str = "path") -> Path:
        """Resolve `path` and require it under the case dir or the run dir.

        Returns the resolved absolute Path on success; raises PathViolation
        otherwise. Call this on EVERY model-supplied path before any read.
        """
        resolved = _resolve(path)
        if _is_within(resolved, self.case_dir) or _is_within(resolved, self.run_dir):
            return resolved
        raise PathViolation(
            f"read of {param}='{path}' refused: it resolves to '{resolved}', "
            f"which is outside both the evidence directory ('{self.case_dir}') "
            f"and the run directory ('{self.run_dir}'). Reads are allowed only "
            f"inside those two directories."
        )

    def resolve_write(self, path: str | Path, param: str = "path") -> Path:
        """Resolve `path` and require it under the run dir (the only write root).

        Returns the resolved absolute Path on success; raises PathViolation
        otherwise. Evidence is never writable - not even by the server.
        """
        resolved = _resolve(path)
        if _is_within(resolved, self.run_dir):
            return resolved
        if _is_within(resolved, self.case_dir):
            raise PathViolation(
                f"write of {param}='{path}' refused: '{resolved}' is inside "
                f"the evidence directory, which is strictly read-only. Writes "
                f"are allowed only under the run directory ('{self.run_dir}')."
            )
        raise PathViolation(
            f"write of {param}='{path}' refused: it resolves to '{resolved}', "
            f"which is outside the run directory ('{self.run_dir}'). Writes "
            f"are allowed only under the run directory."
        )
