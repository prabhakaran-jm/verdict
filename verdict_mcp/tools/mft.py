"""Tool 4: mft_query.

Spec ref: spec.md > MCP Server > Tool definitions > #4 mft_query.
Filled in by checklist item 10.

Parse MFT (extracted via fs_extract) with filters: path_contains?, after?,
before?, deleted_only?. Wraps MFTECmd (fallback: fls -m bodyfile filtering,
per the item-2 gate decision).
"""

from __future__ import annotations


def mft_query(mft_path: str, path_contains: str | None = None,
              after: str | None = None, before: str | None = None,
              deleted_only: bool = False) -> dict:
    raise NotImplementedError("Implemented in checklist item 10.")
