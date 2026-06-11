"""Tool 7: execution_evidence (prefetch + amcache).

Spec ref: spec.md > MCP Server > Tool definitions > #7 execution_evidence.
Filled in by checklist item 4.

Params: source (pf file/dir or Amcache.hve), name_contains?, after?, before?.
Wraps PECmd + AmcacheParser (fallbacks: pyscca / RegRipper amcache plugin).
"""

from __future__ import annotations


def execution_evidence(source: str, name_contains: str | None = None,
                       after: str | None = None, before: str | None = None) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
