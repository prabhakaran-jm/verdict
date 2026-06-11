"""Tool 5: evtx_query.

Spec ref: spec.md > MCP Server > Tool definitions > #5 evtx_query.
Filled in by checklist item 4.

Query an event log. Params: log (path), event_ids?, after?, before?, keyword?,
limit (<=500, enforced). Wraps EvtxECmd (fallback: evtx_dump static binary +
jq-style filter in Python, per the item-2 gate decision).
"""

from __future__ import annotations

MAX_LIMIT = 500


def evtx_query(log: str, event_ids: list[int] | None = None,
               after: str | None = None, before: str | None = None,
               keyword: str | None = None, limit: int = 100) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
