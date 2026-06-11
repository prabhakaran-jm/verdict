"""Tool 8: timeline_query.

Spec ref: spec.md > MCP Server > Tool definitions > #8 timeline_query.
Filled in by checklist item 10.

Filesystem timeline pivots. Params: image|bodyfile, after, before (window
REQUIRED), keyword?. Wraps fls -m -> mactime; bodyfile built once per image and
cached in runs/<id>/bodyfile/. Deliberate scope choice: no Plaso supertimeline
(spec.md > Key Technical Decisions #3).
"""

from __future__ import annotations


def timeline_query(image: str, after: str, before: str,
                   keyword: str | None = None) -> dict:
    raise NotImplementedError("Implemented in checklist item 10.")
