"""Tool 9: mem_analyze.

Spec ref: spec.md > MCP Server > Tool definitions > #9 mem_analyze.
Filled in by checklist item 10.

Run one ALLOWED Volatility 3 plugin. Params: image, plugin (enum below),
filter?. Plugin allowlist enforced server-side - arbitrary plugin names
rejected (and the rejection ledgered).
"""

from __future__ import annotations

PLUGIN_ALLOWLIST = (
    "pslist", "pstree", "psscan", "netscan",
    "malfind", "cmdline", "dlllist", "handles",
)


def mem_analyze(image: str, plugin: str, filter: str | None = None) -> dict:
    raise NotImplementedError("Implemented in checklist item 10.")
