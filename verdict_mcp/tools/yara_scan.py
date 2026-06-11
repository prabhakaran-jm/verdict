"""Tool 10: yara_scan.

Spec ref: spec.md > MCP Server > Tool definitions > #10 yara_scan.
Filled in by checklist item 4.

Params: target (extracted file, artifact dir, or memory image), ruleset (enum
derived from rules/). Wraps yara (fallback: yara-python). Returns match names +
offsets.
"""

from __future__ import annotations


def yara_scan(target: str, ruleset: str) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
