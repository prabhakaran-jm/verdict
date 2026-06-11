"""Tool 1: evidence_inventory.

Spec ref: spec.md > MCP Server > Tool definitions > #1 evidence_inventory.
Filled in by checklist item 4.

Walk the case dir; classify each file (disk image / memory / loose artifact /
pcap - pcap noted, never parsed, per PRD non-goals); SHA-256 everything.
Returns the inventory table. Wraps: file, hashlib.
"""

from __future__ import annotations


def evidence_inventory(case_dir: str) -> dict:
    # TODO(item 4): walk + classify + hash; ledger pair via runner conventions.
    raise NotImplementedError("Implemented in checklist item 4.")
