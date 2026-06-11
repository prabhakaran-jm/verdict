"""Tool 6: registry_query.

Spec ref: spec.md > MCP Server > Tool definitions > #6 registry_query.
Filled in by checklist item 4.

Run named plugins against an extracted hive. Params: hive (path), plugin
(enum: run_keys, services, usb, network, sam_users, ...). Wraps RECmd batch
(fallback: RegRipper rip.pl, native on SIFT).
"""

from __future__ import annotations

PLUGINS = ("run_keys", "services", "usb", "network", "sam_users")


def registry_query(hive: str, plugin: str) -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
