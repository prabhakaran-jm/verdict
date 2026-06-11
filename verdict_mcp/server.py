"""FastMCP app - 13 tool definitions + phase metadata + _log_event control plane.

Spec ref: spec.md > MCP Server > Tool definitions (server.py, tools/).
Skeleton filled in by checklist item 3; tools registered in items 4 and 10.

Model-visible tools (all params Pydantic-validated, narrowing params required
where the underlying data is large):
  1 evidence_inventory   (tools/inventory.py)      - item 4
  2 fs_list              (tools/fs.py)             - item 10
  3 fs_extract           (tools/fs.py)             - item 10
  4 mft_query            (tools/mft.py)            - item 10
  5 evtx_query           (tools/evtx.py)           - item 4
  6 registry_query       (tools/registry.py)       - item 4
  7 execution_evidence   (tools/execution.py)      - item 4
  8 timeline_query       (tools/timeline.py)       - item 10
  9 mem_analyze          (tools/memory.py)         - item 10
 10 yara_scan            (tools/yara_scan.py)      - item 4
 11 read_artifact        (tools/artifacts.py)      - item 4
 12 record_finding       (tools/findings_tools.py) - item 4 (triage only)
 13 record_verdict       (tools/findings_tools.py) - item 4 (verify only)

Orchestrator-only (NEVER exposed to the model): _log_event - the control-plane
channel for orchestrator events into the server-written ledger, preserving the
single-writer claim.
"""

from __future__ import annotations


def build_app(case_dir: str, run_dir: str):
    """Construct the FastMCP app wired to pathguard/runner/ledger. TODO(item 3)."""
    raise NotImplementedError("Implemented in checklist item 3.")
