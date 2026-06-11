"""System prompts: triage, verifier, report prose.

Spec ref: spec.md > Orchestrator > Triage phase (agent/prompts.py).

- TRIAGE_SYSTEM: filled in by checklist item 7 (kill-chain hypothesis order,
  narrate between hypotheses, recall-oriented, always narrow queries,
  conflicts-as-findings, honest-clean, cite ledger seqs, seek the disk<->memory
  dual citation).
- VERIFIER_SYSTEM: filled in by checklist item 8 ("your job is to break this
  claim"; re-run cited queries; independently re-derive or refute).
- REPORT_PROSE_SYSTEM: filled in by checklist item 9 (executive summary +
  attack narrative over verified findings only).
"""

TRIAGE_SYSTEM: str = ""  # TODO(item 7)
VERIFIER_SYSTEM: str = ""  # TODO(item 8)
REPORT_PROSE_SYSTEM: str = ""  # TODO(item 9)
