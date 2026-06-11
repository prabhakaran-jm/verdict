"""Report generator - render report.html, then the PDF attempt chain.

Spec ref: spec.md > Orchestrator > Report generator (report/).
Filled in by checklist item 9.

One self-contained report.html (inline CSS, no JS, anchors only - judges open it
offline). Eight sections: header / executive summary / attack narrative /
findings table (VERIFIED + UNCONFIRMED only) / per-finding detail with anchors
into the embedded ledger rendering / Appendix A refuted-with-refutations /
Appendix B/C inventory + tool-call index / Appendix D methodology + constraints.

PDF attempt chain: chromium --headless --print-to-pdf -> wkhtmltopdf -> manual
print-to-PDF before submission.
"""

from __future__ import annotations


def generate_report(run_dir: str, findings: list[dict], ledger_path: str,
                    *, case_name: str, model: str, total_cost: float) -> str:
    """Render template.html.j2 -> runs/<id>/report.html; returns the path."""
    raise NotImplementedError("Implemented in checklist item 9.")


def attempt_pdf(html_path: str) -> str | None:
    """Try chromium headless, then wkhtmltopdf; return PDF path or None."""
    raise NotImplementedError("Implemented in checklist item 9.")
