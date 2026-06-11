"""Budget guard - token-to-dollar ticker, sub-budgets, graceful degrade.

Spec ref: spec.md > Orchestrator > Budget guard (budget.py).
Filled in by checklist item 7.

Tracks cost from every response.usage (input $3/M, output $15/M, cache read
$0.30/M, cache write $3.75/M). Sub-budgets: triage soft-cap 60% of --budget,
verify reserved 30%, report 10%. Triage hitting its cap -> stop opening
hypotheses, force transition to verify; emit a budget_event ledger line and a
report note. Never a dead process at $5.01.
"""

from __future__ import annotations

# Sonnet 4.6 pricing, USD per million tokens (spec.md > Stack).
PRICE_INPUT = 3.00
PRICE_OUTPUT = 15.00
PRICE_CACHE_READ = 0.30
PRICE_CACHE_WRITE = 3.75


class BudgetGuard:
    """Cumulative cost tracking + phase sub-budget enforcement. TODO(item 7)."""

    def __init__(self, budget_usd: float) -> None:
        self.budget_usd = budget_usd
        self.spent_usd = 0.0
        # TODO(item 7): sub-budget thresholds (triage 60% / verify 30% / report 10%).

    def track(self, usage) -> float:
        """Add one response.usage to the ticker; return cumulative spend."""
        raise NotImplementedError("Implemented in checklist item 7.")

    def triage_capped(self) -> bool:
        """True when triage must stop opening hypotheses and hand off to verify."""
        raise NotImplementedError("Implemented in checklist item 7.")
