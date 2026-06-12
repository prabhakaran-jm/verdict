"""Budget guard - token-to-dollar ticker, sub-budgets, graceful degrade.

Spec ref: spec.md > Orchestrator > Budget guard (budget.py).
Built by checklist item 7.

Tracks cost from every response.usage (input $3/M, output $15/M, cache read
$0.30/M, cache write $3.75/M - Sonnet 4.6). Sub-budgets: triage soft-cap 60% of
--budget, verify reserved 30%, report 10%. Triage hitting its cap -> stop
opening hypotheses, force transition to verify; emit a budget_event ledger line
and a report note. Never a dead process at $5.01: the cap forces a graceful
transition between turns, it never kills a run mid-tool.

The cap is a SOFT cap checked BETWEEN turns by the loop/triage, never a hard
kill mid-tool. add_usage() (alias track()) updates the running total from one
response.usage; total_cost feeds the terminal ticker.
"""

from __future__ import annotations

from typing import Any

# Sonnet 4.6 pricing, USD per million tokens (spec.md > Stack).
PRICE_INPUT = 3.00
PRICE_OUTPUT = 15.00
PRICE_CACHE_READ = 0.30
PRICE_CACHE_WRITE = 3.75

_PER_TOKEN = 1_000_000.0

#: Sub-budget fractions of the total --budget (spec.md > Budget guard).
TRIAGE_FRACTION = 0.60
VERIFY_FRACTION = 0.30
REPORT_FRACTION = 0.10


def usage_cost(usage: Any) -> float:
    """Dollar cost of one response.usage, exactly from the Sonnet 4.6 rates.

    `usage` is an anthropic Usage object (or any object/dict exposing the same
    token fields). Missing fields count as zero, so a fake/stub usage that only
    sets input/output tokens still prices correctly. The four token buckets are
    disjoint - input_tokens already EXCLUDES cache reads/writes in the SDK, so
    they sum without double-counting (Anthropic pricing model).
    """
    inp = _usage_field(usage, "input_tokens")
    out = _usage_field(usage, "output_tokens")
    cache_read = _usage_field(usage, "cache_read_input_tokens")
    cache_write = _usage_field(usage, "cache_creation_input_tokens")
    return (
        inp * PRICE_INPUT
        + out * PRICE_OUTPUT
        + cache_read * PRICE_CACHE_READ
        + cache_write * PRICE_CACHE_WRITE
    ) / _PER_TOKEN


def _usage_field(usage: Any, name: str) -> int:
    """One token field from a Usage object or a dict; 0 when absent/None."""
    if isinstance(usage, dict):
        value = usage.get(name)
    else:
        value = getattr(usage, name, None)
    return int(value) if value else 0


class BudgetGuard:
    """Cumulative cost tracking + phase sub-budget enforcement.

    Lifecycle (spec.md > Budget guard):
      guard = BudgetGuard(5.00)
      guard.track(response.usage)          # each turn, returns cumulative spend
      if guard.over_triage_cap(): ...      # checked BETWEEN turns, never mid-tool
      guard.total_cost                      # the live ticker value for the UI

    Phase sub-budgets are soft fractions of the total: triage 60%, verify 30%,
    report 10%. over_triage_cap() trips when cumulative spend reaches the triage
    cap; the loop/triage then transitions to verify rather than opening new
    hypotheses. The cap NEVER raises or kills a run - the spend ceiling is the
    total --budget; the sub-budget is a transition signal, not a hard stop.
    """

    def __init__(self, budget_usd: float) -> None:
        self.budget_usd = float(budget_usd)
        self.spent_usd = 0.0
        # One-shot guard so the budget_event ledger line / report note fire
        # exactly once when triage first crosses its cap.
        self._triage_cap_announced = False
        #: Report notes accumulated for the report generator (item 9) - human
        #: lines explaining any graceful degradation that happened this run.
        self.notes: list[str] = []

    # --------------------------------------------------------------- tracking

    def track(self, usage: Any) -> float:
        """Add one response.usage to the ticker; return cumulative spend.

        Priced exactly from the Sonnet 4.6 rates (usage_cost). Idempotent in the
        sense that it is purely additive - call it once per messages.create.
        """
        self.spent_usd += usage_cost(usage)
        return self.spent_usd

    #: Alias matching the spec's add_usage() name; track() is the short form the
    #: loop uses. Both do the same thing.
    add_usage = track

    @property
    def total_cost(self) -> float:
        """Cumulative spend in USD - the value the terminal ticker displays."""
        return self.spent_usd

    # --------------------------------------------------------- sub-budgets

    def triage_cap(self) -> float:
        """Dollar ceiling for the triage phase (60% of the total budget)."""
        return self.budget_usd * TRIAGE_FRACTION

    def verify_cap(self) -> float:
        """Dollar ceiling for triage+verify combined (90% of the total).

        Verify is reserved 30% on top of triage's 60%; expressed as a cumulative
        ceiling so the verifier (item 8) can check spend the same way triage
        does. Report keeps the final 10%.
        """
        return self.budget_usd * (TRIAGE_FRACTION + VERIFY_FRACTION)

    def report_reserve(self) -> float:
        """Dollars reserved for the report-prose call (10% of the total)."""
        return self.budget_usd * REPORT_FRACTION

    def remaining(self) -> float:
        """Dollars left before the hard total budget; never negative-clamped
        here so callers can see an overage, but the soft cap should prevent it."""
        return self.budget_usd - self.spent_usd

    # --------------------------------------------------- transition signals

    def over_triage_cap(self) -> bool:
        """True once cumulative spend reaches the triage soft cap.

        Checked BETWEEN turns by the loop/triage: when True, triage stops opening
        new hypotheses and transitions to verify. Never a hard kill - the run
        keeps going, it just narrows (spec.md > Budget guard: never a dead
        process at $5.01).
        """
        return self.spent_usd >= self.triage_cap()

    #: Spec wording: triage_capped() is the boolean the loop checks. Same as
    #: over_triage_cap().
    triage_capped = over_triage_cap

    def over_budget(self) -> bool:
        """True once cumulative spend reaches the hard total budget."""
        return self.spent_usd >= self.budget_usd

    def announce_triage_cap(self) -> bool:
        """Mark the triage-cap crossing as announced; True only the first time.

        Lets the loop emit the budget_event ledger line + report note exactly
        once when triage first crosses its cap, even though over_triage_cap()
        stays True for the rest of triage.
        """
        if self._triage_cap_announced:
            return False
        self._triage_cap_announced = True
        note = (
            f"Triage reached its soft budget cap "
            f"(${self.triage_cap():.2f} of ${self.budget_usd:.2f} total; "
            f"spent ${self.spent_usd:.2f}); stopped opening new hypotheses and "
            f"transitioned to verification."
        )
        self.notes.append(note)
        return True

    def budget_event_payload(self, kind: str) -> dict[str, Any]:
        """The payload for a `budget_event` ledger line via _log_event."""
        return {
            "kind": kind,
            "spent_usd": round(self.spent_usd, 6),
            "budget_usd": self.budget_usd,
            "triage_cap_usd": round(self.triage_cap(), 6),
        }
