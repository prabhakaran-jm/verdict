"""Terminal UI - rich rendering; this IS the demo video.

Spec ref: spec.md > Orchestrator > Terminal UI (terminal.py).
PRD ref: prd.md > Autonomous Investigation Run (the narrated run + REFUTED flip).
Built by checklist item 6; the agent loop (item 7) and verifier (item 8) call
these methods - there is no agent logic in this module.

Surfaces (each a method the loop calls):
  tool_line(...)      one compact line per tool call: timestamp, tool, key args,
                      duration, short sha, running cost.
  narration(text)     dimmed agent reasoning between hypotheses.
  inventory_table(..) the evidence inventory rendered at survey time (cli.py
                      reuses this; PRD ~10s-to-inventory acceptance).
  plan(text)          the stated investigation plan line.
  status fields       findings_count / elapsed / cumulative cost via a persistent
                      rich.Live status bar (start_status / update_status / stop).
  verdict_flip(...)   per-finding VERIFIED/UNCONFIRMED/REFUTED flip with color +
                      one-line reason (the on-camera wow moment, item 8).
  summary_table(...)  completion: severity-sorted findings + artifact paths.

All output goes through one rich.Console so tests can capture it to a string
(Console(file=StringIO(), force_terminal=False)).
"""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

#: Severity ordering for the completion table (critical first). Anything
#: unrecognized sorts last (spec.md > Data Model > Finding severities).
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

#: Verdict -> rich color (spec.md > Terminal UI: VERIFIED green / UNCONFIRMED
#: yellow / REFUTED red).
_VERDICT_STYLE = {
    "VERIFIED": "bold green",
    "UNCONFIRMED": "bold yellow",
    "REFUTED": "bold red",
}

#: Severity -> rich color for the summary table.
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


def _short_sha(sha: str | None, width: int = 4) -> str:
    """First `width` hex chars + an ellipsis, or '----' when absent.

    Matches the spec's `sha=ab12...` tool-line shape; keeps the line compact
    while staying enough to eyeball against the ledger.
    """
    if not sha:
        return "-" * width
    return f"{sha[:width]}..."


def _compact_args(args: dict[str, Any] | None, max_len: int = 48) -> str:
    """`key=value` pairs for the tool line, paths basename'd, long values clipped.

    The model passes full paths; the line only needs the leaf so it stays
    readable (spec.md > Terminal UI tool-line example: `log=Security ids=[4624]`).
    Long values are truncated with an ellipsis. None/empty values are dropped.
    """
    if not args:
        return ""
    parts: list[str] = []
    for key in args:  # preserve call order; not sorted - this is display only
        value = args[key]
        if value is None:
            continue
        if isinstance(value, str) and ("/" in value or "\\" in value):
            value = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        rendered = str(value)
        if len(rendered) > max_len:
            rendered = rendered[: max_len - 1] + "…"
        parts.append(f"{key}={rendered}")
    return " ".join(parts)


class TerminalUI:
    """Rich live display wrapper. No agent logic - the loop drives every method.

    Construct with a Console (inject a StringIO-backed one in tests). The
    persistent status bar is a rich.Live around a single status Text; tool
    lines and narration print above it via Live.console so they scroll while
    the bar stays pinned to the bottom (spec.md > Terminal UI: persistent
    status bar).
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._live: Live | None = None
        self._start_monotonic = time.monotonic()
        # Status-bar state; the loop pushes updates, we render them.
        self._findings_count = 0
        self._cost_usd = 0.0

    # ----------------------------------------------------------- printing

    def _emit(self, renderable: Any) -> None:
        """Print above the status bar if it's live, else straight to console."""
        target = self._live.console if self._live is not None else self.console
        target.print(renderable)
        if self._live is not None:
            self._live.update(self._status_renderable())

    @staticmethod
    def _now_hms() -> str:
        """Local wall-clock HH:MM:SS for the tool-line timestamp."""
        return time.strftime("%H:%M:%S", time.localtime())

    # --------------------------------------------------------- tool lines

    def tool_line(self, tool: str, args: dict[str, Any] | None = None, *,
                  duration_s: float | None = None, sha: str | None = None,
                  total_cost: float | None = None, ts: str | None = None) -> None:
        """One line per tool call (spec.md > Terminal UI / prd.md tool-line AC).

        Example rendered shape:
          [09:14:03] evtx_query log=Security ids=[4624] 1.2s sha=ab12… $0.43

        `ts` overrides the timestamp (tests pin it); `total_cost` defaults to
        the running cost tracked by the status bar so the loop can omit it.
        """
        stamp = ts or self._now_hms()
        cost = self._cost_usd if total_cost is None else total_cost
        line = Text()
        line.append(f"[{stamp}] ", style="dim")
        line.append(tool, style="bold cyan")
        arg_str = _compact_args(args)
        if arg_str:
            line.append(" " + arg_str)
        if duration_s is not None:
            line.append(f" {duration_s:.1f}s", style="dim")
        line.append(f" sha={_short_sha(sha)}", style="dim")
        line.append(f" ${cost:.2f}", style="green")
        self._emit(line)

    def narration(self, text: str) -> None:
        """Dimmed agent reasoning between hypotheses (1-2 plain-English lines)."""
        self._emit(Text(text, style="dim italic"))

    def plan(self, text: str) -> None:
        """The stated investigation plan line (survey phase, prd ~10s AC)."""
        body = Text()
        body.append("Plan: ", style="bold")
        body.append(text)
        self._emit(body)

    # --------------------------------------------------------- inventory

    def inventory_table(self, files: list[dict[str, Any]], *,
                        case_dir: str | None = None,
                        counts: dict[str, int] | None = None) -> None:
        """Render the evidence inventory (cli.py survey step reuses this).

        Each row: path, type, size, short sha. `files` is the list of dicts
        evidence_inventory returns ({"path","type","size","sha256"}). A header
        line states the case dir and type counts so the judge sees recognized
        evidence at a glance (prd.md > Autonomous Investigation Run AC).
        """
        title = "Evidence inventory"
        if case_dir:
            title += f" - {case_dir}"
        table = Table(title=title, show_lines=False, expand=False)
        table.add_column("File", style="bold", overflow="fold")
        table.add_column("Type", no_wrap=True)
        table.add_column("Size", justify="right", no_wrap=True)
        table.add_column("SHA-256", no_wrap=True, style="dim")
        for entry in files:
            table.add_row(
                str(entry.get("path", "?")),
                str(entry.get("type", "?")),
                _human_size(entry.get("size")),
                _short_sha(entry.get("sha256"), width=8),
            )
        self._emit(table)
        if counts:
            summary = ", ".join(f"{kind}: {n}" for kind, n in sorted(counts.items()))
            self._emit(Text(f"  {len(files)} files - {summary}", style="dim"))

    # ----------------------------------------------------------- status bar

    def start_status(self) -> None:
        """Begin the persistent status bar (findings / elapsed / cost)."""
        if self._live is not None:
            return
        self._start_monotonic = time.monotonic()
        self._live = Live(self._status_renderable(), console=self.console,
                          refresh_per_second=4, transient=False)
        self._live.start()

    def update_status(self, *, findings: int | None = None,
                      cost_usd: float | None = None) -> None:
        """Push new status-bar values (the loop calls this each turn)."""
        if findings is not None:
            self._findings_count = findings
        if cost_usd is not None:
            self._cost_usd = cost_usd
        if self._live is not None:
            self._live.update(self._status_renderable())

    def stop_status(self) -> None:
        """Tear down the status bar (idempotent; safe if never started)."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    def _status_renderable(self) -> Text:
        elapsed = time.monotonic() - self._start_monotonic
        bar = Text()
        bar.append("findings ", style="dim")
        bar.append(str(self._findings_count), style="bold")
        bar.append("  ·  elapsed ", style="dim")
        bar.append(_human_duration(elapsed), style="bold")
        bar.append("  ·  cost ", style="dim")
        bar.append(f"${self._cost_usd:.2f}", style="bold green")
        return bar

    # ----------------------------------------------------------- verdicts

    def verdict_flip(self, finding_id: str, verdict: str, reason: str) -> None:
        """Per-finding VERIFIED/UNCONFIRMED/REFUTED flip (item 8's wow moment).

        Color-coded by verdict with a one-line reason (spec.md > Verifier
        phase; prd.md > Self-Verification). Unknown verdicts render plain so a
        typo never crashes the demo.
        """
        style = _VERDICT_STYLE.get(verdict, "bold")
        line = Text()
        line.append(f"{finding_id} ", style="bold")
        line.append(verdict, style=style)
        if reason:
            line.append(f" - {reason}", style="dim")
        self._emit(line)

    # ------------------------------------------------------- completion

    def summary_table(self, findings: list[dict[str, Any]], *,
                      artifacts: dict[str, str] | None = None) -> None:
        """Completion: severity-sorted findings table + artifact paths.

        Each finding dict may carry: finding_id, claim, severity, attack_id,
        verdict, cites. Sorted critical->low (spec.md > Terminal UI:
        severity-sorted summary). `artifacts` is a label->path map
        (report.html, ledger.jsonl, ...) printed beneath the table.
        """
        self.stop_status()  # the bar must not fight the final table for the cursor
        table = Table(title="Findings summary", show_lines=False, expand=False)
        table.add_column("ID", no_wrap=True, style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("ATT&CK", no_wrap=True, style="dim")
        table.add_column("Verdict", no_wrap=True)
        table.add_column("Claim", overflow="fold")
        # The FindingsStore mirrors the server's finding_id into the canonical
        # `id` field; raw server results use `finding_id`. Accept either.
        def _fid(f: dict[str, Any]) -> str:
            return str(f.get("id") or f.get("finding_id") or "?")

        ordered = sorted(
            findings,
            key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity")).lower(), 99),
                           _fid(f)),
        )
        for finding in ordered:
            severity = str(finding.get("severity", "?")).lower()
            verdict = str(finding.get("verdict") or "-")
            table.add_row(
                _fid(finding),
                Text(severity, style=_SEVERITY_STYLE.get(severity, "white")),
                str(finding.get("attack_id", "-")),
                Text(verdict, style=_VERDICT_STYLE.get(verdict, "dim")),
                str(finding.get("claim", "")),
            )
        if not ordered:
            table.add_row("-", "-", "-", "-",
                          Text("no findings - evidence examined and clean",
                               style="dim"))
        self.console.print(table)
        if artifacts:
            self.console.print(Text("Artifacts:", style="bold"))
            for label, path in artifacts.items():
                line = Text("  ")
                line.append(f"{label}: ", style="dim")
                line.append(str(path))
                self.console.print(line)


# ------------------------------------------------------------- formatting


def _human_size(size: Any) -> str:
    """Compact byte size (e.g. '12 B', '4.0 KB'); '?' when unknown."""
    if not isinstance(size, (int, float)):
        return "?"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _human_duration(seconds: float) -> str:
    """`Mm SSs` or `SSs` for the status bar elapsed clock."""
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"
