"""VERDICT CLI - Typer entry point, case validation, run-folder creation.

Spec ref: spec.md > Orchestrator > CLI & case validation (cli.py).
PRD ref: prd.md > Autonomous Investigation Run (the ~10s-to-inventory AC,
exit-code behavior). Built by checklist item 6.

`verdict investigate <case_dir> [--budget 5.00] [--output runs/]
[--model claude-sonnet-4-6]` does, in order:
  validate case -> create runs/<UTC-timestamp>/ -> spawn verdict_mcp over stdio
  -> call evidence_inventory through the client -> render the inventory table +
  a stated investigation plan within ~10s -> clean shutdown -> exit 0.

The triage/verify/report agent loop is item 7 and slots in at the marked seam;
item 6 stops after the survey-and-exit flow.

Exit codes (spec.md > Runtime & Deployment):
    0  success
    1  invalid/empty case folder (immediate, no investigation starts)
    2  interrupted (API outage -> partial report)
    3  internal error
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import typer

from verdict.mcp_client import MCPClient
from verdict.terminal import TerminalUI

app = typer.Typer(
    name="verdict",
    help="VERDICT - autonomous DFIR investigation with architectural guardrails.",
    no_args_is_help=True,
)

# Exit codes per spec.md > Runtime & Deployment.
EXIT_OK = 0
EXIT_INVALID_CASE = 1
EXIT_INTERRUPTED = 2
EXIT_INTERNAL = 3

#: Run-folder subdirectories the server/tools write into (mirrors what items
#: 3-5 created: outputs/ for full tool output, artifacts/ for files extracted
#: from images, scratch/ + bodyfile/ for cached timelines). The server's
#: Runner makes outputs/ itself, but we create them all up front so the run
#: dir is well-formed the moment the server starts (spec.md > Data Model > Run
#: folder).
RUN_SUBDIRS: tuple[str, ...] = ("outputs", "artifacts", "scratch", "bodyfile")

#: Recognized evidence types from evidence_inventory's classifier - any one
#: makes the case folder valid (spec.md > CLI & case validation: >=1 recognized
#: evidence type). "other" is NOT evidence on its own (a folder of stray text
#: files is an empty case). Loose-artifact hives/evtx/prefetch count, as do disk
#: images, memory images, and pcap.
RECOGNIZED_EVIDENCE_TYPES: frozenset[str] = frozenset({
    "disk_image", "memory_image", "evtx", "registry_hive", "prefetch", "pcap",
})


class CaseValidationError(Exception):
    """Case folder is missing, unreadable, empty, or has no recognized evidence.

    Carries a clear, human-readable message the CLI prints to stderr before
    exiting 1 - nothing else runs (no run folder, no server spawn). The agent
    loop (item 7) never sees an invalid case (spec.md > CLI & case validation).
    """


# --------------------------------------------------------------- validation


def validate_case_dir(case_dir: str | Path) -> Path:
    """Validate the case folder; return its resolved Path or raise.

    Checks, in order (spec.md > CLI & case validation):
      1. exists and is a directory
      2. readable (we can list it)
      3. contains >=1 recognized evidence type (disk image, memory image,
         loose artifact - evtx/hive/prefetch - or pcap)

    Reuses verdict_mcp.tools.inventory.classify so the CLI's notion of "evidence"
    is exactly the server's, with no second classifier to drift. Raises
    CaseValidationError with a clear message on any failure; the caller turns
    that into a stderr line + exit 1.
    """
    path = Path(case_dir).expanduser()
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise CaseValidationError(
            f"case folder '{case_dir}' could not be resolved: {exc}"
        ) from exc

    if not resolved.exists():
        raise CaseValidationError(f"case folder does not exist: {resolved}")
    if not resolved.is_dir():
        raise CaseValidationError(f"case path is not a directory: {resolved}")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise CaseValidationError(f"case folder is not readable: {resolved}")

    from verdict_mcp.tools.inventory import classify

    recognized: list[str] = []
    try:
        entries = list(resolved.rglob("*"))
    except OSError as exc:
        raise CaseValidationError(
            f"case folder could not be read: {resolved} ({exc})"
        ) from exc
    for entry in entries:
        try:
            if not entry.is_file():
                continue
        except OSError:
            continue
        kind = classify(entry)
        if kind in RECOGNIZED_EVIDENCE_TYPES:
            recognized.append(kind)

    if not recognized:
        raise CaseValidationError(
            f"case folder contains no recognized evidence: {resolved}\n"
            f"  expected at least one of: disk image (.E01/.dd/.raw), memory "
            f"image (.mem/.vmem/.raw), loose artifacts (.evtx, registry hives, "
            f".pf prefetch), or pcap. An honest empty report needs ground to "
            f"stand on - nothing was started."
        )
    return resolved


# --------------------------------------------------------- run-folder setup


def create_run_dir(output_parent: str | Path) -> Path:
    """Create runs/<UTC-timestamp>/ with the subdirs the server expects.

    Timestamp format yyyymmddTHHMMSSZ (spec.md > CLI & case validation;
    matches scripts/checkpoint2-check.py and the existing runs/). A re-run
    never overwrites a prior trail (prd.md > Audit Ledger): if a folder with
    the same timestamp somehow exists (sub-second re-invocation), we
    disambiguate with a `-NN` suffix rather than reuse it. Creates outputs/,
    artifacts/, scratch/, bodyfile/ under the new run dir.
    """
    parent = Path(output_parent).expanduser().resolve()
    parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    run_dir = parent / stamp
    suffix = 1
    # NEVER overwrite a prior run trail. mkdir(exist_ok=False) is the atomic
    # guard - if two invocations race within the same UTC second, the loser
    # gets the next free suffix instead of clobbering the winner.
    while True:
        try:
            run_dir.mkdir(parents=False, exist_ok=False)
            break
        except FileExistsError:
            run_dir = parent / f"{stamp}-{suffix:02d}"
            suffix += 1

    for sub in RUN_SUBDIRS:
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    return run_dir


# ----------------------------------------------------------- survey flow


async def _survey(case_dir: Path, run_dir: Path, ui: TerminalUI,
                  budget: float, model: str) -> None:
    """Spawn the server, run evidence_inventory, render inventory + plan.

    This is the item-6 survey-and-exit flow. The agent loop (item 7) inserts
    at the marked seam after the plan is stated. We set the triage phase (the
    only phase where evidence_inventory is allowed) and call it through the
    double-gated client, then render the result with terminal.py.
    """
    async with MCPClient(case_dir, run_dir) as client:
        client.set_phase("triage")  # evidence_inventory is triage-only (tool #1)

        raw = await client.call_tool("evidence_inventory", {})
        inventory = json.loads(raw)
        ui.inventory_table(
            inventory.get("files", []),
            case_dir=inventory.get("case_dir", str(case_dir)),
            counts=inventory.get("counts"),
        )

        # Stated investigation plan within ~10s (prd.md > Autonomous
        # Investigation Run). Static placeholder is fine for item 6; the triage
        # agent will state a real, kill-chain-shaped plan in item 7.
        ui.plan(
            "triage across the kill chain (initial access -> persistence -> "
            "lateral movement -> C2), then adversarially verify every finding, "
            f"then write the report. Budget ${budget:.2f}, model {model}."
        )

        # ---------------------------------------------------------------
        # AGENT LOOP GOES HERE (item 7)
        # The triage loop, budget guard (budget.py), findings store
        # (findings.py), verifier pass (item 8), and report generation (item 9)
        # slot in here, driving `client` (already phase-gated) and `ui`
        # (tool_line / narration / update_status / verdict_flip / summary_table).
        # Item 6 stops after the survey + stated plan.
        # ---------------------------------------------------------------


# --------------------------------------------------------------- command


@app.callback()
def main() -> None:
    """Keep Typer in subcommand mode so the CLI surface is `verdict investigate ...`."""


@app.command()
def investigate(
    case_dir: str = typer.Argument(..., help="Path to the case/evidence folder."),
    budget: float = typer.Option(5.00, "--budget", help="Max API spend (USD) for this run."),
    output: str = typer.Option("runs/", "--output", help="Parent directory for run folders."),
    model: str = typer.Option(
        "claude-sonnet-4-6", "--model", help="Claude model for triage and verify."
    ),
) -> None:
    """Run a fully autonomous investigation against CASE_DIR."""
    # 1. Validate the case folder. Failure -> clear stderr message, exit 1,
    #    NOTHING else runs (no run folder, no server spawn).
    try:
        case = validate_case_dir(case_dir)
    except CaseValidationError as exc:
        typer.echo(f"verdict: {exc}", err=True)
        raise typer.Exit(code=EXIT_INVALID_CASE)

    # 2. Create the run folder (never overwrites a prior trail).
    try:
        run_dir = create_run_dir(output)
    except OSError as exc:
        typer.echo(f"verdict: could not create run folder under "
                   f"'{output}': {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL)

    ui = TerminalUI()
    ui.console.print(f"Case validated: {case}")
    ui.console.print(f"Run folder: {run_dir}")

    # 3-6. Spawn server -> evidence_inventory -> render inventory + plan ->
    #      clean shutdown -> exit 0. KeyboardInterrupt -> exit 2; anything else
    #      -> exit 3 (spec.md > Runtime & Deployment exit codes).
    try:
        asyncio.run(_survey(case, run_dir, ui, budget, model))
    except KeyboardInterrupt:
        typer.echo("verdict: interrupted", err=True)
        raise typer.Exit(code=EXIT_INTERRUPTED)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level guard -> clean exit 3
        typer.echo(f"verdict: internal error: {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL)

    raise typer.Exit(code=EXIT_OK)


if __name__ == "__main__":
    app()
