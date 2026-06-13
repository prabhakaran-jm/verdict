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
from typing import Any

import typer

from verdict.agent.loop import DEFAULT_EFFORT, LoopConfig, LoopInterrupted
from verdict.agent.triage import run_triage
from verdict.agent.verifier import run_verifier
from verdict.budget import BudgetGuard
from verdict.findings import FindingsStore
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


class ConfigError(Exception):
    """A precondition for the run is missing (e.g. no ANTHROPIC_API_KEY).

    Carries a clear, human-readable message the CLI prints to stderr before
    exiting nonzero - never a traceback. The autonomous run needs an API key;
    we detect its absence up front and say exactly what to set (checklist item
    7: a no-key run fails gracefully, not with a crash).
    """


def build_anthropic_client(model: str):
    """Construct the AsyncAnthropic client, lazily, with a clear no-key error.

    Imported lazily so the package imports (and the fake-client tests) run with
    no `anthropic` key and no real API calls - the $0 dev/test constraint. A
    missing ANTHROPIC_API_KEY raises ConfigError with a plain message instead of
    the SDK's own exception, so the CLI exits cleanly rather than dumping a
    traceback.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise ConfigError(
            "ANTHROPIC_API_KEY is not set. VERDICT runs Claude autonomously and "
            "needs an API key. Set it and re-run, e.g.:\n"
            "  export ANTHROPIC_API_KEY=sk-ant-...   (Linux/macOS)\n"
            "  $env:ANTHROPIC_API_KEY = 'sk-ant-...'  (PowerShell)"
        )
    try:
        from anthropic import AsyncAnthropic
    except ImportError as exc:  # pragma: no cover - anthropic is a hard dep
        raise ConfigError(
            f"the 'anthropic' package is not installed ({exc}); run "
            f"`pip install -e .` to install dependencies."
        ) from exc
    return AsyncAnthropic()


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


async def _run_investigation(
    case_dir: Path, run_dir: Path, ui: TerminalUI, budget: float, model: str,
    *, anthropic_client: Any, client: MCPClient | None = None,
) -> bool:
    """Survey -> triage -> [verify seam] -> [report seam] -> completion summary.

    Drives the whole autonomous run on one event loop (spec.md > Stack: async
    throughout). `client` lets tests inject a connected MCPClient against the
    real server subprocess; in production we open one here. `anthropic_client`
    is the AsyncAnthropic client (or a fake, in the $0 tests). Returns True on a
    clean completion; raises LoopInterrupted on a sustained API outage so the
    caller writes a partial report and exits 2.
    """
    owns_client = client is None
    if owns_client:
        client = await MCPClient(case_dir, run_dir).__aenter__()
    try:
        client.set_phase("triage")  # evidence_inventory is triage-only (tool #1)

        # run_started through the control plane (server is the single writer).
        await _safe_log_event(client, "run_started", {
            "case_dir": str(case_dir), "budget_usd": budget, "model": model})

        # --- survey: evidence_inventory -> render inventory + plan (~10s AC).
        raw = await client.call_tool("evidence_inventory", {})
        inventory = json.loads(raw)
        ui.inventory_table(
            inventory.get("files", []),
            case_dir=inventory.get("case_dir", str(case_dir)),
            counts=inventory.get("counts"),
        )
        ui.plan(
            "triage across the kill chain (initial access -> persistence -> "
            "lateral movement -> C2), then adversarially verify every finding, "
            f"then write the report. Budget ${budget:.2f}, model {model}."
        )

        budget_guard = BudgetGuard(budget)
        findings_store = FindingsStore(run_dir)
        config = LoopConfig(model=model, effort=DEFAULT_EFFORT)

        ui.start_status()
        ui.update_status(findings=0, cost_usd=0.0)

        # --- TRIAGE (item 7): the real agentic loop, driven by anthropic_client.
        try:
            await run_triage(
                anthropic_client, client,
                inventory_json=raw,
                budget_guard=budget_guard,
                findings_store=findings_store,
                terminal_ui=ui,
                config=config,
            )
        except LoopInterrupted as exc:
            await _safe_log_event(client, "run_interrupted",
                                  {"reason": str(exc)})
            ui.narration(f"INTERRUPTED: {exc}")
            raise
        finally:
            ui.update_status(cost_usd=budget_guard.total_cost)

        # --- VERIFIER PASS (item 8): fresh-context per-finding adversarial
        #     self-check. Set phase "verify", reuse loop.run_phase with
        #     VERIFIER_SYSTEM under the verify sub-budget (verify_cap). Each
        #     verdict -> findings_store.set_verdict + ui.verdict_flip live; the
        #     decoy flips REFUTED. A sustained API outage here still surfaces
        #     LoopInterrupted (per-finding errors degrade to UNCONFIRMED inside
        #     run_verifier) -> partial report + exit 2, mirroring triage.
        try:
            await run_verifier(
                anthropic_client, client,
                run_dir=run_dir,
                budget_guard=budget_guard,
                findings_store=findings_store,
                terminal_ui=ui,
                config=config,
            )
        except LoopInterrupted as exc:
            await _safe_log_event(client, "run_interrupted",
                                  {"reason": str(exc)})
            ui.narration(f"INTERRUPTED: {exc}")
            raise
        finally:
            ui.update_status(cost_usd=budget_guard.total_cost)

        # ---------------------------------------------------------------
        # REPORT GENERATION GOES HERE (item 9)
        #   One Sonnet call (REPORT_PROSE_SYSTEM) over the VERIFIED/UNCONFIRMED
        #   findings -> report.html/pdf, reserving budget_guard.report_reserve().
        #   budget_guard.notes carries any graceful-degradation lines for the
        #   report. The ledger.jsonl + findings.json are already on disk.
        # ---------------------------------------------------------------

        # --- completion summary (severity-sorted findings + artifact paths).
        ui.summary_table(
            findings_store.findings,
            artifacts={
                "findings.json": str(findings_store.path),
                "ledger.jsonl": str(run_dir / "ledger.jsonl"),
            },
        )
        await _safe_log_event(client, "run_ended", {
            "findings": len(findings_store),
            "total_cost_usd": round(budget_guard.total_cost, 6),
        })
        return True
    finally:
        ui.stop_status()
        if owns_client:
            await client.__aexit__(None, None, None)


async def _safe_log_event(client: MCPClient, event: str,
                          payload: dict[str, Any]) -> None:
    """Control-plane ledger write that never crashes the run on failure."""
    try:
        await client.log_event(event, payload)
    except Exception:  # noqa: BLE001 - ledger is convenience at the CLI edge
        pass


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

    # 2. Build the Anthropic client up front - a missing ANTHROPIC_API_KEY is a
    #    clean, plain-English failure with a nonzero exit, NOT a traceback, and
    #    NOT a littered empty run folder (checklist item 7). Done before the run
    #    folder so a misconfigured host fails fast.
    try:
        anthropic_client = build_anthropic_client(model)
    except ConfigError as exc:
        typer.echo(f"verdict: {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL)

    # 3. Create the run folder (never overwrites a prior trail).
    try:
        run_dir = create_run_dir(output)
    except OSError as exc:
        typer.echo(f"verdict: could not create run folder under "
                   f"'{output}': {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL)

    ui = TerminalUI()
    ui.console.print(f"Case validated: {case}")
    ui.console.print(f"Run folder: {run_dir}")

    # 4. Spawn server -> survey -> triage -> [verify/report seams] -> summary ->
    #    clean shutdown -> exit 0. LoopInterrupted (API outage) -> exit 2 with a
    #    partial report from existing findings; KeyboardInterrupt -> exit 2;
    #    anything else -> exit 3 (spec.md > Runtime & Deployment exit codes).
    try:
        asyncio.run(_run_investigation(
            case, run_dir, ui, budget, model,
            anthropic_client=anthropic_client))
    except LoopInterrupted as exc:
        typer.echo(
            f"verdict: interrupted - the Anthropic API was unavailable. A "
            f"partial trail (ledger.jsonl, findings.json) is in {run_dir}. "
            f"Recover by re-running (a fresh run folder, never a resume). "
            f"Details: {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERRUPTED)
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
