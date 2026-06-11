"""VERDICT CLI - Typer entry point, case validation, run-folder creation.

Spec ref: spec.md > Orchestrator > CLI & case validation (cli.py).
Filled in by checklist item 6. This stub exists so the `verdict` console script
installs and `verdict --help` works from item 1 onward.

Exit codes (spec.md > Runtime & Deployment):
    0  success
    1  invalid/empty case folder (immediate, no investigation starts)
    2  interrupted (API outage -> partial report)
    3  internal error
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="verdict",
    help="VERDICT - autonomous DFIR investigation with architectural guardrails.",
    no_args_is_help=True,
)


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
    # TODO(item 6): validate case folder (exists, readable, >=1 recognized evidence
    #   type) -> exit 1 on failure; create runs/<UTC-timestamp>/; spawn verdict_mcp
    #   over stdio; print evidence inventory table + investigation plan within ~10 s.
    # TODO(item 7): triage loop + budget guard.
    # TODO(item 8): verifier pass.
    # TODO(item 9): report generation.
    typer.echo("VERDICT scaffold: the investigation pipeline lands in checklist items 6-9.")
    raise typer.Exit(code=3)


if __name__ == "__main__":
    app()
