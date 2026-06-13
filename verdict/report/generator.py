"""Report generator - render report.html, then the PDF attempt chain.

Spec ref: spec.md > Orchestrator > Report generator (report/);
          spec.md > Data Flow - Lifecycle of a Finding.
PRD ref: prd.md > Investigation Report; prd.md > Failure & Empty-Case Behavior.
Built by checklist item 9.

One self-contained report.html (inline CSS, NO JS, anchors only - judges open it
offline). Eight sections: header / executive summary / attack narrative /
findings table (VERIFIED + UNCONFIRMED only) / per-finding detail with anchors
into the embedded ledger rendering / Appendix A refuted-with-refutations /
Appendix B/C inventory + tool-call index / Appendix D methodology + constraints.

The executive summary + attack narrative are ONE Sonnet call over the VERIFIED +
UNCONFIRMED findings (REPORT_PROSE_SYSTEM). The call is best-effort: a fake
client drives it in tests, and any failure / malformed output / clean-case empty
falls back to a deterministic, honest summary so the report always renders.

Citations resolve OFFLINE: each finding's cited seq is rendered as
<a href="#ledger-<seq>"> and the embedded ledger rendering (Appendix C) gives
every tool_result line id="ledger-<seq>", so a click jumps to the matching entry
with no server and no JS.

PDF attempt chain: `chromium --headless --print-to-pdf` -> `wkhtmltopdf` -> if
neither binary is on PATH, log a clear manual-fallback message and return None
WITHOUT failing the run (PRD only requires the PDF exists for submission).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from verdict.agent.prompts import REPORT_PROSE_SYSTEM

REPORT_FILENAME = "report.html"
PDF_FILENAME = "report.pdf"
LEDGER_FILENAME = "ledger.jsonl"

#: How much of a cited artifact's text to inline as an excerpt (per-finding
#: detail). Tool outputs are already capped at 8 KB server-side; the report
#: excerpt is tighter so the page stays readable.
EXCERPT_CHARS = 1200

#: Verdicts that belong in the headline findings table (spec.md > Data Flow:
#: VERIFIED/UNCONFIRMED -> main table; REFUTED -> appendix).
HEADLINE_VERDICTS = ("VERIFIED", "UNCONFIRMED")

#: The manual-fallback message logged when no PDF binary is available. Returned
#: verbatim so the caller / tests can assert on it without raising.
PDF_MANUAL_FALLBACK = (
    "PDF not generated on this host (no chromium/chromium-browser/chrome or "
    "wkhtmltopdf found on PATH); print report.html to PDF manually before "
    "submission."
)


# ----------------------------------------------------------- ledger loading


def _read_ledger(ledger_path: Path) -> list[dict[str, Any]]:
    """Parse ledger.jsonl into event records; tolerate blank/torn lines."""
    records: list[dict[str, Any]] = []
    try:
        text = ledger_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _ledger_view(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Human-readable rendering of every ledger line for Appendix C.

    Each entry keeps seq/ts/event/tool and gets a one-line `summary`. Only
    tool_result entries are anchored (id="ledger-<seq>") in the template, since
    citations point at the result that produced the cited output.
    """
    view: list[dict[str, Any]] = []
    for rec in records:
        event = rec.get("event", "")
        summary = _summarize_event(rec)
        view.append({
            "seq": rec.get("seq"),
            "ts": rec.get("ts", ""),
            "event": event,
            "tool": rec.get("tool", ""),
            "summary": summary,
        })
    return view


def _summarize_event(rec: dict[str, Any]) -> str:
    """A compact human description of one ledger event."""
    event = rec.get("event", "")
    if event == "tool_called":
        params = rec.get("params", {})
        return _compact_json(params) if params else ""
    if event == "tool_result":
        bits = []
        sha = rec.get("output_sha256")
        if sha:
            bits.append(f"sha={sha[:12]}...")
        if rec.get("output_path"):
            bits.append(rec["output_path"])
        if rec.get("truncated"):
            bits.append("truncated")
        if rec.get("exit_code") is not None:
            bits.append(f"exit={rec['exit_code']}")
        return " · ".join(bits)
    if event == "tool_rejected":
        return str(rec.get("reason", ""))[:200]
    if event == "finding_recorded":
        return f"{rec.get('finding_id', '?')}: {str(rec.get('claim', ''))[:120]}"
    if event == "verdict_recorded":
        return f"{rec.get('finding_id', '?')} -> {rec.get('verdict', '?')}: {str(rec.get('reason', ''))[:120]}"
    if event == "api_usage":
        return f"cost ${rec.get('cost_usd', 0):.4f} (cumulative ${rec.get('cumulative_cost_usd', 0):.4f})"
    if event == "budget_event":
        return _compact_json({k: v for k, v in rec.items()
                              if k not in ("seq", "ts", "run_id", "event")})
    if event in ("run_started", "run_ended", "run_interrupted"):
        return _compact_json({k: v for k, v in rec.items()
                              if k not in ("seq", "ts", "run_id", "event")})
    return ""


def _compact_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)[:240]
    except (TypeError, ValueError):
        return str(obj)[:240]


def _inventory_from_ledger(records: list[dict[str, Any]],
                           run_dir: Path) -> list[dict[str, Any]]:
    """The evidence inventory (path/type/size/sha256) for Appendix B.

    Sourced from the evidence_inventory tool's stored output. We find the first
    evidence_inventory tool_result, read its stored output file, and return its
    `files` list. Missing/unreadable -> [].
    """
    output_path: str | None = None
    for rec in records:
        if rec.get("event") == "tool_result" and rec.get("tool") == "evidence_inventory":
            output_path = rec.get("output_path")
            break
    if not output_path:
        return []
    try:
        data = json.loads((run_dir / output_path).read_text(
            encoding="utf-8", errors="replace"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    files = data.get("files") if isinstance(data, dict) else None
    return files if isinstance(files, list) else []


def _budget_notes(records: list[dict[str, Any]],
                  extra_notes: list[str] | None) -> list[str]:
    """Budget-guard notes to surface in the report header.

    Combines any caller-supplied notes (BudgetGuard.notes) with a synthesized
    note when budget_event lines exist in the ledger (graceful degradation
    fired) - prd.md: budget-guard activation noted in the report.
    """
    notes: list[str] = list(extra_notes or [])
    budget_events = [r for r in records if r.get("event") == "budget_event"]
    if budget_events and not notes:
        notes.append(
            "A budget-guard event was recorded during this run; the run "
            "degraded gracefully within its cost ceiling (see the tool-call "
            "index for details).")
    return notes


# ------------------------------------------------- cited-evidence excerpts


def _cited_evidence(finding: dict[str, Any], records: list[dict[str, Any]],
                    run_dir: Path) -> list[dict[str, Any]]:
    """For each cited seq, resolve {cite_seq, tool, output_path, excerpt}.

    Reuses the verifier's ledger reconstruction so the report and the verifier
    agree on what a citation pins down. The excerpt is pulled from the cited
    tool_result's stored output file (runs/<id>/outputs/<seq>_<tool>.*).
    """
    from verdict.agent.verifier import build_cited_entries

    cites = _int_cites(finding)
    entries = build_cited_entries(records, cites)
    out: list[dict[str, Any]] = []
    for entry in entries:
        out.append({
            "cite_seq": entry.get("cite_seq"),
            "tool": entry.get("tool", "?"),
            "output_path": entry.get("output_path"),
            "excerpt": _excerpt(run_dir, entry.get("output_path")),
        })
    return out


def _int_cites(finding: dict[str, Any]) -> list[int]:
    out: list[int] = []
    for c in finding.get("cites", []) or []:
        try:
            out.append(int(c))
        except (TypeError, ValueError):
            continue
    return out


def _excerpt(run_dir: Path, output_path: str | None) -> str:
    """A short text excerpt from a stored tool output, or "" if unavailable.

    JSON outputs are pretty-printed (so the relevant content reads cleanly);
    other text is taken verbatim. Truncated to EXCERPT_CHARS with an ellipsis.
    Binary / missing files yield "" (the template shows a graceful placeholder).
    """
    if not output_path:
        return ""
    path = (run_dir / output_path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return ""
    text = raw
    stripped = raw.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            text = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            text = raw
    text = text.strip()
    if len(text) > EXCERPT_CHARS:
        text = text[:EXCERPT_CHARS].rstrip() + "\n... (truncated; full output in the run folder)"
    return text


# --------------------------------------------------------- prose (Sonnet)


def _findings_for_prose(headline: list[dict[str, Any]]) -> str:
    """The user-turn payload for the prose call: the headline findings as JSON."""
    slim = [{
        "id": f.get("id"),
        "claim": f.get("claim"),
        "severity": f.get("severity"),
        "attack_id": f.get("attack_id"),
        "verdict": f.get("verdict"),
    } for f in headline]
    return (
        "Write the executive summary and attack narrative for these "
        "VERIFIED/UNCONFIRMED findings (return STRICT JSON per your "
        "instructions):\n\n" + json.dumps(slim, indent=2, ensure_ascii=False))


def _response_text(response: Any) -> str:
    """Concatenate the text blocks of an anthropic messages response."""
    parts: list[str] = []
    for block in getattr(response, "content", None) or []:
        btype = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
        if btype == "text":
            text = block.get("text") if isinstance(block, dict) else getattr(block, "text", "")
            if text:
                parts.append(text)
    return "".join(parts)


def _parse_prose(text: str) -> dict[str, Any] | None:
    """Parse the model's JSON prose payload, tolerating stray fences/prose."""
    text = text.strip()
    if not text:
        return None
    # Strip a ```json fence if present.
    if text.startswith("```"):
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    # Fall back to the first {...} span.
    candidate = text
    if not candidate.lstrip().startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        candidate = text[start:end + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _normalize_narrative(raw: Any, valid_ids: set[str]) -> list[dict[str, str]]:
    """Coerce the model's attack_narrative into [{text, finding_id}] entries.

    Every narrative sentence must be footnoted to a SUPPLIED (headline) finding
    id - the narrative is over VERIFIED/UNCONFIRMED findings only. A sentence
    with a missing finding_id or one we did not supply (e.g. a refuted or
    invented id) is dropped entirely, so no narrative sentence ever renders a
    dangling or excluded-finding anchor.
    """
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        if not text:
            continue
        fid = str(item.get("finding_id", "")).strip()
        if fid not in valid_ids:
            continue  # unfootnoted / excluded / invented -> drop the sentence
        out.append({"text": text, "finding_id": fid})
    return out


def _deterministic_summary(headline: list[dict[str, Any]],
                           inventory: list[dict[str, Any]]) -> str:
    """An honest, jargon-light fallback exec summary (clean case / no model).

    Used when there is no prose client, the call fails, or the model returns
    nothing usable. For a clean case it states what was examined and that it was
    clean (prd.md > Failure & Empty-Case Behavior).
    """
    n_files = len(inventory)
    examined = (f"{n_files} evidence item{'s' if n_files != 1 else ''}"
                if n_files else "the supplied evidence")
    if not headline:
        return (
            f"VERDICT examined {examined} and found no indicators of compromise. "
            f"Every potential lead raised during triage was independently "
            f"re-checked and none survived as a confirmed finding. No malicious "
            f"activity, persistence, or attacker tooling was established from the "
            f"evidence provided. This is an honest empty result: the "
            f"investigation completed and the evidence appears clean.")
    n = len(headline)
    sev = [str(f.get("severity", "")).lower() for f in headline]
    worst = next((s for s in ("critical", "high", "medium", "low") if s in sev),
                 "low")
    return (
        f"VERDICT examined {examined} and reported {n} "
        f"finding{'s' if n != 1 else ''} after independent verification. "
        f"The most serious confirmed issue is rated {worst}. Each finding below "
        f"was re-derived from the raw evidence it cites by a separate "
        f"adversarial pass, and any claim that could not be reproduced was "
        f"excluded from this summary. See the findings table for severity and "
        f"confidence, and the finding detail for the underlying evidence.")


async def _generate_prose(anthropic_client: Any, headline: list[dict[str, Any]],
                          inventory: list[dict[str, Any]], model: str,
                          ) -> tuple[str, list[dict[str, str]]]:
    """Produce (executive_summary, attack_narrative) via one prose call.

    Async: awaited from the orchestrator's running event loop (cli) - an earlier
    asyncio.run() here raised "cannot be called from a running loop", silently
    fell back, and left the coroutine un-awaited. Best-effort otherwise: no
    client, empty headline, call failure, or malformed output -> deterministic
    honest summary + empty narrative. NEVER raises - the report must render.
    """
    fallback = (_deterministic_summary(headline, inventory), [])
    if anthropic_client is None or not headline:
        return fallback
    try:
        response = await anthropic_client.messages.create(
            model=model,
            max_tokens=1500,
            system=[{"type": "text", "text": REPORT_PROSE_SYSTEM}],
            messages=[{"role": "user",
                       "content": _findings_for_prose(headline)}],
        )
    except Exception:  # noqa: BLE001 - prose is best-effort; never fatal
        return fallback

    data = _parse_prose(_response_text(response))
    if not data:
        return fallback
    summary = str(data.get("executive_summary", "")).strip()
    valid_ids = {str(f.get("id")) for f in headline}
    narrative = _normalize_narrative(data.get("attack_narrative"), valid_ids)
    if not summary:
        summary = fallback[0]
    return summary, narrative


# --------------------------------------------------------- public API


async def generate_report(run_dir: str, findings: list[dict], ledger_path: str,
                          *, case_name: str, model: str, total_cost: float,
                          wall_time: str = "", anthropic_client: Any = None,
                          budget_notes: list[str] | None = None,
                          interrupted: bool = False) -> str:
    """Render template.html.j2 -> runs/<id>/report.html; returns the path.

    `findings` is the FindingsStore list (id/claim/severity/attack_id/cites/
    verdict/verdict_reason). `anthropic_client` drives the single prose call (a
    fake client in tests, the real AsyncAnthropic in production); pass None to
    skip the call entirely and use the deterministic summary. Everything else is
    read off disk (ledger.jsonl + the stored tool outputs), so the report is a
    faithful rendering of the run.
    """
    run_path = Path(run_dir).resolve()
    records = _read_ledger(Path(ledger_path))

    headline = [f for f in findings
                if str(f.get("verdict") or "").upper() in HEADLINE_VERDICTS]
    refuted = [f for f in findings
               if str(f.get("verdict") or "").upper() == "REFUTED"]

    # Attach cited-evidence excerpts to each headline finding for the detail.
    headline_ctx = []
    for f in headline:
        ctx = dict(f)
        ctx["verdict"] = str(f.get("verdict") or "").upper()
        ctx["severity"] = str(f.get("severity") or "").lower()
        ctx["evidence"] = _cited_evidence(f, records, run_path)
        headline_ctx.append(ctx)
    refuted_ctx = []
    for f in refuted:
        ctx = dict(f)
        ctx["severity"] = str(f.get("severity") or "").lower()
        refuted_ctx.append(ctx)

    inventory = _inventory_from_ledger(records, run_path)
    summary, narrative = await _generate_prose(anthropic_client, headline_ctx,
                                               inventory, model)

    context = {
        "case_name": case_name,
        "run_id": run_path.name,
        "model": model,
        "total_cost": total_cost,
        "wall_time": wall_time or "(not recorded)",
        "interrupted": interrupted,
        "budget_notes": _budget_notes(records, budget_notes),
        "executive_summary": summary,
        "attack_narrative": narrative,
        "verified_unconfirmed": headline_ctx,
        "refuted": refuted_ctx,
        "inventory": inventory,
        "ledger": _ledger_view(records),
    }

    html = _render(context)
    out_path = run_path / REPORT_FILENAME
    out_path.write_text(html, encoding="utf-8")
    return str(out_path)


def _render(context: dict[str, Any]) -> str:
    """Render the Jinja2 template with autoescaping on (untrusted tool text)."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    template_dir = Path(__file__).resolve().parent
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2", "html.j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("template.html.j2")
    return template.render(**context)


# --------------------------------------------------------------- PDF chain


def attempt_pdf(html_path: str) -> str | None:
    """Try chromium headless, then wkhtmltopdf; return the PDF path or None.

    Discovers binaries on PATH (never hardcoded). On success writes report.pdf
    beside report.html and returns its path. If no usable binary is present (or
    every attempt fails), prints the manual-fallback message and returns None -
    NEVER raises, so a host without a PDF engine does not fail the run (PRD only
    requires the PDF exists for submission; resolves open question #4).
    """
    html = Path(html_path).resolve()
    pdf = html.with_name(PDF_FILENAME)

    for builder in (_pdf_via_chromium, _pdf_via_wkhtmltopdf):
        try:
            if builder(html, pdf) and pdf.exists() and pdf.stat().st_size > 0:
                return str(pdf)
        except Exception:  # noqa: BLE001 - try the next engine, never crash
            continue

    print(f"verdict: {PDF_MANUAL_FALLBACK}")
    return None


#: Candidate chromium executable names, in preference order (cross-platform).
_CHROMIUM_NAMES = (
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    "chrome", "msedge",
)


def _find_binary(names: tuple[str, ...]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _pdf_via_chromium(html: Path, pdf: Path) -> bool:
    """Render with headless Chromium/Chrome (--headless --print-to-pdf)."""
    binary = _find_binary(_CHROMIUM_NAMES)
    if not binary:
        return False
    # file:// URI so headless Chrome loads the local self-contained HTML.
    uri = html.as_uri()
    cmd = [
        binary, "--headless", "--disable-gpu", "--no-sandbox",
        f"--print-to-pdf={pdf}", "--print-to-pdf-no-header", uri,
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=120)
    return result.returncode == 0


def _pdf_via_wkhtmltopdf(html: Path, pdf: Path) -> bool:
    """Render with wkhtmltopdf."""
    binary = shutil.which("wkhtmltopdf")
    if not binary:
        return False
    cmd = [binary, "--quiet", str(html), str(pdf)]
    result = subprocess.run(cmd, capture_output=True, timeout=120)
    return result.returncode == 0
