"""Tool 7: execution_evidence (prefetch + amcache in one tool).

Spec ref: spec.md > MCP Server > Tool definitions > #7 execution_evidence.

Params: source (a .pf file, a directory of .pf files, or an Amcache.hve
hive - detected from the file), name_contains?, after?, before?.

Paths (per the item-2 gate decisions):
  prefetch  pyscca, IN-PROCESS (python module, not a CLI - common.py's
            pure_tool_call writes the full output + SHA + ledger pair).
  amcache   through the runner, capability "execution":
              primary  AmcacheParser (.NET): -f <hive> --csv <scratch>;
                       CSV rows parsed and filtered here
              fallback RegRipper: -r <hive> -p amcache; report text split
                       into blocks and filtered here (time filtering on
                       text output is best-effort: blocks without a
                       parseable timestamp are kept, not dropped)

The test seam (runner extra_argv "execution") uses the RegRipper shape.
"""

from __future__ import annotations

import csv
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from verdict_mcp import binaries
from verdict_mcp.tools.common import (
    Rejection,
    cap_items,
    clean_params,
    ensure_utc,
    in_window,
    parse_event_time,
    pure_tool_call,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\S*")
#: AmcacheParser CSV columns worth echoing to the model.
_CSV_KEEP = ("ApplicationName", "Name", "FullPath", "SHA1",
             "FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp",
             "FileIDLastWriteTimestamp", "LinkDate")


def _detect_source(path: Path) -> tuple[str, list[Path]]:
    """('prefetch', [pf files]) or ('amcache', [hive]); Rejection otherwise."""
    if path.is_dir():
        pf_files = sorted(p for p in path.iterdir()
                          if p.is_file() and p.suffix.lower() == ".pf")
        if not pf_files:
            raise Rejection(
                f"source directory '{path}' contains no .pf files")
        return "prefetch", pf_files
    if not path.is_file():
        raise Rejection(f"source='{path}' is not an existing file or directory")
    if path.suffix.lower() == ".pf":
        return "prefetch", [path]
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        magic = b""
    if path.name.lower() == "amcache.hve" or path.suffix.lower() == ".hve" \
            or magic == b"regf":
        return "amcache", [path]
    raise Rejection(
        f"source='{path.name}' is neither a .pf prefetch file, a directory "
        f"of .pf files, nor an Amcache.hve registry hive"
    )


def _prefetch_records(pf_files: list[Path]) -> tuple[
        list[dict[str, Any]], list[dict[str, str]]]:
    """Parse .pf files with pyscca; per-file failures are reported, not fatal."""
    try:
        import pyscca  # gate-confirmed fallback on the SIFT VM
    except ImportError as exc:
        raise Rejection(
            "prefetch parsing requires the pyscca python module, which is "
            "not importable on this host"
        ) from exc
    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for pf in pf_files:
        try:
            scca = pyscca.open(str(pf))
        except Exception as exc:  # corrupt/unsupported .pf - keep going
            errors.append({"pf_file": pf.name, "error": str(exc)})
            continue
        run_times: list[str] = []
        for i in range(8):  # win8+ keeps the last 8 run times
            try:
                when = scca.get_last_run_time(i)
            except Exception:
                break
            if when is not None and when.year > 1970:
                run_times.append(ensure_utc(when).isoformat())
        records.append({
            "pf_file": pf.name,
            "executable": scca.executable_filename,
            "run_count": scca.run_count,
            "last_run_times": run_times,
        })
    return records, errors


def _filter_prefetch(records: list[dict[str, Any]], name_contains: str | None,
                     after: datetime | None,
                     before: datetime | None) -> list[dict[str, Any]]:
    kept = []
    for rec in records:
        if name_contains is not None:
            haystack = f"{rec['executable']} {rec['pf_file']}".lower()
            if name_contains.lower() not in haystack:
                continue
        if after or before:
            times = [parse_event_time(t) for t in rec["last_run_times"]]
            if not any(in_window(t, after, before) for t in times):
                continue
        kept.append(rec)
    return kept


def _amcache_args(ctx: "AppContext", source: Path) -> tuple[
        list[str | Path], str | None, Path | None, str]:
    """(args, runner component, csv scratch dir or None, parser label)."""
    if ctx.runner.has_capability_override("execution"):
        resolved = None  # test stub speaks the RegRipper shape
    else:
        resolved = binaries.try_resolve("execution")
    if resolved is not None and resolved.tier == "primary":  # AmcacheParser
        scratch = ctx.run_dir / "scratch" / f"amcache_{uuid.uuid4().hex[:8]}"
        scratch.mkdir(parents=True, exist_ok=True)
        return (["-f", source, "--csv", scratch], "AmcacheParser", scratch,
                "AmcacheParser")
    component = "RegRipper" if resolved is not None else None
    return ["-r", source, "-p", "amcache"], component, None, "RegRipper -p amcache"


def _amcache_entries_from_csv(scratch: Path, name_contains: str | None,
                              after: datetime | None,
                              before: datetime | None) -> list[dict[str, Any]]:
    entries = []
    for csv_path in sorted(scratch.glob("*.csv")):
        with open(csv_path, newline="", encoding="utf-8",
                  errors="replace") as fh:
            for row in csv.DictReader(fh):
                if name_contains is not None and \
                        name_contains.lower() not in str(row).lower():
                    continue
                if after or before:
                    stamps = [parse_event_time(v) for k, v in row.items()
                              if k and "timestamp" in k.lower()]
                    stamps = [s for s in stamps if s is not None]
                    if stamps and not any(in_window(s, after, before)
                                          for s in stamps):
                        continue
                entry = {k: row[k] for k in _CSV_KEEP if row.get(k)}
                entry["_csv"] = csv_path.name
                entries.append(entry or {"_csv": csv_path.name, **row})
    return entries


def _amcache_entries_from_text(text: str, name_contains: str | None,
                               after: datetime | None,
                               before: datetime | None) -> list[str]:
    """RegRipper report -> blocks; name filter exact, time filter best-effort
    (a block with no parseable timestamp is kept - never silently dropped)."""
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
    kept = []
    for block in blocks:
        if name_contains is not None and \
                name_contains.lower() not in block.lower():
            continue
        if after or before:
            stamps = [parse_event_time(m)
                      for m in _TIMESTAMP_RE.findall(block)]
            stamps = [s for s in stamps if s is not None]
            if stamps and not any(in_window(s, after, before)
                                  for s in stamps):
                continue
        kept.append(block)
    return kept


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def execution_evidence(
        source: str,
        name_contains: Annotated[str | None, Field(
            description="Case-insensitive substring on executable name/path")] = None,
        after: Annotated[datetime | None, Field(
            description="Only evidence at/after this ISO timestamp")] = None,
        before: Annotated[datetime | None, Field(
            description="Only evidence at/before this ISO timestamp")] = None,
    ) -> dict[str, Any]:
        """Program-execution evidence from prefetch or Amcache. `source`
        is a .pf file, a directory of .pf files, or an Amcache.hve hive
        (type auto-detected). Prefetch yields executable, run count and
        last-run times; Amcache yields file path/SHA1 entries. Narrow with
        name_contains and/or an after/before window."""
        path = ctx.pathguard.resolve_read(source, "source")
        source_type, files = _detect_source(path)
        params = clean_params(source=source, name_contains=name_contains,
                              after=after, before=before)

        if source_type == "prefetch":
            def compute() -> tuple[Any, dict[str, Any], bool]:
                records, errors = _prefetch_records(files)
                kept = _filter_prefetch(records, name_contains, after, before)
                full = {"source_type": "prefetch", "parser": "pyscca",
                        "pf_files_parsed": len(records),
                        "parse_errors": errors, "all_records": records,
                        "matches": kept}
                shown, capped = cap_items(kept)
                response: dict[str, Any] = {
                    "source_type": "prefetch",
                    "parser": "pyscca",
                    "total_matches": len(kept),
                    "returned": len(shown),
                    "records": shown,
                }
                if errors:
                    response["parse_errors"] = errors[:10]
                return full, response, capped
            # Rejection from a missing pyscca must hit the boundary, not
            # become a structured error result - probe the import first.
            try:
                import pyscca  # noqa: F401
            except ImportError as exc:
                raise Rejection(
                    "prefetch parsing requires the pyscca python module, "
                    "which is not importable on this host"
                ) from exc
            return pure_tool_call(ctx, "execution_evidence", params, compute)

        # amcache via the runner
        args, component, scratch, parser = _amcache_args(ctx, path)
        run = ctx.runner.run_tool("execution", args, tool="execution_evidence",
                                  params=params, ext="txt",
                                  component=component)
        if run.is_error:
            return run.payload()
        if scratch is not None:  # AmcacheParser CSVs
            entries: list[Any] = _amcache_entries_from_csv(
                scratch, name_contains, after, before)
        else:  # RegRipper (or stub) report text
            text = run.output_path.read_text(encoding="utf-8",
                                             errors="replace")
            entries = _amcache_entries_from_text(text, name_contains,
                                                 after, before)
        shown, capped = cap_items(entries)
        return {
            "source_type": "amcache",
            "parser": parser,
            "total_entries": len(entries),
            "returned": len(shown),
            "entries": shown,
            "truncated": capped,
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
