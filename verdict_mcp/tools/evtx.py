"""Tool 5: evtx_query.

Spec ref: spec.md > MCP Server > Tool definitions > #5 evtx_query.

Query an event log. Params: log (path), event_ids?, after?, before?,
keyword?, limit (REQUIRED, <=500). The binary dumps records (runner
capability "evtx"); this module filters them in Python and truncates to
`limit`. Two invocation shapes, chosen by what binaries.resolve() found:

  primary  EvtxECmd (.NET): -f <log> --json <scratch> --jsonf <name> -
           records land in a scratch JSONL file under the run dir; the
           runner artifact holds the console log.
  fallback evtx_dump: -o jsonl <log> - records ARE the runner artifact.

The test seam (runner extra_argv "evtx") uses the fallback shape with a
stub that prints canned JSONL, so the whole pipeline runs without a real
binary.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from verdict_mcp import binaries
from verdict_mcp.tools.common import (
    cap_items,
    clean_params,
    in_window,
    parse_event_time,
    require_file,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

MAX_LIMIT = 500
#: A single record's `data` is clipped to this many chars in the response.
RECORD_DATA_CAP = 1024


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Compact, shape-agnostic record: handles both evtx_dump's nested
    {"Event": {"System": ..., "EventData": ...}} and EvtxECmd's flat maps."""
    event = raw.get("Event")
    if isinstance(event, dict) and isinstance(event.get("System"), dict):
        system = event["System"]
        event_id: Any = system.get("EventID")
        if isinstance(event_id, dict):  # {"#text": 7045, "#attributes": ...}
            event_id = event_id.get("#text")
        time_created = system.get("TimeCreated")
        when = None
        if isinstance(time_created, dict):
            when = (time_created.get("#attributes") or {}).get("SystemTime")
        provider = system.get("Provider")
        if isinstance(provider, dict):
            provider = (provider.get("#attributes") or {}).get("Name")
        data: Any = event.get("EventData")
    else:  # EvtxECmd flat record
        event_id = raw.get("EventId", raw.get("EventID"))
        when = raw.get("TimeCreated")
        provider = raw.get("Provider")
        data = raw.get("Payload")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                pass
        extras = {key: raw[key] for key in
                  ("MapDescription", "UserName", "ExecutableInfo")
                  if raw.get(key)}
        if extras:
            data = {"payload": data, **extras} if data else extras
        system = raw  # Channel/Computer live at the top level here

    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        pass
    data_text = json.dumps(data, ensure_ascii=False, default=str) \
        if data is not None else None
    if data_text is not None and len(data_text) > RECORD_DATA_CAP:
        data = data_text[:RECORD_DATA_CAP] + "...[truncated]"
    return {
        "event_id": event_id,
        "time": when,
        "provider": provider,
        "channel": system.get("Channel"),
        "computer": system.get("Computer"),
        "data": data,
    }


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def evtx_query(
        log: str,
        limit: Annotated[int, Field(
            ge=1, le=MAX_LIMIT,
            description="Max records returned (required; <=500)")],
        event_ids: Annotated[list[int] | None, Field(
            description="Only these event IDs, e.g. [4624, 7045]")] = None,
        after: Annotated[datetime | None, Field(
            description="Only events at/after this ISO timestamp")] = None,
        before: Annotated[datetime | None, Field(
            description="Only events at/before this ISO timestamp")] = None,
        keyword: Annotated[str | None, Field(
            description="Case-insensitive substring match on the raw record")] = None,
    ) -> dict[str, Any]:
        """Query a Windows event log (.evtx). Narrow with event_ids, an
        after/before time window, and/or a keyword; results truncate at
        `limit`. Returns compact records (event_id, time, provider,
        channel, computer, data) plus the total match count and a pointer
        to the full parsed dump in the run folder."""
        path = require_file(ctx.pathguard.resolve_read(log, "log"), "log")
        params = clean_params(log=log, event_ids=event_ids, after=after,
                              before=before, keyword=keyword, limit=limit)

        records_file: Path | None = None
        if ctx.runner.has_capability_override("evtx"):
            resolved = None  # test stub speaks the fallback shape
        else:
            resolved = binaries.try_resolve("evtx")
        if resolved is not None and resolved.tier == "primary":  # EvtxECmd
            scratch = ctx.run_dir / "scratch"
            scratch.mkdir(parents=True, exist_ok=True)
            records_name = f"evtx_{uuid.uuid4().hex[:8]}.jsonl"
            records_file = scratch / records_name
            args: list[str | Path] = ["-f", path, "--json", scratch,
                                      "--jsonf", records_name]
        else:  # evtx_dump (or the test stub): JSONL on stdout
            args = ["-o", "jsonl", path]

        run = ctx.runner.run_tool("evtx", args, tool="evtx_query",
                                  params=params, ext="jsonl")
        if run.is_error:
            return run.payload()
        source = records_file if records_file is not None else run.output_path
        if not source.is_file():
            out = run.payload()
            out["is_error"] = True
            out["error"] = "parser produced no JSON records file"
            return out

        matches: list[dict[str, Any]] = []
        total = 0
        parse_errors = 0
        wanted_ids = set(event_ids) if event_ids else None
        needle = keyword.lower() if keyword else None
        for line in source.read_text(encoding="utf-8",
                                     errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            record = _normalize(raw)
            if wanted_ids is not None and record["event_id"] not in wanted_ids:
                continue
            if (after or before) and not in_window(
                    parse_event_time(record["time"]), after, before):
                continue
            if needle is not None and needle not in line.lower():
                continue
            total += 1
            if len(matches) < limit:
                matches.append(record)

        kept, capped = cap_items(matches)
        out: dict[str, Any] = {
            "total_matches": total,
            "returned": len(kept),
            "records": kept,
            "truncated": capped or len(kept) < total,
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
        if records_file is not None:
            out["records_path"] = records_file.relative_to(
                ctx.run_dir).as_posix()
        if parse_errors:
            out["unparseable_lines_skipped"] = parse_errors
        return out
