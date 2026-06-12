"""Shared plumbing for the typed tools (checklist item 4).

Three jobs, one module:

1. `Rejection` + `install_rejection_boundary(app, ctx)` - the PRD acceptance
   behavior (prd.md > Constrained Tooling): EVERY refused call - pydantic
   schema violation, unknown tool, unknown parameter, PathViolation, or a
   semantic Rejection raised inside a handler - produces exactly one
   `tool_rejected` ledger line and a clean, model-readable error. Never a
   traceback, never a crash. FastMCP validates params before our handlers
   run, so the boundary wraps the one choke point every call flows through
   (ToolManager.call_tool) and ledgers what FastMCP refused for us.

2. `pure_tool_call(...)` - runner conventions for in-process tools
   (evidence_inventory, read_artifact, pyscca prefetch, yara-python):
   tool_called BEFORE the work, full output -> outputs/<seq>_<tool>.<ext>,
   SHA-256, tool_result AFTER - so pure-Python results are as citable as
   subprocess results.

3. Small helpers: response capping at the 8 KiB excerpt budget, tolerant
   event-timestamp parsing, streamed SHA-256, param cleaning.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from verdict_mcp.pathguard import PathViolation
from verdict_mcp.runner import OUTPUTS_DIRNAME

if TYPE_CHECKING:  # import cycle guard: server.py -> tools -> common
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

#: Budget for what a tool sends back to the model - mirrors the runner's
#: 8 KiB stdout excerpt cap (spec.md > Subprocess runner).
RESPONSE_CAP_BYTES = 8 * 1024

#: Tools the rejection boundary leaves alone. _log_event is the
#: orchestrator-only control plane (never in the model's tools array);
#: its failures are orchestrator programming errors, not model rejections.
_BOUNDARY_EXEMPT = frozenset({"_log_event"})


class Rejection(Exception):
    """A handler-side refusal (semantic validation): clean message, ledgered.

    Raise this for anything pydantic's schema can't express - a ruleset name
    not on disk, a cite that isn't a tool_result seq, a source file of the
    wrong type. The boundary converts it to a tool_rejected ledger line and
    a clear error back to the model.
    """


# --------------------------------------------------------------- boundary


def install_rejection_boundary(app: "FastMCP", ctx: "AppContext") -> None:
    """Wrap ToolManager.call_tool so every refusal is ledgered tool_rejected.

    Single choke point: FastMCP.call_tool (used by both the stdio transport
    and in-process tests) resolves `self._tool_manager.call_tool` by
    attribute lookup at call time, so an instance-level wrapper intercepts
    every path. `_tool_manager` is FastMCP-private but stable across mcp 1.x;
    this is the only place the server touches it.
    """
    manager = app._tool_manager  # noqa: SLF001 - see docstring
    if getattr(manager, "_verdict_boundary_installed", False):
        return
    original = manager.call_tool

    async def guarded_call_tool(name: str, arguments: dict[str, Any] | None,
                                *args: Any, **kwargs: Any) -> Any:
        if name in _BOUNDARY_EXEMPT:
            return await original(name, arguments or {}, *args, **kwargs)

        tool = manager.get_tool(name)
        if tool is None:
            reason = f"unknown tool '{name}'"
            ctx.ledger.tool_rejected(name, reason, params=arguments or {})
            raise ToolError(reason)

        # FastMCP/pydantic silently ignores extra fields; a typed server
        # should not - an unknown parameter is a malformed call.
        properties = tool.parameters.get("properties", {})
        unknown = sorted(set(arguments or {}) - set(properties))
        if unknown:
            reason = (
                f"unknown parameter(s) for '{name}': {', '.join(unknown)}. "
                f"Valid parameters: {', '.join(sorted(properties)) or '(none)'}."
            )
            ctx.ledger.tool_rejected(name, reason, params=arguments or {})
            raise ToolError(reason)

        try:
            return await original(name, arguments or {}, *args, **kwargs)
        except ToolError as exc:
            reason = _clean_reason(exc)
            ctx.ledger.tool_rejected(name, reason, params=arguments or {})
            # Re-raise with the compact message; `from None` keeps pydantic's
            # multi-line dump (and any traceback text) away from the model.
            raise ToolError(reason) from None

    manager.call_tool = guarded_call_tool
    manager._verdict_boundary_installed = True  # noqa: SLF001


def _clean_reason(exc: BaseException) -> str:
    """One clean, model-readable line for a refused call.

    Tool.run wraps every handler/validation exception in ToolError with the
    cause chain preserved - walk it for the types we know how to phrase.
    """
    seen: set[int] = set()
    cause: BaseException | None = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, ValidationError):
            details = "; ".join(
                f"{'.'.join(str(loc) for loc in err['loc']) or 'params'}: "
                f"{err['msg']}"
                for err in cause.errors()
            )
            return f"invalid parameters: {details}"
        if isinstance(cause, (PathViolation, Rejection)):
            return str(cause)
        cause = cause.__cause__ or cause.__context__
    return str(exc)


# --------------------------------------------------- pure-Python tool runs


def pure_tool_call(ctx: "AppContext", tool: str, params: dict[str, Any],
                   compute: Callable[[], tuple[Any, dict[str, Any], bool]],
                   ext: str = "json") -> dict[str, Any]:
    """Runner conventions for a tool that does its work in-process.

    tool_called is ledgered BEFORE compute() runs; the FULL payload is
    written to outputs/<seq>_<tool>.<ext> and hashed; tool_result is
    ledgered AFTER - always, even if compute() raises (structured error
    result, like the runner's nonzero-exit path).

    compute() -> (full_payload, response_fields, truncated):
      full_payload    everything, JSON-dumped into the output artifact
      response_fields the capped view merged into the model's response
      truncated       True when response_fields holds less than full_payload
    """
    seq = ctx.ledger.tool_called(tool, params)
    start = time.monotonic()
    error: str | None = None
    full: Any = None
    response: dict[str, Any] = {}
    truncated = False
    try:
        full, response, truncated = compute()
    except Exception as exc:  # structured error result, never a traceback
        error = f"'{tool}' failed: {exc}"
        full = {"error": error}
    duration_ms = int((time.monotonic() - start) * 1000)

    blob = json.dumps(full, indent=2, ensure_ascii=False,
                      default=str).encode("utf-8")
    out_name = f"{seq:04d}_{tool}.{ext}"
    out_path = ctx.runner.outputs_dir / out_name
    out_path.write_bytes(blob)
    output_rel = f"{OUTPUTS_DIRNAME}/{out_name}"
    output_sha256 = hashlib.sha256(blob).hexdigest()

    extra: dict[str, Any] = {}
    if error is not None:
        extra["is_error"] = True
        extra["error"] = error
    result_seq = ctx.ledger.tool_result(
        tool, duration_ms=duration_ms, output_sha256=output_sha256,
        output_path=output_rel, truncated=truncated,
        exit_code=0 if error is None else 1, **extra,
    )

    out = dict(response)
    out.update(
        truncated=truncated,
        output_path=output_rel,
        output_sha256=output_sha256,
        cite_seq=result_seq,  # the tool_result seq record_finding cites
        is_error=error is not None,
    )
    if error is not None:
        out["error"] = error
    return out


# ----------------------------------------------------------------- helpers


def clean_params(**params: Any) -> dict[str, Any]:
    """The validated params dict for the ledger, None entries dropped."""
    return {key: value for key, value in params.items() if value is not None}


def require_file(path: Path, param: str) -> Path:
    """Reject (cleanly) when a pathguard-resolved path isn't an existing file."""
    if not path.is_file():
        raise Rejection(f"{param}='{path}' is not an existing file")
    return path


def cap_items(items: list[Any],
              cap_bytes: int = RESPONSE_CAP_BYTES) -> tuple[list[Any], bool]:
    """First items whose cumulative JSON size fits the response budget.

    Returns (kept, truncated). At least one item is always kept so a single
    oversized record degrades to one entry rather than an empty answer.
    """
    kept: list[Any] = []
    used = 0
    for item in items:
        size = len(json.dumps(item, ensure_ascii=False, default=str)
                   .encode("utf-8"))
        if kept and used + size > cap_bytes:
            return kept, True
        kept.append(item)
        used += size
        if used > cap_bytes:
            return kept, len(kept) < len(items)
    return kept, False


def cap_text(text: str, cap_bytes: int = RESPONSE_CAP_BYTES) -> tuple[str, bool]:
    """Character-safe text cap at the response budget; (text, truncated)."""
    raw = text.encode("utf-8")
    if len(raw) <= cap_bytes:
        return text, False
    return raw[:cap_bytes].decode("utf-8", errors="ignore"), True


def sha256_file(path: Path) -> str:
    """Streamed SHA-256 (evidence files can be tens of GB)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_utc(dt: datetime) -> datetime:
    """Aware UTC datetime; naive values are treated as already-UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


_FRACTION_OVERFLOW = re.compile(r"(\.\d{6})\d+")


def parse_event_time(value: Any) -> datetime | None:
    """Tolerant artifact-timestamp parse -> aware UTC datetime (None on failure).

    Handles the shapes the parsers emit: ISO-8601 with 'Z' or offset,
    evtx_dump's '2026-06-10 09:00:00.123456 UTC', EvtxECmd's 7-digit
    fractional seconds, and plain naive timestamps (assumed UTC).
    """
    if isinstance(value, datetime):
        return ensure_utc(value)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    text = _FRACTION_OVERFLOW.sub(r"\1", text)
    try:
        return ensure_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def in_window(when: datetime | None, after: datetime | None,
              before: datetime | None) -> bool:
    """True iff `when` satisfies the requested window.

    A record without a parseable timestamp fails any requested bound - a
    time-filtered answer must never smuggle in undatable records.
    """
    if after is not None and (when is None or when < ensure_utc(after)):
        return False
    if before is not None and (when is None or when > ensure_utc(before)):
        return False
    return True
