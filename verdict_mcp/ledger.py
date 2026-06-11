"""Ledger writer - append-only JSONL, fsync per line, server-only.

Spec ref: spec.md > MCP Server > Ledger writer (ledger.py).
PRD ref: prd.md > Audit Ledger.

Append-only runs/<id>/ledger.jsonl, written by the server ONLY, one JSON object
per line, fsync after every line - intact up to the moment of death if the
process is killed. The Ledger object created with the run dir is THE single
writer: no other module opens ledger.jsonl. Orchestrator-side events reach it
through the `_log_event` control-plane tool (see server.py), which the model
never sees.

Schema example:
{"seq": 43, "ts": "2026-06-12T09:14:03.221Z", "run_id": "...",
 "event": "tool_result", "tool": "evtx_query", "duration_ms": 1180,
 "output_sha256": "ab12...", "output_path": "outputs/0043_evtx_query.json",
 "truncated": true, "exit_code": 0}
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEDGER_FILENAME = "ledger.jsonl"

#: Every event type the spec defines (spec.md > Data Model > Ledger event).
EVENT_TYPES: frozenset[str] = frozenset({
    "run_started",
    "tool_called",
    "tool_result",
    "tool_rejected",
    "finding_recorded",
    "verdict_recorded",
    "api_usage",
    "budget_event",
    "run_interrupted",
    "run_ended",
})

#: Keys the ledger owns; event-specific fields may not collide with them.
RESERVED_KEYS: frozenset[str] = frozenset({"seq", "ts", "run_id", "event"})


def utc_ts() -> str:
    """UTC ISO-8601 timestamp with millisecond precision and a 'Z' suffix."""
    now = datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Ledger:
    """Single writer for the audit trail: one fsync'd JSON line per event.

    The file handle is opened once (append mode) and every `write()` does
    write -> flush -> fsync, so each accepted event is durable on disk the
    moment `write()` returns - never batched, crash-intact (prd.md > Audit
    Ledger). Thread-safe: a lock serializes writers so lines never interleave.
    """

    def __init__(self, run_dir: str | Path, run_id: str) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.run_id = run_id
        self.path = self.run_dir / LEDGER_FILENAME
        self._lock = threading.Lock()
        # Run dirs are fresh per run (spec.md > Data Model > Run folder), but if
        # a ledger already exists we continue its seq rather than restart at 1.
        self._seq = self._last_seq_on_disk()
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")

    # ------------------------------------------------------------------ core

    def write(self, event: str, **fields: Any) -> int:
        """Append one event line + fsync; returns the assigned seq.

        `fields` are the event-specific keys (e.g. tool=..., params=...).
        Unknown event types and collisions with reserved keys are programming
        errors and raise ValueError before anything touches the file.
        """
        if event not in EVENT_TYPES:
            raise ValueError(
                f"unknown ledger event '{event}' "
                f"(known: {', '.join(sorted(EVENT_TYPES))})"
            )
        clash = RESERVED_KEYS & fields.keys()
        if clash:
            raise ValueError(
                f"event fields may not override reserved ledger keys: "
                f"{', '.join(sorted(clash))}"
            )
        with self._lock:
            if self._fh.closed:
                raise RuntimeError("ledger is closed")
            self._seq += 1
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": utc_ts(),
                "run_id": self.run_id,
                "event": event,
            }
            record.update(fields)
            # default=str: tool params may carry Path/datetime values.
            self._fh.write(json.dumps(record, ensure_ascii=False, default=str))
            self._fh.write("\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            return self._seq

    # ----------------------------------------------------- typed conveniences

    def tool_called(self, tool: str, params: dict[str, Any],
                    **extra: Any) -> int:
        """Ledger a tool invocation BEFORE it executes; returns its seq."""
        return self.write("tool_called", tool=tool, params=params, **extra)

    def tool_result(self, tool: str, *, duration_ms: int, output_sha256: str,
                    output_path: str, truncated: bool,
                    exit_code: int | None, **extra: Any) -> int:
        """Ledger a tool outcome (success or structured error) after it ran."""
        return self.write(
            "tool_result", tool=tool, duration_ms=duration_ms,
            output_sha256=output_sha256, output_path=output_path,
            truncated=truncated, exit_code=exit_code, **extra,
        )

    def tool_rejected(self, tool: str, reason: str, **extra: Any) -> int:
        """Ledger a refused call (validation failure or PathViolation)."""
        return self.write("tool_rejected", tool=tool, reason=reason, **extra)

    # -------------------------------------------------------------- lifecycle

    @property
    def seq(self) -> int:
        """Last assigned sequence number (0 before the first write)."""
        return self._seq

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---------------------------------------------------------------- helpers

    def _last_seq_on_disk(self) -> int:
        """Max seq in an existing ledger file (0 if absent/empty).

        Tolerates a torn final line - the file is valid JSONL up to the moment
        a previous process died (prd.md > Audit Ledger).
        """
        last = 0
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        seq = json.loads(line).get("seq")
                    except json.JSONDecodeError:
                        continue  # torn line from a killed process
                    if isinstance(seq, int) and seq > last:
                        last = seq
        except FileNotFoundError:
            return 0
        return last
