"""Subprocess runner - the single choke point for all external binaries.

Spec ref: spec.md > MCP Server > Subprocess runner (runner.py).
PRD ref: prd.md > Constrained Tooling.

Every forensic binary execution flows through Runner.run_tool():
  - argv is a LIST whose prefix comes from binaries.resolve(capability) -
    executable paths NEVER come from model input; shell=False always.
  - per-tool timeout (default 120 s; mem_analyze 600 s).
  - FULL stdout -> <run_dir>/outputs/<seq>_<tool>.<ext> where <seq> is the
    tool_called ledger seq, zero-padded to 4; SHA-256 of that file ledgered.
  - tool_called is ledgered BEFORE exec, tool_result AFTER (always, even on
    failure), so the audit trail is intact whatever happens in between.
  - the model gets an excerpt capped at 8 KiB (character-safe UTF-8
    truncation) plus a pointer to the full artifact + its hash.
  - nonzero exit / timeout / spawn failure -> structured error result
    (is_error=True, stderr excerpt included), still ledgered as tool_result
    with the exit code. Retry-once-then-route-around is the ORCHESTRATOR's
    job (spec.md > Agent loop); the runner reports, it never retries.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from verdict_mcp import binaries
from verdict_mcp.ledger import Ledger

DEFAULT_TIMEOUT_S = 120
MEM_ANALYZE_TIMEOUT_S = 600
#: Per-tool timeout overrides; anything not listed gets DEFAULT_TIMEOUT_S.
DEFAULT_TIMEOUTS: dict[str, int] = {"mem_analyze": MEM_ANALYZE_TIMEOUT_S}

EXCERPT_CAP_BYTES = 8 * 1024  # 8192: what the model sees of stdout
STDERR_EXCERPT_CAP_BYTES = 2 * 1024  # error diagnostics stay small
OUTPUTS_DIRNAME = "outputs"


def _excerpt(data: bytes, cap: int = EXCERPT_CAP_BYTES) -> tuple[str, bool]:
    """First `cap` bytes of `data` as text, never cutting a UTF-8 char in half.

    Returns (text, truncated). Non-UTF-8 bytes decode with replacement chars;
    when truncating, partial trailing sequences are dropped so the boundary is
    character-safe.
    """
    truncated = len(data) > cap
    cut = data[:cap]
    if truncated:
        while cut and (cut[-1] & 0xC0) == 0x80:  # trailing continuation bytes
            cut = cut[:-1]
        if cut and cut[-1] >= 0xC0:  # orphaned multi-byte lead byte
            cut = cut[:-1]
    return cut.decode("utf-8", errors="replace"), truncated


@dataclass(frozen=True)
class RunResult:
    """What a tool implementation gets back from run_tool()."""

    tool: str
    capability: str
    seq: int  # tool_called ledger seq == output filename stem
    result_seq: int  # tool_result ledger seq
    exit_code: int | None  # None: timed out or never spawned
    duration_ms: int
    output_path: Path  # absolute path of the full output file
    output_rel: str  # run-dir-relative, posix-style ("outputs/0042_...")
    output_sha256: str
    excerpt: str  # stdout excerpt, <= 8 KiB UTF-8, character-safe
    truncated: bool
    is_error: bool
    stderr_excerpt: str = ""
    error: str | None = None  # one-line failure summary (model-readable)
    timed_out: bool = False
    argv: tuple[str, ...] = field(default=())

    def payload(self) -> dict[str, Any]:
        """The dict a tool returns to the model: excerpt + pointer, never the blob."""
        data: dict[str, Any] = {
            "excerpt": self.excerpt,
            "truncated": self.truncated,
            "output_path": self.output_rel,
            "output_sha256": self.output_sha256,
            # The tool_result ledger seq - what record_finding cites.
            "cite_seq": self.result_seq,
            "exit_code": self.exit_code,
            "is_error": self.is_error,
        }
        if self.is_error:
            data["error"] = self.error
            data["stderr"] = self.stderr_excerpt
        return data


class Runner:
    """Executes fixed binaries for one run; writes outputs + ledger pairs.

    `extra_argv` maps capability name -> fixed argv prefix and is checked
    before binaries.resolve(). It exists for tests (e.g. a harmless
    `sys.executable -c ...` capability) - production capabilities live in
    binaries.py, the single source of binary paths.
    """

    def __init__(self, run_dir: str | Path, ledger: Ledger, *,
                 extra_argv: Mapping[str, Sequence[str]] | None = None) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.ledger = ledger
        self.outputs_dir = self.run_dir / OUTPUTS_DIRNAME
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        self._extra_argv: dict[str, tuple[str, ...]] = {
            name: tuple(str(part) for part in prefix)
            for name, prefix in (extra_argv or {}).items()
        }

    def run_tool(self, capability: str, args: Sequence[str | Path], *,
                 tool: str | None = None, params: dict[str, Any] | None = None,
                 ext: str = "txt", timeout_s: int | None = None,
                 component: str | None = None,
                 output_file: Path | None = None) -> RunResult:
        """Run one fixed binary with validated args; persist + ledger everything.

        capability: binaries.py capability name (or an extra_argv test entry).
        args:       argument list appended to the fixed argv prefix. Already
                    validated/pathguarded by the calling tool - NEVER a raw
                    command string; there is nothing here a shell ever parses.
        tool:       model-visible tool name for the ledger + output filename
                    (defaults to the capability name).
        params:     the validated tool params to ledger with tool_called
                    (defaults to {"args": [...]}).
        ext:        output file extension (json for parsers that emit JSON).
        timeout_s:  override; defaults to DEFAULT_TIMEOUTS[tool] or 120 s.
        component:  pick a non-lead component of the capability, e.g.
                    run_tool("fs", ..., component="icat").
        output_file: a tool that writes its real output to a FILE rather than
                    stdout (e.g. EvtxECmd -> records JSONL) passes that path;
                    the runner hashes/persists those DETERMINISTIC bytes as the
                    cited artifact instead of the run-stamped console log on
                    stdout, so static evidence re-runs byte-for-byte (no replay
                    drift). Falls back to stdout if the file is missing.
        """
        tool = tool or capability
        prefix = self._argv_prefix(capability, component)
        argv = [*prefix, *(str(a) for a in args)]
        if timeout_s is None:
            timeout_s = DEFAULT_TIMEOUTS.get(tool, DEFAULT_TIMEOUT_S)

        seq = self.ledger.tool_called(
            tool,
            params if params is not None else {"args": [str(a) for a in args]},
            argv=argv,  # exact command line, for the audit trail
        )
        out_name = f"{seq:04d}_{tool}.{ext}"
        out_path = self.outputs_dir / out_name
        output_rel = f"{OUTPUTS_DIRNAME}/{out_name}"

        stdout = b""
        stderr = b""
        exit_code: int | None = None
        error: str | None = None
        timed_out = False
        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv prefix, shell=False
                argv, shell=False, capture_output=True, timeout=timeout_s,
            )
            exit_code = proc.returncode
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            error = f"'{tool}' timed out after {timeout_s}s and was killed"
        except OSError as exc:
            error = f"'{tool}' failed to start: {exc}"
        duration_ms = int((time.monotonic() - start) * 1000)

        # Full output + hash exist even for failures - citations stay checkable.
        # When the tool wrote its records to output_file, cite THOSE bytes (the
        # actual evidence, deterministic) not stdout (EvtxECmd's console log is
        # run-stamped and would drift on every re-run). stdout otherwise - which
        # is the records themselves for stdout-emitting tools like evtx_dump.
        if output_file is not None and output_file.is_file():
            payload = output_file.read_bytes()
        else:
            payload = stdout
        out_path.write_bytes(payload)
        output_sha256 = hashlib.sha256(payload).hexdigest()
        excerpt, truncated = _excerpt(payload)
        stderr_excerpt, _ = _excerpt(stderr, STDERR_EXCERPT_CAP_BYTES)

        is_error = timed_out or error is not None or exit_code != 0
        if is_error and error is None:
            error = f"'{tool}' exited with code {exit_code}"
            if stderr_excerpt:
                error += f": {stderr_excerpt.splitlines()[0][:200]}"

        extra: dict[str, Any] = {}
        if is_error:
            extra["is_error"] = True
            extra["error"] = error
        if timed_out:
            extra["timed_out"] = True
        result_seq = self.ledger.tool_result(
            tool, duration_ms=duration_ms, output_sha256=output_sha256,
            output_path=output_rel, truncated=truncated, exit_code=exit_code,
            **extra,
        )

        return RunResult(
            tool=tool, capability=capability, seq=seq, result_seq=result_seq,
            exit_code=exit_code, duration_ms=duration_ms,
            output_path=out_path, output_rel=output_rel,
            output_sha256=output_sha256, excerpt=excerpt, truncated=truncated,
            is_error=is_error, stderr_excerpt=stderr_excerpt, error=error,
            timed_out=timed_out, argv=tuple(argv),
        )

    # ----------------------------------------------------------- test seam

    def has_capability_override(self, capability: str) -> bool:
        """True if an `extra_argv` prefix is registered for `capability`.

        Tools consult this to keep their argv shape in sync with the test
        stub instead of probing binaries.resolve() on hosts without the
        real forensic binaries.
        """
        return capability in self._extra_argv

    def add_capability_override(self, capability: str,
                                argv: Sequence[str | Path]) -> None:
        """Register/replace a fixed argv prefix after construction.

        Mirrors the constructor's `extra_argv` test seam for harnesses that
        receive an already-built AppContext (build_app constructs the Runner
        internally). Test-only; production capabilities live in binaries.py.
        """
        self._extra_argv[capability] = tuple(str(part) for part in argv)

    # ---------------------------------------------------------------- helpers

    def _argv_prefix(self, capability: str,
                     component: str | None) -> tuple[str, ...]:
        """Fixed argv prefix for a capability - never from model input."""
        if capability in self._extra_argv:
            return self._extra_argv[capability]
        resolved = binaries.resolve(capability)
        if component is not None:
            probe = resolved.component(component)
            if probe.argv is None:
                raise binaries.BinaryNotFoundError(
                    f"capability '{capability}' component '{component}' is a "
                    f"python library ({probe.module}), not a CLI - use it "
                    f"in-process, not via the runner"
                )
            return probe.argv
        if resolved.argv is None:
            raise binaries.BinaryNotFoundError(
                f"capability '{capability}' resolved to python library "
                f"'{resolved.module}', not a CLI - use it in-process, not "
                f"via the runner"
            )
        return resolved.argv
