"""Tool 10: yara_scan.

Spec ref: spec.md > MCP Server > Tool definitions > #10 yara_scan.

Params: target (file or directory under the case or run dir), ruleset
(enum derived from <repo>/rules/*.yar at server start - registration
builds a real Literal type from the files on disk, so the schema the
model sees lists the actual rulesets). Primary: yara CLI via runner
capability "yara"; fallback: yara-python in-process (a library, so it
goes through common.py's pure_tool_call for its ledger pair + artifact).
Returns match names + string offsets.

NOTE: this module deliberately has no `from __future__ import annotations`
- the dynamic ruleset Literal must be a real annotation object at
decoration time, not a string FastMCP can't resolve.

The test seam (runner extra_argv "yara") stubs the CLI path.
"""

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from verdict_mcp import binaries
from verdict_mcp.tools.common import (
    Rejection,
    cap_items,
    clean_params,
    pure_tool_call,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = Path(os.environ.get("VERDICT_RULES_DIR", REPO_ROOT / "rules"))
#: Directory scans stop after this many files - a query tool, not a crawler.
MAX_DIR_FILES = 2000
MATCH_DATA_CAP = 128

_MATCH_LINE = re.compile(r"^([A-Za-z_]\w*) (.+)$")
_STRING_LINE = re.compile(r"^0x([0-9a-fA-F]+):(\$[\w\-]*):\s?(.*)$")


def discover_rulesets() -> dict[str, Path]:
    """name -> path for every .yar/.yara file shipped in rules/."""
    if not RULES_DIR.is_dir():
        return {}
    found: dict[str, Path] = {}
    for pattern in ("*.yar", "*.yara"):
        for path in sorted(RULES_DIR.glob(pattern)):
            found.setdefault(path.stem, path)
    return found


def _parse_cli_output(text: str) -> list[dict[str, Any]]:
    """yara -s output -> [{rule, target, strings: [{offset, identifier,
    data}]}]. String-detail lines attach to the preceding match line."""
    matches: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith(("warning", "error")):
            continue
        detail = _STRING_LINE.match(line)
        if detail and matches:
            matches[-1]["strings"].append({
                "offset": int(detail.group(1), 16),
                "identifier": detail.group(2),
                "data": detail.group(3)[:MATCH_DATA_CAP],
            })
            continue
        head = _MATCH_LINE.match(line)
        if head:
            matches.append({"rule": head.group(1), "target": head.group(2),
                            "strings": []})
    return matches


def _python_scan(rules_path: Path, targets: list[Path]) -> tuple[
        list[dict[str, Any]], list[dict[str, str]]]:
    """In-process yara-python scan; per-file errors reported, not fatal."""
    try:
        import yara  # binaries.py fallback for the "yara" capability
    except ImportError as exc:
        raise Rejection(
            "neither the yara CLI nor the yara-python module is available "
            "on this host"
        ) from exc
    rules = yara.compile(filepath=str(rules_path))
    matches: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for target in targets:
        try:
            hits = rules.match(str(target), timeout=60)
        except Exception as exc:
            errors.append({"target": str(target), "error": str(exc)})
            continue
        for hit in hits:
            strings = []
            for s in hit.strings:
                if hasattr(s, "instances"):  # yara-python >= 4.3
                    for inst in s.instances:
                        strings.append({
                            "offset": inst.offset,
                            "identifier": s.identifier,
                            "data": repr(bytes(inst.matched_data))[2:-1]
                            [:MATCH_DATA_CAP],
                        })
                else:  # legacy (offset, identifier, data) tuples
                    offset, identifier, data = s
                    strings.append({"offset": offset, "identifier": identifier,
                                    "data": repr(bytes(data))[2:-1]
                                    [:MATCH_DATA_CAP]})
            matches.append({"rule": hit.rule, "target": str(target),
                            "strings": strings})
    return matches, errors


def register(app: "FastMCP", ctx: "AppContext") -> None:
    rulesets = discover_rulesets()
    names = tuple(sorted(rulesets))
    # Real enum in the model-visible schema, derived from rules/ on disk.
    ruleset_type = Literal[names] if names else str  # type: ignore[valid-type]

    description = (
        "Scan a file or directory (under the case or run dir) with a "
        "curated YARA ruleset. Available rulesets: "
        f"{', '.join(names) or '(none shipped)'}. Returns matched rule "
        "names with string identifiers, offsets and matched bytes."
    )

    @app.tool(structured_output=True, description=description)
    def yara_scan(target: str, ruleset: ruleset_type) -> dict[str, Any]:
        if ruleset not in rulesets:
            raise Rejection(
                f"unknown ruleset '{ruleset}'; available rulesets: "
                f"{', '.join(names) or '(none found in rules/)'}"
            )
        rules_path = rulesets[ruleset]
        path = ctx.pathguard.resolve_read(target, "target")
        if not path.exists():
            raise Rejection(f"target='{path}' does not exist")
        params = clean_params(target=target, ruleset=ruleset)

        use_cli = ctx.runner.has_capability_override("yara")
        if not use_cli:
            resolved = binaries.try_resolve("yara")
            use_cli = resolved is not None and resolved.argv is not None

        if use_cli:
            args: list[str | Path] = ["-s", "-w"]
            if path.is_dir():
                args.append("-r")
            args += [rules_path, path]
            run = ctx.runner.run_tool("yara", args, tool="yara_scan",
                                      params=params, ext="txt")
            if run.is_error:
                return run.payload()
            text = run.output_path.read_text(encoding="utf-8",
                                             errors="replace")
            matches = _parse_cli_output(text)
            shown, capped = cap_items(matches)
            return {
                "ruleset": ruleset,
                "target": target,
                "engine": "yara-cli",
                "total_matches": len(matches),
                "returned": len(shown),
                "matches": shown,
                "truncated": capped,
                "output_path": run.output_rel,
                "output_sha256": run.output_sha256,
                "cite_seq": run.result_seq,
                "is_error": False,
            }

        # in-process fallback: yara-python. Probe the import BEFORE the
        # ledger pair so a missing module is a rejection, not a result.
        try:
            import yara  # noqa: F401
        except ImportError as exc:
            raise Rejection(
                "neither the yara CLI nor the yara-python module is "
                "available on this host"
            ) from exc

        if path.is_dir():
            targets = [p for p in sorted(path.rglob("*"))
                       if p.is_file()][:MAX_DIR_FILES]
        else:
            targets = [path]

        def compute() -> tuple[Any, dict[str, Any], bool]:
            matches, errors = _python_scan(rules_path, targets)
            full = {"ruleset": ruleset, "target": target,
                    "engine": "yara-python", "scanned_files": len(targets),
                    "matches": matches, "errors": errors}
            shown, capped = cap_items(matches)
            response: dict[str, Any] = {
                "ruleset": ruleset,
                "target": target,
                "engine": "yara-python",
                "scanned_files": len(targets),
                "total_matches": len(matches),
                "returned": len(shown),
                "matches": shown,
            }
            if errors:
                response["scan_errors"] = errors[:10]
            return full, response, capped

        return pure_tool_call(ctx, "yara_scan", params, compute)
