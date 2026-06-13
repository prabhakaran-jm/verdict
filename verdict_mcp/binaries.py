"""Binary path map + Day-1 availability check.

Spec ref: spec.md > MCP Server > Forensic Binary Matrix.

Single source of truth for forensic binary locations. runner.py (item 3)
executes ONLY argv prefixes resolved here — never a path from model input.

Matrix (primary -> fallback):
  fs:        Sleuth Kit fls/icat/mactime (native on SIFT)
  memory:    Volatility 3 (native; vol3 | vol | vol.py | python -m volatility3)
  yara:      yara CLI (native) -> yara-python module
  evtx:      EvtxECmd (.NET) -> evtx_dump static binary
  mft:       MFTECmd (.NET) -> fls -m bodyfile
  registry:  RECmd (.NET) -> RegRipper rip.pl (native)
  execution: PECmd + AmcacheParser (.NET) -> pyscca module + RegRipper amcache plugin
  timeline:  fls -m + mactime (native) -> Plaso psort (targeted single-artifact only)

Day-1 gate usage (SIFT VM; also runs on Windows — rows just come up red):
    python -m verdict_mcp.binaries --check          # green/red table + GO/NO-GO
    python -m verdict_mcp.binaries --check --json   # machine-readable gate record

Runner API (item 3):
    resolve("evtx")                  -> Resolved (primary if available, else fallback)
    resolve("fs").component("icat")  -> argv prefix for icat specifically
EZ Tools .NET DLL location can be overridden with $VERDICT_EZTOOLS_DIR.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

PROBE_TIMEOUT_S = 20

# Extra directories searched (after PATH) for plain executables — common SIFT spots.
EXTRA_EXE_DIRS: tuple[str, ...] = (
    "/usr/local/bin",
    "/usr/bin",
    "/opt",
    "/opt/regripper",
    "/usr/share/regripper",
    "/usr/local/regripper",
    str(Path.home() / "bin"),
    str(Path.home() / ".local" / "bin"),
)

# Where EZ Tools .NET DLLs typically land on a SIFT VM (SANS Linux guide installs
# under the user's home). $VERDICT_EZTOOLS_DIR takes precedence.
_EZTOOLS_CANDIDATE_DIRS: tuple[str, ...] = (
    "~/ezTools",
    "~/eztools",
    "~/EZTools",
    "~/EZ-Tools",
    "~/Desktop/EZTools",
    "/opt/eztools",
    "/opt/ezTools",
    "/opt/EZTools",
    "/opt/ez-tools",
    "/usr/local/eztools",
    "/usr/local/share/eztools",
)


class BinaryNotFoundError(RuntimeError):
    """Neither the primary nor the fallback for a capability is available."""


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Candidate:
    """One way a component might exist on the host, plus a cheap probe."""

    label: str
    kind: str  # "exe" | "dotnet" | "pymodule"
    names: tuple[str, ...] = ()  # exe: command names tried in order
    dll: str = ""  # dotnet: DLL filename, e.g. "EvtxECmd.dll"
    module: str = ""  # pymodule: importable module name
    probe_args: tuple[str, ...] = ()
    expect: str = ""  # required substring (ci) in probe output; "" -> exit 0 suffices
    library_only: bool = False  # pymodule consumed as an import, not a CLI


@dataclass(frozen=True)
class Group:
    """One required component; candidates are alternatives (first pass wins)."""

    name: str
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True)
class Tier:
    """primary or fallback: ALL groups must pass for the tier to pass."""

    name: str  # "primary" | "fallback"
    description: str  # mirrors the spec matrix cell
    groups: tuple[Group, ...]
    lead: str = ""  # group whose argv becomes the capability argv prefix
    note: str = ""


@dataclass(frozen=True)
class Capability:
    name: str
    title: str
    primary: Tier
    fallback: Tier | None


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    detail: str  # resolved location on success; reason on failure
    argv: tuple[str, ...] | None = None  # argv prefix; None for library modules
    module: str | None = None  # python module name for library components


@dataclass(frozen=True)
class TierResult:
    ok: bool
    detail: str
    components: dict[str, ProbeResult] = field(default_factory=dict)


@dataclass(frozen=True)
class Resolved:
    """What runner.py consumes: a fixed argv prefix (or library module)."""

    capability: str
    tier: str  # "primary" | "fallback"
    description: str
    argv: tuple[str, ...] | None  # lead component argv prefix (None = library)
    module: str | None  # lead component module name (library fallbacks)
    components: dict[str, ProbeResult] = field(default_factory=dict)
    note: str = ""

    def component(self, name: str) -> ProbeResult:
        """Per-component access, e.g. resolve('fs').component('icat')."""
        return self.components[name]


# ----------------------------------------------------------------------- registry


def _exe(label: str, names: tuple[str, ...], probe_args: tuple[str, ...],
         expect: str = "") -> Candidate:
    return Candidate(label=label, kind="exe", names=names,
                     probe_args=probe_args, expect=expect)


def _dotnet(dll: str, expect: str) -> Candidate:
    return Candidate(label=dll, kind="dotnet", dll=dll, expect=expect)


def _pymodule(module: str, probe_args: tuple[str, ...] = (), expect: str = "",
              library_only: bool = False) -> Candidate:
    return Candidate(label=f"python:{module}", kind="pymodule", module=module,
                     probe_args=probe_args, expect=expect, library_only=library_only)


_FLS = _exe("fls", ("fls",), ("-V",), expect="sleuth kit")
_ICAT = _exe("icat", ("icat",), ("-V",), expect="sleuth kit")
_IFIND = _exe("ifind", ("ifind",), ("-V",), expect="sleuth kit")
_MACTIME = _exe("mactime", ("mactime",), ("-V",), expect="sleuth kit")
_RIP = _exe("rip.pl", ("rip.pl", "rip", "regripper"), (), expect="rip")

CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        name="fs",
        title="Filesystem / extract",
        primary=Tier(
            name="primary",
            description="Sleuth Kit (fls, icat, mactime)",
            groups=(Group("fls", (_FLS,)), Group("icat", (_ICAT,)),
                    Group("ifind", (_IFIND,)), Group("mactime", (_MACTIME,))),
            lead="fls",
        ),
        fallback=None,
    ),
    Capability(
        name="memory",
        title="Memory",
        primary=Tier(
            name="primary",
            description="Volatility 3",
            groups=(
                Group("volatility3", (
                    # expect "volatility" (no space): `vol -h` shows the string
                    # only via plugin names like "volatility3.plugins.windows…"
                    _exe("vol3", ("vol3",), ("-h",), expect="volatility"),
                    _exe("vol", ("vol",), ("-h",), expect="volatility"),
                    _exe("vol.py", ("vol.py",), ("-h",), expect="volatility"),
                    _pymodule("volatility3", ("-h",), expect="volatility"),
                )),
            ),
            lead="volatility3",
        ),
        fallback=None,
    ),
    Capability(
        name="yara",
        title="YARA",
        primary=Tier(
            name="primary",
            description="yara CLI",
            groups=(Group("yara", (_exe("yara", ("yara",), ("--version",)),)),),
            lead="yara",
        ),
        fallback=Tier(
            name="fallback",
            description="yara-python module",
            groups=(Group("yara-python", (_pymodule("yara", library_only=True),)),),
            lead="yara-python",
        ),
    ),
    Capability(
        name="evtx",
        title="Event logs",
        primary=Tier(
            name="primary",
            description="EvtxECmd (.NET)",
            groups=(Group("EvtxECmd", (_dotnet("EvtxECmd.dll", expect="evtxecmd"),)),),
            lead="EvtxECmd",
        ),
        fallback=Tier(
            name="fallback",
            description="evtx_dump static binary",
            groups=(Group("evtx_dump", (
                _exe("evtx_dump", ("evtx_dump",), ("--version",), expect="evtx"),)),),
            lead="evtx_dump",
        ),
    ),
    Capability(
        name="mft",
        title="MFT",
        primary=Tier(
            name="primary",
            description="MFTECmd (.NET)",
            groups=(Group("MFTECmd", (_dotnet("MFTECmd.dll", expect="mftecmd"),)),),
            lead="MFTECmd",
        ),
        fallback=Tier(
            name="fallback",
            description="fls -m bodyfile",
            groups=(Group("fls", (_FLS,)),),
            lead="fls",
            note="bodyfile filtering via fls -m",
        ),
    ),
    Capability(
        name="registry",
        title="Registry",
        primary=Tier(
            name="primary",
            description="RECmd (.NET)",
            groups=(Group("RECmd", (_dotnet("RECmd.dll", expect="recmd"),)),),
            lead="RECmd",
        ),
        fallback=Tier(
            name="fallback",
            description="RegRipper rip.pl",
            groups=(Group("RegRipper", (_RIP,)),),
            lead="RegRipper",
        ),
    ),
    Capability(
        name="execution",
        title="Prefetch / Amcache",
        primary=Tier(
            name="primary",
            description="PECmd + AmcacheParser (.NET)",
            groups=(
                Group("PECmd", (_dotnet("PECmd.dll", expect="pecmd"),)),
                Group("AmcacheParser", (_dotnet("AmcacheParser.dll", expect="amcache"),)),
            ),
            lead="PECmd",
        ),
        fallback=Tier(
            name="fallback",
            description="pyscca (prefetch) + RegRipper amcache plugin",
            groups=(
                Group("pyscca", (_pymodule("pyscca", library_only=True),)),
                Group("RegRipper", (_RIP,)),
            ),
            lead="pyscca",
            note="prefetch via pyscca import; amcache via rip.pl amcache plugin",
        ),
    ),
    Capability(
        name="timeline",
        title="Timeline",
        primary=Tier(
            name="primary",
            description="fls -m + mactime",
            groups=(Group("fls", (_FLS,)), Group("mactime", (_MACTIME,))),
            lead="fls",
        ),
        fallback=Tier(
            name="fallback",
            description="Plaso psort (targeted only)",
            groups=(Group("psort", (
                _exe("psort", ("psort.py", "psort"), ("--version",), expect="plaso"),)),),
            lead="psort",
            note="targeted single-artifact use only — never a supertimeline",
        ),
    ),
)

CAPABILITY_NAMES: tuple[str, ...] = tuple(c.name for c in CAPABILITIES)
_CAP_BY_NAME: dict[str, Capability] = {c.name: c for c in CAPABILITIES}


# ------------------------------------------------------------------------ probing

_PROBE_CACHE: dict[tuple, ProbeResult] = {}
_TIER_CACHE: dict[tuple[str, str], TierResult] = {}
_RESOLVE_CACHE: dict[str, Resolved | None] = {}


def clear_cache() -> None:
    _PROBE_CACHE.clear()
    _TIER_CACHE.clear()
    _RESOLVE_CACHE.clear()


def _which(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    for d in EXTRA_EXE_DIRS:
        p = Path(d) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def _eztools_dirs() -> list[Path]:
    dirs: list[Path] = []
    env = os.environ.get("VERDICT_EZTOOLS_DIR")
    if env:
        dirs.append(Path(env).expanduser())
    dirs.extend(Path(d).expanduser() for d in _EZTOOLS_CANDIDATE_DIRS)
    return [d for d in dirs if d.is_dir()]


def _find_dll(dll: str) -> Path | None:
    for root in _eztools_dirs():
        try:
            for hit in sorted(root.rglob(dll)):
                if hit.is_file():
                    return hit
        except OSError:
            continue
    return None


def _run_probe(argv: tuple[str, ...]) -> tuple[bool, int, str, str]:
    """Returns (ran, returncode, combined_output, failure_reason)."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, shell=False by default
            list(argv), capture_output=True, text=True, errors="replace",
            timeout=PROBE_TIMEOUT_S,
        )
    except FileNotFoundError:
        return False, -1, "", f"{argv[0]}: not found"
    except subprocess.TimeoutExpired:
        return False, -1, "", f"{argv[0]}: probe timed out after {PROBE_TIMEOUT_S}s"
    except OSError as exc:  # e.g. not executable on this platform
        return False, -1, "", f"{argv[0]}: {exc}"
    return True, proc.returncode, (proc.stdout or "") + (proc.stderr or ""), ""


def _evaluate(argv: tuple[str, ...], expect: str, where: str,
              prefix: tuple[str, ...] | None = None) -> ProbeResult:
    """Run a probe. On success the ProbeResult carries `prefix` — the
    execution argv WITHOUT probe args like -h/--version — because resolve()
    hands that argv to the runner for real invocations. Storing the full
    probe argv here once sent `evtx_dump --version -o jsonl …` to every
    real call (the binary short-circuited on --version and emitted only
    its banner)."""
    ran, rc, out, reason = _run_probe(argv)
    if not ran:
        return ProbeResult(False, reason)
    exec_argv = tuple(prefix) if prefix is not None else argv
    if expect:
        if expect.lower() in out.lower():
            return ProbeResult(True, where, argv=exec_argv)
        return ProbeResult(False, f"{where}: probe output lacked '{expect}'"
                                  f" (exit {rc})")
    if rc == 0:
        return ProbeResult(True, where, argv=exec_argv)
    return ProbeResult(False, f"{where}: probe exited {rc}")


def _probe_candidate(cand: Candidate) -> ProbeResult:
    key = (cand.label, cand.kind, cand.names, cand.dll, cand.module)
    if key in _PROBE_CACHE:
        return _PROBE_CACHE[key]
    result = _probe_candidate_uncached(cand)
    _PROBE_CACHE[key] = result
    return result


def _probe_candidate_uncached(cand: Candidate) -> ProbeResult:
    if cand.kind == "exe":
        last_fail: ProbeResult | None = None
        for name in cand.names:
            path = _which(name)
            if path is None:
                continue
            res = _evaluate((path, *cand.probe_args), cand.expect, path,
                            prefix=(path,))
            if res.ok:
                return res
            last_fail = res  # keep trying other names; remember why this failed
        if last_fail is not None:
            return last_fail
        tried = "/".join(cand.names)
        return ProbeResult(False, f"'{tried}' not found (PATH + SIFT dirs)")

    if cand.kind == "dotnet":
        stem = cand.dll.removesuffix(".dll")
        # A shell wrapper (e.g. `evtxecmd`) counts as the same tool.
        wrapper = shutil.which(stem.lower()) or shutil.which(stem)
        if wrapper:
            res = _evaluate((wrapper,), cand.expect, wrapper)
            if res.ok:
                return res
        dotnet = shutil.which("dotnet")
        dll_path = _find_dll(cand.dll)
        if dotnet is None and dll_path is None:
            return ProbeResult(False, f"dotnet runtime and {cand.dll} both missing")
        if dotnet is None:
            return ProbeResult(False, f"{cand.dll} found ({dll_path}) but no "
                                      f"'dotnet' runtime on PATH")
        if dll_path is None:
            dirs = ", ".join(_EZTOOLS_CANDIDATE_DIRS[:3]) + ", ..."
            return ProbeResult(False, f"{cand.dll} not found under EZ Tools dirs "
                                      f"({dirs}; set $VERDICT_EZTOOLS_DIR)")
        return _evaluate((dotnet, str(dll_path), *cand.probe_args), cand.expect,
                         f"dotnet {dll_path}", prefix=(dotnet, str(dll_path)))

    if cand.kind == "pymodule":
        if cand.library_only:
            ran, rc, _out, reason = _run_probe(
                (sys.executable, "-c", f"import {cand.module}"))
            if ran and rc == 0:
                return ProbeResult(True, f"python module '{cand.module}' "
                                         f"({sys.executable})", module=cand.module)
            why = reason or f"import failed (exit {rc})"
            return ProbeResult(False, f"python module '{cand.module}' not "
                                      f"importable: {why}")
        argv = (sys.executable, "-m", cand.module)
        return _evaluate((*argv, *cand.probe_args), cand.expect,
                         f"{sys.executable} -m {cand.module}", prefix=argv)

    return ProbeResult(False, f"unknown candidate kind '{cand.kind}'")


def _check_group(group: Group) -> ProbeResult:
    failures: list[str] = []
    for cand in group.candidates:
        res = _probe_candidate(cand)
        if res.ok:
            return res
        failures.append(f"{cand.label}: {res.detail}")
    if len(failures) == 1:
        return ProbeResult(False, failures[0])
    return ProbeResult(False, "no candidate available: " + "; ".join(failures))


def check_tier(capability: str, tier: Tier) -> TierResult:
    key = (capability, tier.name)
    if key in _TIER_CACHE:
        return _TIER_CACHE[key]
    components: dict[str, ProbeResult] = {}
    failures: list[str] = []
    for group in tier.groups:
        res = _check_group(group)
        components[group.name] = res
        if not res.ok:
            failures.append(f"{group.name}: {res.detail}")
    if failures:
        result = TierResult(False, "; ".join(failures), components)
    else:
        lead = tier.lead or tier.groups[0].name
        detail = components[lead].detail
        others = [g.name for g in tier.groups if g.name != lead]
        if others:
            detail += f" (+{', '.join(others)})"
        result = TierResult(True, detail, components)
    _TIER_CACHE[key] = result
    return result


# ---------------------------------------------------------------------- resolve()


def try_resolve(capability: str) -> Resolved | None:
    """Primary if available, else fallback, else None. Results are cached."""
    if capability in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[capability]
    cap = _CAP_BY_NAME.get(capability)
    if cap is None:
        raise KeyError(f"unknown capability '{capability}' "
                       f"(known: {', '.join(CAPABILITY_NAMES)})")
    resolved: Resolved | None = None
    for tier in (cap.primary, cap.fallback):
        if tier is None:
            continue
        result = check_tier(cap.name, tier)
        if not result.ok:
            continue
        lead = tier.lead or tier.groups[0].name
        lead_res = result.components[lead]
        resolved = Resolved(
            capability=cap.name,
            tier=tier.name,
            description=tier.description,
            argv=lead_res.argv,
            module=lead_res.module,
            components=result.components,
            note=tier.note,
        )
        break
    _RESOLVE_CACHE[capability] = resolved
    return resolved


def resolve(capability: str) -> Resolved:
    """The runner's entry point. Raises BinaryNotFoundError if nothing works."""
    resolved = try_resolve(capability)
    if resolved is None:
        cap = _CAP_BY_NAME[capability]
        primary = check_tier(cap.name, cap.primary)
        msg = f"capability '{capability}': primary unavailable ({primary.detail})"
        if cap.fallback is not None:
            fb = check_tier(cap.name, cap.fallback)
            msg += f"; fallback unavailable ({fb.detail})"
        else:
            msg += "; no fallback in the matrix"
        raise BinaryNotFoundError(msg)
    return resolved


def resolve_all() -> dict[str, Resolved | None]:
    return {name: try_resolve(name) for name in CAPABILITY_NAMES}


# ------------------------------------------------------------------- --check mode


def _marks() -> tuple[str, str]:
    """(pass, fail) marks; degrade for consoles that can't encode ✓/✗."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "✓✗".encode(enc)
        return "✓", "✗"
    except (UnicodeEncodeError, LookupError):
        return "OK", "XX"


def _gather() -> dict:
    rows = []
    for cap in CAPABILITIES:
        primary = check_tier(cap.name, cap.primary)
        fallback = check_tier(cap.name, cap.fallback) if cap.fallback else None
        selected = "primary" if primary.ok else (
            "fallback" if fallback is not None and fallback.ok else None)
        rows.append({"cap": cap, "primary": primary, "fallback": fallback,
                     "selected": selected})
    return {"rows": rows, "go": all(r["selected"] for r in rows)}


def _tier_json(tier: Tier | None, result: TierResult | None) -> dict | None:
    if tier is None or result is None:
        return None
    return {
        "description": tier.description,
        "ok": result.ok,
        "detail": result.detail,
        "note": tier.note or None,
        "components": {
            name: {
                "ok": res.ok,
                "detail": res.detail,
                "argv": list(res.argv) if res.argv else None,
                "module": res.module,
            }
            for name, res in result.components.items()
        },
    }


def check(json_mode: bool = False) -> bool:
    """Probe every matrix row; print a green/red table (or JSON). True == GO."""
    data = _gather()
    if json_mode:
        payload = {
            "go": data["go"],
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "platform": sys.platform,
            "python": sys.executable,
            "capabilities": {
                r["cap"].name: {
                    "title": r["cap"].title,
                    "selected": r["selected"],
                    "primary": _tier_json(r["cap"].primary, r["primary"]),
                    "fallback": _tier_json(r["cap"].fallback, r["fallback"]),
                }
                for r in data["rows"]
            },
        }
        print(json.dumps(payload, indent=2))
        return data["go"]

    ok_mark, fail_mark = _marks()

    def cell(tier: Tier | None, result: TierResult | None) -> str:
        if tier is None:
            return "[dim]— (no fallback in matrix)[/dim]"
        if result.ok:
            return f"[green]{ok_mark} {tier.description}[/green]\n" \
                   f"[dim]{result.detail}[/dim]"
        return f"[red]{fail_mark} {tier.description}[/red]\n" \
               f"[dim]{result.detail}[/dim]"

    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # dependency-light degrade; rich is a project dependency
        for r in data["rows"]:
            sel = r["selected"] or "NONE"
            print(f"{r['cap'].name:10} primary={'OK' if r['primary'].ok else 'FAIL'} "
                  f"fallback={'-' if r['fallback'] is None else ('OK' if r['fallback'].ok else 'FAIL')} "
                  f"using={sel}")
        print("GO" if data["go"] else "NO-GO")
        return data["go"]

    console = Console()
    table = Table(title="VERDICT Day-1 gate — Forensic Binary Matrix",
                  show_lines=True)
    table.add_column("Capability", style="bold", no_wrap=True)
    table.add_column("Primary")
    table.add_column("Fallback")
    table.add_column("Using", no_wrap=True)
    for r in data["rows"]:
        cap = r["cap"]
        if r["selected"] == "primary":
            using = "[green]primary[/green]"
        elif r["selected"] == "fallback":
            using = "[yellow]fallback[/yellow]"
        else:
            using = "[red bold]NONE[/red bold]"
        table.add_row(f"{cap.name}\n[dim]{cap.title}[/dim]",
                      cell(cap.primary, r["primary"]),
                      cell(cap.fallback, r["fallback"]),
                      using)
    console.print(table)

    if data["go"]:
        console.print(f"[green bold]{ok_mark} GO[/green bold] — all "
                      f"{len(data['rows'])} capabilities available "
                      f"(primary or fallback).")
    else:
        missing = [r["cap"].name for r in data["rows"] if not r["selected"]]
        console.print(f"[red bold]{fail_mark} NO-GO[/red bold] — unavailable: "
                      f"{', '.join(missing)}.")
        console.print("[dim]On a non-SIFT host (e.g. the Windows dev box) red rows "
                      "are expected — the gate is meant to pass on the SIFT VM.[/dim]")
    return data["go"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m verdict_mcp.binaries",
        description="Day-1 go/no-go gate: probe every Forensic Binary Matrix row.",
    )
    parser.add_argument("--check", action="store_true",
                        help="probe all rows and print a green/red table")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable results (implies --check)")
    args = parser.parse_args(argv)
    if not (args.check or args.json):
        parser.print_usage(sys.stderr)
        return 2
    return 0 if check(json_mode=args.json) else 1


if __name__ == "__main__":
    raise SystemExit(main())
