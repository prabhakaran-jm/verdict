"""Tool 6: registry_query.

Spec ref: spec.md > MCP Server > Tool definitions > #6 registry_query.

Run a named plugin against an extracted hive. Params: hive (path), plugin
(enum: run_keys, services, usb, network, sam_users, autoruns, recent_docs).
Both registry tiers from the Day-1 gate are mapped (runner capability
"registry" picks whichever resolved):

  primary  RECmd (.NET):    -f <hive> --kn <key-path>   (key dump to stdout)
  fallback RegRipper:       -r <hive> -p <plugin>       (report to stdout)

Plugins are hive-type-specific, so the hive type is detected first (file
name, then the path embedded in the regf header) and a plugin pointed at
the wrong hive kind is cleanly rejected. `autoruns` maps to the run-key
surface on both tiers - the broadest single invocation that exists on both
(RegRipper has no one-shot autoruns plugin).

The test seam (runner extra_argv "registry") uses the RegRipper shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from verdict_mcp import binaries
from verdict_mcp.tools.common import Rejection, clean_params, require_file

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from verdict_mcp.server import AppContext

PLUGINS = ("run_keys", "services", "usb", "network", "sam_users",
           "autoruns", "recent_docs")
PluginName = Literal["run_keys", "services", "usb", "network", "sam_users",
                     "autoruns", "recent_docs"]

#: Hive kinds each plugin can answer from.
PLUGIN_HIVES: dict[str, tuple[str, ...]] = {
    "run_keys": ("software", "ntuser"),
    "services": ("system",),
    "usb": ("system",),
    "network": ("software",),
    "sam_users": ("sam",),
    "autoruns": ("software", "ntuser"),
    "recent_docs": ("ntuser",),
}

#: RegRipper rip.pl -p <plugin> (RegRipper 3.0 names; `run` handles both
#: Software and NTUSER hives).
REGRIPPER_PLUGINS: dict[str, str] = {
    "run_keys": "run",
    "services": "services",
    "usb": "usbstor",
    "network": "networklist",
    "sam_users": "samparse",
    "autoruns": "run",
    "recent_docs": "recentdocs",
}

#: RECmd --kn key paths, per (plugin, hive kind).
RECMD_KEYS: dict[tuple[str, str], str] = {
    ("run_keys", "software"): r"Microsoft\Windows\CurrentVersion\Run",
    ("run_keys", "ntuser"): r"Software\Microsoft\Windows\CurrentVersion\Run",
    ("autoruns", "software"): r"Microsoft\Windows\CurrentVersion\Run",
    ("autoruns", "ntuser"): r"Software\Microsoft\Windows\CurrentVersion\Run",
    ("services", "system"): r"ControlSet001\Services",
    ("usb", "system"): r"ControlSet001\Enum\USBSTOR",
    ("network", "software"):
        r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
    ("sam_users", "sam"): r"SAM\Domains\Account\Users",
    ("recent_docs", "ntuser"):
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
}

_HIVE_KINDS: dict[str, str] = {
    "sam": "sam", "security": "security", "software": "software",
    "system": "system", "default": "default", "ntuser.dat": "ntuser",
    "usrclass.dat": "usrclass", "amcache.hve": "amcache",
}


def detect_hive_type(path: Path) -> str:
    """Best-effort hive kind: file name first, then the original path
    embedded at offset 0x30 of the regf header. 'unknown' never blocks."""
    name = path.name.lower()
    if name in _HIVE_KINDS:
        return _HIVE_KINDS[name]
    try:
        with open(path, "rb") as fh:
            header = fh.read(0x70)
    except OSError:
        return "unknown"
    if header[:4] != b"regf" or len(header) < 0x70:
        return "unknown"
    embedded = header[0x30:0x70].decode("utf-16-le", errors="ignore")
    embedded = embedded.split("\x00")[0].strip().lower().replace("/", "\\")
    base = embedded.rsplit("\\", 1)[-1]
    return _HIVE_KINDS.get(base, "unknown")


def register(app: "FastMCP", ctx: "AppContext") -> None:
    @app.tool(structured_output=True)
    def registry_query(hive: str, plugin: PluginName) -> dict[str, Any]:
        """Run a named forensic plugin against an extracted registry hive:
        run_keys (persistence Run/RunOnce), services, usb (USBSTOR
        history), network (known networks), sam_users (local accounts;
        SAM hive), autoruns (autostart surface), recent_docs (NTUSER
        RecentDocs). The hive file's type must match the plugin (e.g.
        sam_users needs a SAM hive). Returns the parser's text output."""
        path = require_file(ctx.pathguard.resolve_read(hive, "hive"), "hive")
        hive_type = detect_hive_type(path)
        allowed = PLUGIN_HIVES[plugin]
        if hive_type != "unknown" and hive_type not in allowed:
            raise Rejection(
                f"plugin '{plugin}' expects a {'/'.join(h.upper() for h in allowed)} "
                f"hive; '{path.name}' looks like a {hive_type.upper()} hive"
            )
        params = clean_params(hive=hive, plugin=plugin)

        if ctx.runner.has_capability_override("registry"):
            resolved = None  # test stub speaks the RegRipper shape
        else:
            resolved = binaries.try_resolve("registry")
        if resolved is not None and resolved.tier == "primary":  # RECmd
            kind = hive_type if hive_type != "unknown" else allowed[0]
            key_path = RECMD_KEYS[(plugin, kind)]
            args: list[str | Path] = ["-f", path, "--kn", key_path]
            parser = f"RECmd --kn {key_path}"
        else:  # RegRipper rip.pl (or the test stub)
            rr_plugin = REGRIPPER_PLUGINS[plugin]
            args = ["-r", path, "-p", rr_plugin]
            parser = f"RegRipper -p {rr_plugin}"

        run = ctx.runner.run_tool("registry", args, tool="registry_query",
                                  params=params, ext="txt")
        if run.is_error:
            return run.payload()
        return {
            "plugin": plugin,
            "hive": hive,
            "hive_type": hive_type,
            "parser": parser,
            "text": run.excerpt,
            "truncated": run.truncated,
            "output_path": run.output_rel,
            "output_sha256": run.output_sha256,
            "cite_seq": run.result_seq,
            "is_error": False,
        }
