"""Binary path map + Day-1 availability check.

Spec ref: spec.md > MCP Server > Forensic Binary Matrix.
Filled in by checklist item 2 (the Day-1 go/no-go gate, run on the SIFT VM via
`python -m verdict_mcp.binaries --check`).

Matrix (primary -> fallback):
  filesystem/extract: Sleuth Kit fls/icat/mactime (native on SIFT)
  memory:             Volatility 3 (native)
  yara:               yara (native) -> yara-python
  event logs:         EvtxECmd (.NET) -> evtx_dump static binary
  MFT:                MFTECmd (.NET) -> fls -m bodyfile
  registry:           RECmd (.NET) -> RegRipper rip.pl (native)
  prefetch/amcache:   PECmd + AmcacheParser (.NET) -> pyscca / RegRipper plugin
  timeline:           fls -m + mactime (native) -> Plaso (targeted only)
"""

from __future__ import annotations

# TODO(item 2): fixed absolute paths resolved on the SIFT VM; runner.py uses
# ONLY these - never a path from model input.
BINARIES: dict[str, str] = {}


def check() -> bool:
    """Probe every matrix row (primary, then fallback); print a green/red table.

    TODO(item 2): returns True only if every capability has a working binary.
    """
    raise NotImplementedError("Implemented in checklist item 2.")


if __name__ == "__main__":
    import sys

    if "--check" in sys.argv:
        raise SystemExit(0 if check() else 1)
    print("usage: python -m verdict_mcp.binaries --check", file=sys.stderr)
    raise SystemExit(2)
