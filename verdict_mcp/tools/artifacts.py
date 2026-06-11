"""Tool 11: read_artifact.

Spec ref: spec.md > MCP Server > Tool definitions > #11 read_artifact.
Filled in by checklist item 4.

Bounded read of an extracted/output file. Params: path (run dir or case dir
loose file), offset?, length (<=8 KB, enforced), mode (text|hex). The
verifier's content-inspection workhorse - this is what reads the smoke-case
mimikatz.exe decoy and finds 12 bytes of ASCII text.
"""

from __future__ import annotations

MAX_LENGTH = 8 * 1024


def read_artifact(path: str, offset: int = 0, length: int = MAX_LENGTH,
                  mode: str = "text") -> dict:
    raise NotImplementedError("Implemented in checklist item 4.")
