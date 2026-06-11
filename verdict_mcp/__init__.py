"""verdict_mcp - the constrained side of the boundary.

FastMCP server, stdio transport, started per-run with --case (read root) and
--run (write root). Pydantic validation -> path guard -> subprocess runner ->
append-only ledger. The model's only actuators are the typed tools this server
exposes; no shell tool exists to disable.
"""

__version__ = "0.1.0"
