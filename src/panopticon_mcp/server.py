"""Panopticon MCP server: CVE intelligence tools for AI agents."""

import argparse
import sys

from mcp.server.fastmcp import FastMCP

from panopticon_mcp import config, dbreader, kev, nvd

mcp = FastMCP("Panopticon")


# Tools migrate mechanically from panopticon-python/mcp_server.py:
# replace module-level DB_PATH with config.DB_PATH, move helpers to dbreader/nvd/kev.
@mcp.tool()
async def get_cve_details(cve_id: str) -> str:
    """Retrieve full CVE info: local DB first, live NVD fallback, KEV enrichment."""
    cve = await dbreader.resolve_cve(config.DB_PATH, cve_id, nvd, kev)
    ...  # body identical to desktop version


@mcp.tool()
async def db_status() -> str:
    """Report current data mode: local+live or live-only, DB path, KEV cache size."""
    ...


def main() -> None:
    parser = argparse.ArgumentParser(prog="panopticon-mcp")
    parser.add_argument("--db-path", help="Path to panopticon.db (overrides env/auto-discovery)")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    config.DB_PATH = config.resolve_db_path(args.db_path)
    mode = "local+live" if config.DB_PATH else "live-only (NVD + CISA KEV)"
    print(f"panopticon-mcp: db={config.DB_PATH or 'not found'} mode={mode}", file=sys.stderr)

    mcp.run(transport=args.transport)
