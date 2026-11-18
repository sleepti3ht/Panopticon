"""Panopticon MCP server: CVE intelligence tools for AI agents."""

import argparse
import json
import sys

from mcp.server.fastmcp import FastMCP

from panopticon_mcp import config, context, dbreader, kev, nvd

mcp = FastMCP("Panopticon")


@mcp.tool()
async def get_cve_details(cve_id: str) -> str:
    """Retrieve full CVE info: local DB first, live NVD fallback, KEV enrichment."""
    cve = await dbreader.resolve_cve(cve_id)
    if not cve:
        return json.dumps({"error": f"CVE {cve_id} not found in local DB or NVD API"})

    await kev.ensure_loaded()
    kev_info = kev.lookup(cve_id)
    cve["in_cisa_kev"] = kev_info is not None
    if kev_info:
        cve["kev_details"] = kev_info
    return json.dumps(cve, indent=2)


@mcp.tool()
async def search_cves(vendor: str, min_cvss: float = 0.0, limit: int = 50) -> str:
    """Search CVEs by vendor with CVSS filter (local DB only, no NVD fallback)."""
    rows = await dbreader.search_vendor(vendor, min_cvss, limit)
    if rows is None:
        return json.dumps({"error": "Local database not available (live-only mode)"})

    await kev.ensure_loaded()
    for r in rows:
        r["in_cisa_kev"] = kev.lookup(r["cve_id"]) is not None
    return json.dumps(
        {"vendor": vendor, "min_cvss": min_cvss, "count": len(rows), "cves": rows},
        indent=2,
    )


@mcp.tool()
async def is_cve_exploited(cve_id: str) -> str:
    """Check CISA KEV status: confirmed active exploitation in the wild."""
    await kev.ensure_loaded()
    kev_info = kev.lookup(cve_id)
    if kev_info:
        return json.dumps(
            {
                "cve_id": cve_id,
                "in_cisa_kev": True,
                "actively_exploited": True,
                **kev_info,
            },
            indent=2,
        )
    return json.dumps(
        {
            "cve_id": cve_id,
            "in_cisa_kev": False,
            "actively_exploited": False,
            "note": "Not in CISA KEV catalog. May still be exploitable but not confirmed in the wild.",
        },
        indent=2,
    )


@mcp.tool()
async def get_cwe_hierarchy(cve_id: str) -> str:
    """CWE IDs for a CVE plus related-CVE counts for pattern analysis."""
    cve = await dbreader.resolve_cve(cve_id)
    if not cve:
        return json.dumps({"error": f"CVE {cve_id} not found"})

    cwe_ids = cve.get("cwe_ids", [])
    return json.dumps(
        {
            "cve_id": cve_id,
            "cwe_ids": cwe_ids,
            "cwe_count": len(cwe_ids),
            "cwe_statistics": await dbreader.cwe_stats(cwe_ids),
            "pattern_insight": context.interpret_cwe_pattern(cwe_ids),
        },
        indent=2,
    )


@mcp.tool()
async def get_cve_context_for_mitigation(cve_id: str) -> str:
    """Structured LLM-ready context for mitigation plan generation."""
    cve = await dbreader.resolve_cve(cve_id)
    if not cve:
        return (
            f"ERROR: CVE {cve_id} not found in local database or NVD API. "
            "Cannot generate mitigation."
        )

    await kev.ensure_loaded()
    return context.build_mitigation_context(cve, kev.lookup(cve_id))


@mcp.tool()
async def db_status() -> str:
    """Report data mode, DB path and cache sizes (agent self-awareness)."""
    return json.dumps(
        {
            "mode": "local+live" if config.DB_PATH else "live-only",
            "db_path": str(config.DB_PATH) if config.DB_PATH else None,
            "nvd_cache_entries": nvd.cache_size(),
            "kev_cache_entries": kev.cache_size(),
            "nvd_api_key_set": config.NVD_API_KEY is not None,
        },
        indent=2,
    )


def main() -> None:
    """CLI entry point: resolve config, announce mode, run transport."""
    parser = argparse.ArgumentParser(prog="panopticon-mcp-server")
    parser.add_argument(
        "--db-path", help="Path to panopticon.db (overrides env/auto-discovery)"
    )
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    config.DB_PATH = config.resolve_db_path(args.db_path)
    mode = "local+live" if config.DB_PATH else "live-only (NVD + CISA KEV)"
    print(
        f"panopticon-mcp-server: db={config.DB_PATH or 'not found'} mode={mode}",
        file=sys.stderr,
    )

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
