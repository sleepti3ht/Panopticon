"""SQLite read layer: local CVE DB access and resolve cascade."""

import sys
from pathlib import Path

import aiosqlite

from panopticon_mcp import config, nvd


def _db_available() -> bool:
    """True when a local DB path is resolved and the file exists."""
    return config.DB_PATH is not None and Path(config.DB_PATH).is_file()


async def get_cve(cve_id: str) -> dict | None:
    """Fetch CVE from local SQLite DB. None if DB missing or CVE absent."""
    if not _db_available():
        return None
    try:
        async with aiosqlite.connect(config.DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT cve_id, description, cvss_score, severity, cvss_vector, published_date
                FROM cves WHERE cve_id = ?
                """,
                (cve_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                details = dict(row)

            async with db.execute(
                "SELECT cwe_id FROM cwe_mapping WHERE cve_id = ?", (cve_id,)
            ) as cursor:
                details["cwe_ids"] = [r["cwe_id"] for r in await cursor.fetchall()]

            async with db.execute(
                "SELECT vendor, product, version FROM affected_products WHERE cve_id = ?",
                (cve_id,),
            ) as cursor:
                details["affected_products"] = [
                    dict(r) for r in await cursor.fetchall()
                ]

            async with db.execute(
                "SELECT url, source, tags FROM references_links WHERE cve_id = ?",
                (cve_id,),
            ) as cursor:
                details["references"] = [dict(r) for r in await cursor.fetchall()]

            details["source"] = "local_db"
            return details
    except Exception as e:  # noqa: BLE001
        print(f"DB error for {cve_id}: {e}", file=sys.stderr)
        return None


async def resolve_cve(cve_id: str) -> dict | None:
    """Resolve CVE: local DB first (fast), live NVD fallback (rate-limited)."""
    local = await get_cve(cve_id)
    if local:
        return local
    if _db_available():
        print(f"CVE {cve_id} not in local DB, querying NVD API...", file=sys.stderr)
    return await nvd.fetch_cve(cve_id)


async def search_vendor(vendor: str, min_cvss: float, limit: int) -> list[dict] | None:
    """Search local DB by vendor with CVSS filter. None in live-only mode."""
    if not _db_available():
        return None
    try:
        async with aiosqlite.connect(config.DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT DISTINCT c.cve_id, c.cvss_score, c.severity, c.published_date
                FROM cves c
                JOIN affected_products ap ON c.cve_id = ap.cve_id
                WHERE ap.vendor LIKE ? AND c.cvss_score >= ?
                ORDER BY c.cvss_score DESC
                LIMIT ?
                """,
                # Vendors are stored lowercased by the ingestor: normalize the query
                (f"%{vendor.lower()}%", min_cvss, limit),
            ) as cursor:
                return [dict(row) for row in await cursor.fetchall()]
    except Exception as e:  # noqa: BLE001
        print(f"Vendor search error: {e}", file=sys.stderr)
        return None


async def cwe_stats(cwe_ids: list[str]) -> list[dict]:
    """Count related CVEs per CWE in local DB (pattern analysis)."""
    if not cwe_ids or not _db_available():
        return []
    stats = []
    try:
        async with aiosqlite.connect(config.DB_PATH) as db:
            for cwe_id in cwe_ids:
                async with db.execute(
                    "SELECT COUNT(DISTINCT cve_id) AS cnt FROM cwe_mapping WHERE cwe_id = ?",
                    (cwe_id,),
                ) as cursor:
                    row = await cursor.fetchone()
                    stats.append(
                        {"cwe_id": cwe_id, "related_cve_count": row[0] if row else 0}
                    )
    except Exception as e:  # noqa: BLE001
        print(f"CWE stats error: {e}", file=sys.stderr)
    return stats
