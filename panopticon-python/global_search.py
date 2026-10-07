"""
Global search across the entire CVE database.
Searches by: cve_id, description, vendor, product, cwe_id.
CLI usage: python global_search.py <query>
Outputs JSON array to stdout.
"""
import sys
import json
import os
import aiosqlite
import asyncio

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "panopticon.db")


async def global_search(query: str, limit: int = 50) -> list:
    """Global search across all relevant tables."""
    if not query or len(query) < 2:
        return []

    search_term = f"%{query.lower()}%"
    results = []

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Search by CVE ID
        async with db.execute(
            """
            SELECT cve_id, cvss_score, severity, published_date
            FROM cves
            WHERE cve_id LIKE ?
            LIMIT ?
            """,
            (search_term, limit),
        ) as cursor:
            for row in await cursor.fetchall():
                results.append({
                    "type": "CVE",
                    "id": row["cve_id"],
                    "title": row["cve_id"],
                    "subtitle": f"CVSS {row['cvss_score']} • {row['severity']}",
                    "year": row["published_date"][:4] if row["published_date"] else None,
                })

        # Search by description (only if limit not yet reached)
        if len(results) < limit:
            async with db.execute(
                """
                SELECT cve_id, description, cvss_score, severity
                FROM cves
                WHERE description LIKE ?
                LIMIT ?
                """,
                (search_term, limit - len(results)),
            ) as cursor:
                for row in await cursor.fetchall():
                    # Skip duplicates
                    if not any(r["id"] == row["cve_id"] for r in results):
                        desc = (
                            row["description"][:80] + "..."
                            if len(row["description"]) > 80
                            else row["description"]
                        )
                        results.append({
                            "type": "CVE",
                            "id": row["cve_id"],
                            "title": row["cve_id"],
                            "subtitle": desc,
                            "year": None,
                        })

        # Search by vendor
        if len(results) < limit:
            async with db.execute(
                """
                SELECT DISTINCT vendor, COUNT(*) as cve_count
                FROM affected_products
                WHERE vendor LIKE ?
                GROUP BY vendor
                ORDER BY cve_count DESC
                LIMIT ?
                """,
                (search_term, limit - len(results)),
            ) as cursor:
                for row in await cursor.fetchall():
                    results.append({
                        "type": "Vendor",
                        "id": row["vendor"],
                        "title": row["vendor"],
                        "subtitle": f"{row['cve_count']} CVEs",
                        "year": None,
                    })

        # Search by CWE
        if len(results) < limit:
            async with db.execute(
                """
                SELECT DISTINCT cwe_id
                FROM cwe_mapping
                WHERE cwe_id LIKE ?
                LIMIT ?
                """,
                (search_term, limit - len(results)),
            ) as cursor:
                for row in await cursor.fetchall():
                    results.append({
                        "type": "CWE",
                        "id": row["cwe_id"],
                        "title": row["cwe_id"],
                        "subtitle": "Weakness type",
                        "year": None,
                    })

    return results[:limit]


if __name__ == "__main__":
    query = sys.argv[1] if len(sys.argv) > 1 else ""
    result = asyncio.run(global_search(query))
    print(json.dumps(result))