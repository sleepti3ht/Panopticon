"""
Retrieve a list of unique vendors from the database.
CLI usage: python get_vendors.py [query]
Outputs JSON array to stdout.
"""
import sys
import json
import os
import aiosqlite
import asyncio

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "panopticon.db")


async def get_vendors(query: str = None, limit: int = 50) -> list:
    """Get list of unique vendors with optional filtering."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if query:
            async with db.execute(
                """
                SELECT DISTINCT vendor, COUNT(*) as cve_count
                FROM affected_products
                WHERE vendor LIKE ?
                GROUP BY vendor
                ORDER BY cve_count DESC
                LIMIT ?
                """,
                (f"%{query.lower()}%", limit),
            ) as cursor:
                rows = await cursor.fetchall()
        else:
            async with db.execute(
                """
                SELECT DISTINCT vendor, COUNT(*) as cve_count
                FROM affected_products
                GROUP BY vendor
                ORDER BY cve_count DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()

        return [{"vendor": row["vendor"], "cve_count": row["cve_count"]} for row in rows]


if __name__ == "__main__":
    query = sys.argv[1] if len(sys.argv) > 1 else None
    result = asyncio.run(get_vendors(query))
    print(json.dumps(result))