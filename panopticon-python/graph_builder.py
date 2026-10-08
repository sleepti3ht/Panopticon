"""
Build graph data from the database for vis-network rendering.
CLI usage: python graph_builder.py [vendor] [min_year] [depth]
Outputs JSON with nodes and edges to stdout.
"""
import sys
import json
import os
import aiosqlite
import asyncio
import networkx as nx
import httpx

# Resolve DB path relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "panopticon.db")

MAX_GRAPH_NODES = 100  # Reduced for readability
MAX_EGO_DEPTH = 2
# In-memory CISA KEV catalog cache (loaded once per process lifetime)
_kev_cache: dict[str, dict] = {}
_kev_loaded = False
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _ensure_kev_loaded() -> None:
    """Lazy-load the CISA Known Exploited Vulnerabilities catalog."""
    global _kev_cache, _kev_loaded
    if _kev_loaded:
        return
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        _kev_cache[cve_id] = {
                            "date_added": vuln.get("dateAdded", ""),
                            "due_date": vuln.get("dueDate", ""),
                            "required_action": vuln.get("requiredAction", ""),
                            "known_ransomware_usage": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        }
    except Exception as e:
        print(f"KEV load error: {e}", file=sys.stderr)
    _kev_loaded = True

async def get_cve_details(db, cve_id: str) -> dict:
    """Retrieve full CVE information from the database."""
    async with db.execute(
        """
        SELECT cve_id, description, cvss_score, severity, published_date, last_modified
        FROM cves WHERE cve_id = ?
        """,
        (cve_id,),
    ) as cursor:
        row = await cursor.fetchone()
        if not row:
            return {}
        details = dict(row)

    async with db.execute(
        "SELECT cwe_id FROM cwe_mapping WHERE cve_id = ?", (cve_id,)
    ) as cursor:
        rows = await cursor.fetchall()
        details["cwe_ids"] = [row["cwe_id"] for row in rows]

    async with db.execute(
        "SELECT url, source, tags FROM references_links WHERE cve_id = ?", (cve_id,)
    ) as cursor:
        rows = await cursor.fetchall()
        details["references"] = [dict(row) for row in rows]

    async with db.execute(
        "SELECT vendor, product, version FROM affected_products WHERE cve_id = ?",
        (cve_id,),
    ) as cursor:
        rows = await cursor.fetchall()
        details["affected_products"] = [dict(row) for row in rows]

    # Enrich with CISA KEV status
    _ensure_kev_loaded()
    kev_info = _kev_cache.get(cve_id)
    details["in_cisa_kev"] = kev_info is not None
    if kev_info:
        details["kev_details"] = kev_info

    return details


async def build_graph_for_vendor(
    vendor: str = None,
    min_year: int = None,
    depth: int = MAX_EGO_DEPTH,
    focus_cve: str = None,
) -> dict:
    """Build subgraph for vis-network rendering.
    If focus_cve is set and vendor is not, resolve the CVE's primary vendor
    so the target node is guaranteed to be present in the graph."""
    if not vendor and focus_cve:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT vendor FROM affected_products WHERE cve_id = ? ORDER BY rowid LIMIT 1",
                (focus_cve,),
            ) as cursor:
                row = await cursor.fetchone()
                vendor = row["vendor"] if row else None

    G = nx.Graph()
    cve_details_cache = {}

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if vendor:
            # Year filter via subquery
            year_filter = "AND c.published_date >= ?" if min_year else ""
            year_param = (f"{min_year}-01-01",) if min_year else ()

            query = f"""
                SELECT DISTINCT ap.cve_id
                FROM affected_products ap
                JOIN cves c ON ap.cve_id = c.cve_id
                WHERE ap.vendor = ? {year_filter}
            """
            params = (vendor.lower(),) + year_param

            async with db.execute(query, params) as cursor:
                cve_ids = [row["cve_id"] for row in await cursor.fetchall()]

            if not cve_ids:
                return {"nodes": [], "edges": []}

            for cve_id in cve_ids:
                async with db.execute(
                    """
                    SELECT cve_id, vendor, product, version
                    FROM affected_products WHERE cve_id = ?
                    """,
                    (cve_id,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    for row in rows:
                        product_node = f"{row['vendor']}:{row['product']}"
                        G.add_node(
                            product_node,
                            type="product",
                            label=row["product"],
                            group="vendor",
                        )
                        G.add_edge(product_node, cve_id, label="affects")
                        G.add_node(cve_id, type="cve", label=cve_id, group="cve")

                if cve_id not in cve_details_cache:
                    cve_details_cache[cve_id] = await get_cve_details(db, cve_id)
        else:
            year_filter = "WHERE published_date >= ?" if min_year else ""
            year_param = (f"{min_year}-01-01",) if min_year else ()

            async with db.execute(
                f"""
                SELECT cve_id, cvss_score, severity
                FROM cves {year_filter}
                ORDER BY published_date DESC
                LIMIT 100
                """,
                year_param,
            ) as cursor:
                async for row in cursor:
                    G.add_node(
                        row["cve_id"],
                        type="cve",
                        label=row["cve_id"],
                        group="cve",
                        cvss=row["cvss_score"],
                    )
                    cve_details_cache[row["cve_id"]] = await get_cve_details(
                        db, row["cve_id"]
                    )

            async with db.execute(
                f"""
                SELECT ap.cve_id, ap.vendor, ap.product
                FROM affected_products ap
                JOIN cves c ON ap.cve_id = c.cve_id
                {year_filter}
                LIMIT 200
                """,
                year_param,
            ) as cursor:
                async for row in cursor:
                    product_node = f"{row['vendor']}:{row['product']}"
                    G.add_node(
                        product_node,
                        type="product",
                        label=row["product"],
                        group="vendor",
                    )
                    G.add_edge(product_node, row["cve_id"], label="affects")

        # Truncate graph if it exceeds node limit
        if len(G.nodes) > MAX_GRAPH_NODES:
            nodes = list(G.nodes)[:MAX_GRAPH_NODES]
            G = G.subgraph(nodes)

    # Convert to vis-network format
    nodes = []
    for node_id, attrs in G.nodes(data=True):
        node_data = {
            "id": node_id,
            "label": attrs.get("label", node_id),
            "group": attrs.get("group", "default"),
            "title": (
                f"CVSS: {attrs.get('cvss', 'N/A')}"
                if attrs.get("type") == "cve"
                else f"Vendor: {attrs.get('label', '')}"
            ),
        }

        if attrs.get("type") == "cve" and node_id in cve_details_cache:
            details = cve_details_cache[node_id]
            node_data["details"] = {
                "cve_id": details.get("cve_id"),
                "description": details.get("description", ""),
                "cvss_score": details.get("cvss_score", 0.0),
                "severity": details.get("severity", "UNKNOWN"),
                "cwe_ids": details.get("cwe_ids", []),
                "published_date": details.get("published_date", ""),
                "affected_products": details.get("affected_products", []),
                "references": details.get("references", []),
                # KEV flags must survive the projection whitelist
                "in_cisa_kev": details.get("in_cisa_kev", False),
                "kev_details": details.get("kev_details"),
            }

        nodes.append(node_data)

    edges = []
    for source, target, attrs in G.edges(data=True):
        edges.append({"from": source, "to": target})

    return {"nodes": nodes, "edges": edges}


if __name__ == "__main__":
    # Empty string means "absent": positional slots must stay aligned
    vendor = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else None
    min_year = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    focus_cve = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None

    result = asyncio.run(build_graph_for_vendor(vendor, min_year, focus_cve=focus_cve))
    print(json.dumps(result))