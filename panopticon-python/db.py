"""
Database schema and persistence layer for Panopticon CVE Map.
Uses aiosqlite for async SQLite operations.
"""
import aiosqlite
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL DEFAULT 0.0,
    cvss_vector TEXT,
    severity TEXT,
    published_date TEXT,
    last_modified TEXT
);

CREATE TABLE IF NOT EXISTS affected_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT REFERENCES cves(cve_id),
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,
    cpe_string TEXT,
    UNIQUE(cve_id, cpe_string)
);

CREATE TABLE IF NOT EXISTS cwe_mapping (
    cve_id TEXT REFERENCES cves(cve_id),
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS references_links (
    cve_id TEXT REFERENCES cves(cve_id),
    url TEXT NOT NULL,
    source TEXT,
    tags TEXT,
    UNIQUE(cve_id, url)
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_vendor ON affected_products(vendor);
CREATE INDEX IF NOT EXISTS idx_product ON affected_products(product);
CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cwe ON cwe_mapping(cwe_id);
CREATE INDEX IF NOT EXISTS idx_published ON cves(published_date);
"""


async def init_db():
    """Initialize database and run migrations."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def insert_cve(cve_data: dict):
    """Atomic CVE insertion with duplicate ignoring (INSERT OR IGNORE)."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR IGNORE INTO cves
            (cve_id, description, cvss_score, cvss_vector, severity, published_date, last_modified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_data["cve_id"],
                cve_data["description"],
                cve_data["cvss_score"],
                cve_data.get("cvss_vector"),
                cve_data["severity"],
                cve_data["published_date"],
                cve_data["last_modified"],
            ),
        )

        # Affected products (CPE)
        for cpe in cve_data.get("affected_products", []):
            await db.execute(
                """
                INSERT OR IGNORE INTO affected_products
                (cve_id, vendor, product, version, cpe_string)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cve_data["cve_id"],
                    cpe["vendor"],
                    cpe["product"],
                    cpe.get("version"),
                    cpe.get("cpe_string"),
                ),
            )

        # CWE mapping
        for cwe_id in cve_data.get("cwe_ids", []):
            await db.execute(
                """
                INSERT OR IGNORE INTO cwe_mapping (cve_id, cwe_id)
                VALUES (?, ?)
                """,
                (cve_data["cve_id"], cwe_id),
            )

        # References (advisories, patches, exploits)
        for ref in cve_data.get("references", []):
            await db.execute(
                """
                INSERT OR IGNORE INTO references_links (cve_id, url, source, tags)
                VALUES (?, ?, ?, ?)
                """,
                (cve_data["cve_id"], ref["url"], ref.get("source"), ref.get("tags")),
            )

        await db.commit()