"""
MCP Server for Panopticon CVE Map.
Exposes tools for CVE database queries, live NVD fallback, CISA KEV flagging,
and CWE enrichment to feed AI mitigation generation.
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# Add project path to imports
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from fastmcp import FastMCP
import aiosqlite
import httpx
from dotenv import load_dotenv

load_dotenv(SCRIPT_DIR / ".env")

mcp = FastMCP("Panopticon CVE Server")

# Database path
DB_PATH = str(SCRIPT_DIR / "panopticon.db")
if not Path(DB_PATH).exists():
    print(f"WARNING: Database not found at {DB_PATH}", file=sys.stderr)

# NVD API configuration
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
# Rate limit: 0.6s between requests with API key, 6s without
NVD_REQUEST_DELAY = 0.6 if NVD_API_KEY else 6.0

# CISA KEV catalog URL (public JSON, ~1100 entries, updated daily)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory caches to avoid rate-limit exhaustion and redundant network calls
_nvd_cache: dict[str, tuple[float, dict]] = {}  # cve_id -> (timestamp, data)
_kev_cache: dict[str, dict] = {}  # cve_id -> kev_metadata
_kev_loaded = False
_last_nvd_request = 0.0

NVD_CACHE_TTL_SECONDS = 3600  # 1 hour


async def _rate_limit_delay():
    """Enforce minimum delay between NVD API requests to avoid 403."""
    global _last_nvd_request
    now = time.time()
    elapsed = now - _last_nvd_request
    if elapsed < NVD_REQUEST_DELAY:
        await asyncio.sleep(NVD_REQUEST_DELAY - elapsed)
    _last_nvd_request = time.time()


async def fetch_from_nvd_api(cve_id: str) -> Optional[dict]:
    """
    Fetch a single CVE from NVD API with rate limiting and caching.
    Returns normalized CVE dict or None if not found.
    """
    # Check in-memory cache first
    if cve_id in _nvd_cache:
        ts, data = _nvd_cache[cve_id]
        if time.time() - ts < NVD_CACHE_TTL_SECONDS:
            return data
    
    await _rate_limit_delay()
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                NVD_BASE_URL,
                params={"cveId": cve_id},
                headers=headers
            )
            
            if resp.status_code == 404:
                return None
            if resp.status_code == 403:
                print(f"NVD API 403: rate limit exceeded for {cve_id}", file=sys.stderr)
                return None
            if resp.status_code == 503:
                print(f"NVD API 503: service unavailable for {cve_id}", file=sys.stderr)
                return None
            if resp.status_code != 200:
                print(f"NVD API error {resp.status_code} for {cve_id}", file=sys.stderr)
                return None
            
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            
            cve_data = vulns[0].get("cve", {})
            normalized = _normalize_nvd_cve(cve_data)
            
            # Cache successful result
            _nvd_cache[cve_id] = (time.time(), normalized)
            return normalized
    
    except httpx.RequestError as e:
        print(f"NVD request error for {cve_id}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"NVD fallback unexpected error for {cve_id}: {e}", file=sys.stderr)
        return None


def _normalize_nvd_cve(cve_data: dict) -> dict:
    """
    Normalize raw NVD API response to match local DB schema.
    Extracts CVSS (v3.1 > v3.0 > v2), CWE IDs, affected products, references.
    """
    cve_id = cve_data.get("id", "")
    
    # Description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available"
    )[:2000]
    
    # CVSS extraction with priority: v3.1 > v3.0 > v2
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_vector = ""
    severity = "UNKNOWN"
    
    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        if version_key in metrics and metrics[version_key]:
            metric = metrics[version_key][0]
            cvss_info = metric.get("cvssData", {})
            cvss_score = cvss_info.get("baseScore", 0.0)
            cvss_vector = cvss_info.get("vectorString", "")
            severity = cvss_info.get("baseSeverity", "UNKNOWN").upper()
            break
    
    if severity == "UNKNOWN" and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric = metrics["cvssMetricV2"][0]
        cvss_info = metric.get("cvssData", {})
        cvss_score = cvss_info.get("baseScore", 0.0)
        cvss_vector = cvss_info.get("vectorString", "")
        severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
    
    # Infer severity from score if still UNKNOWN
    if severity == "UNKNOWN" and cvss_score > 0:
        if cvss_score >= 9.0: severity = "CRITICAL"
        elif cvss_score >= 7.0: severity = "HIGH"
        elif cvss_score >= 4.0: severity = "MEDIUM"
        else: severity = "LOW"
    
    # CWE IDs
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-") and cwe_val not in cwe_ids:
                cwe_ids.append(cwe_val)
    
    # Affected products from CPE matches
    affected_products = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and "criteria" in match:
                    parts = match["criteria"].split(":")
                    if len(parts) >= 6:
                        affected_products.append({
                            "vendor": parts[3].lower().replace("_", " "),
                            "product": parts[4].lower().replace("_", " "),
                            "version": parts[5] if parts[5] != "*" else None
                        })
    
    # References
    references = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append({
                "url": url,
                "source": ref.get("source", ""),
                "tags": ",".join(ref.get("tags", []))
            })
    
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "published_date": cve_data.get("published", ""),
        "last_modified": cve_data.get("lastModified", ""),
        "cwe_ids": cwe_ids,
        "affected_products": affected_products,
        "references": references,
        "source": "nvd_live"  # Distinguish from local DB entries
    }


async def _ensure_kev_loaded():
    """
    Lazy-load CISA Known Exploited Vulnerabilities catalog into memory.
    Called once on first KEV-related query, then cached for process lifetime.
    """
    global _kev_loaded, _kev_cache
    
    if _kev_loaded:
        return
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(CISA_KEV_URL)
            if resp.status_code != 200:
                print(f"Failed to load CISA KEV: HTTP {resp.status_code}", file=sys.stderr)
                _kev_loaded = True  # Prevent retry storms
                return
            
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    _kev_cache[cve_id] = {
                        "date_added": vuln.get("dateAdded", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "known_ransomware_usage": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "product": vuln.get("product", ""),
                        "vendor": vuln.get("vendorProject", ""),
                        "short_description": vuln.get("shortDescription", "")
                    }
            
            print(f"Loaded {len(_kev_cache)} entries from CISA KEV catalog", file=sys.stderr)
            _kev_loaded = True
    
    except Exception as e:
        print(f"CISA KEV load error: {e}", file=sys.stderr)
        _kev_loaded = True  # Prevent retry storms


def is_cve_in_kev(cve_id: str) -> Optional[dict]:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog."""
    return _kev_cache.get(cve_id)


async def _get_cve_from_db(cve_id: str) -> Optional[dict]:
    """Fetch CVE from local SQLite database. Returns None if not found."""
    if not Path(DB_PATH).exists():
        return None
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute("""
                SELECT cve_id, description, cvss_score, severity, cvss_vector, published_date
                FROM cves WHERE cve_id = ?
            """, (cve_id,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                details = dict(row)
            
            async with db.execute("SELECT cwe_id FROM cwe_mapping WHERE cve_id = ?", (cve_id,)) as cursor:
                rows = await cursor.fetchall()
                details["cwe_ids"] = [r["cwe_id"] for r in rows]
            
            async with db.execute(
                "SELECT vendor, product, version FROM affected_products WHERE cve_id = ?",
                (cve_id,)
            ) as cursor:
                rows = await cursor.fetchall()
                details["affected_products"] = [dict(r) for r in rows]
            
            async with db.execute(
                "SELECT url, source, tags FROM references_links WHERE cve_id = ?",
                (cve_id,)
            ) as cursor:
                rows = await cursor.fetchall()
                details["references"] = [dict(r) for r in rows]
            
            details["source"] = "local_db"
            return details
    
    except Exception as e:
        print(f"DB error for {cve_id}: {e}", file=sys.stderr)
        return None


async def _resolve_cve(cve_id: str) -> Optional[dict]:
    """
    Resolve CVE with fallback strategy: local DB → live NVD API.
    Returns normalized CVE dict or None if not found anywhere.
    """
    # Try local DB first (fastest path)
    local_data = await _get_cve_from_db(cve_id)
    if local_data:
        return local_data
    
    # Fallback to live NVD API (slower, rate-limited)
    print(f"CVE {cve_id} not in local DB, querying NVD API...", file=sys.stderr)
    return await fetch_from_nvd_api(cve_id)


@mcp.tool()
async def get_cve_details(cve_id: str) -> str:
    """
    Retrieve full CVE information by ID.
    Uses local database with live NVD API fallback when entry is missing.
    
    Args:
        cve_id: Vulnerability ID (e.g., CVE-2024-37320)
    
    Returns:
        JSON with description, CVSS, CWE, affected products, references, and KEV status
    """
    cve = await _resolve_cve(cve_id)
    if not cve:
        return json.dumps({"error": f"CVE {cve_id} not found in local DB or NVD API"})
    
    # Enrich with CISA KEV status
    await _ensure_kev_loaded()
    kev_info = is_cve_in_kev(cve_id)
    cve["in_cisa_kev"] = kev_info is not None
    if kev_info:
        cve["kev_details"] = kev_info
    
    return json.dumps(cve, indent=2)


@mcp.tool()
async def search_cves(vendor: str, min_cvss: float = 0.0, limit: int = 50) -> str:
    """
    Search CVEs by vendor name with CVSS score filtering.
    Only searches local database (does not use NVD fallback for search).
    
    Args:
        vendor: Vendor name (e.g., microsoft, adobe)
        min_cvss: Minimum CVSS score threshold (default 0.0)
        limit: Maximum number of results (default 50)
    
    Returns:
        JSON with matching CVE list sorted by CVSS descending
    """
    if not Path(DB_PATH).exists():
        return json.dumps({"error": "Database not found"})
    
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            
            async with db.execute("""
                SELECT DISTINCT c.cve_id, c.cvss_score, c.severity, c.published_date
                FROM cves c
                JOIN affected_products ap ON c.cve_id = ap.cve_id
                WHERE ap.vendor LIKE ? AND c.cvss_score >= ?
                ORDER BY c.cvss_score DESC
                LIMIT ?
            """, (f"%{vendor}%", min_cvss, limit)) as cursor:
                rows = await cursor.fetchall()
                results = [dict(row) for row in rows]
            
            # Annotate with KEV status
            await _ensure_kev_loaded()
            for r in results:
                r["in_cisa_kev"] = r["cve_id"] in _kev_cache
            
            return json.dumps({
                "vendor": vendor,
                "min_cvss": min_cvss,
                "count": len(results),
                "cves": results
            }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"Search failed: {e}"})


@mcp.tool()
async def is_cve_exploited(cve_id: str) -> str:
    """
    Check if a CVE is in CISA Known Exploited Vulnerabilities catalog.
    These are vulnerabilities confirmed to be actively exploited in the wild.
    Federal agencies are required to patch KEV entries within 2 weeks (BOD 22-01).
    
    Args:
        cve_id: Vulnerability ID (e.g., CVE-2021-44228)
    
    Returns:
        JSON with KEV status and metadata (date added, required action, due date, ransomware usage)
    """
    await _ensure_kev_loaded()
    
    kev_info = is_cve_in_kev(cve_id)
    if kev_info:
        return json.dumps({
            "cve_id": cve_id,
            "in_cisa_kev": True,
            "actively_exploited": True,
            **kev_info
        }, indent=2)
    
    return json.dumps({
        "cve_id": cve_id,
        "in_cisa_kev": False,
        "actively_exploited": False,
        "note": "Not in CISA KEV catalog. May still be exploitable but not confirmed in the wild."
    }, indent=2)


@mcp.tool()
async def get_cwe_hierarchy(cve_id: str) -> str:
    """
    Retrieve CWE (Common Weakness Enumeration) IDs associated with a CVE.
    CWE classifies vulnerability types at a higher abstraction level than CVE.
    Useful for pattern analysis (e.g., "this vendor has 80% memory corruption issues").
    
    Args:
        cve_id: Vulnerability ID
    
    Returns:
        JSON with CWE IDs, counts, and related CVE statistics
    """
    cve = await _resolve_cve(cve_id)
    if not cve:
        return json.dumps({"error": f"CVE {cve_id} not found"})
    
    cwe_ids = cve.get("cwe_ids", [])
    
    # For each CWE, count how many other CVEs share it (pattern analysis)
    cwe_stats = []
    if cwe_ids and Path(DB_PATH).exists():
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                for cwe_id in cwe_ids:
                    async with db.execute(
                        "SELECT COUNT(DISTINCT cve_id) as cnt FROM cwe_mapping WHERE cwe_id = ?",
                        (cwe_id,)
                    ) as cursor:
                        row = await cursor.fetchone()
                        count = row[0] if row else 0
                        cwe_stats.append({"cwe_id": cwe_id, "related_cve_count": count})
        except Exception as e:
            print(f"CWE stats error: {e}", file=sys.stderr)
    
    return json.dumps({
        "cve_id": cve_id,
        "cwe_ids": cwe_ids,
        "cwe_count": len(cwe_ids),
        "cwe_statistics": cwe_stats,
        "pattern_insight": _interpret_cwe_pattern(cwe_ids)
    }, indent=2)


def _interpret_cwe_pattern(cwe_ids: list[str]) -> str:
    """Generate human-readable insight about vulnerability type based on CWE IDs."""
    if not cwe_ids:
        return "No CWE classification available"
    
    # Common CWE patterns (top ~20 most frequent)
    pattern_map = {
        "CWE-79": "Cross-site Scripting (XSS) - input validation issue",
        "CWE-89": "SQL Injection - unsanitized database queries",
        "CWE-78": "OS Command Injection - shell command execution",
        "CWE-416": "Use After Free - memory corruption",
        "CWE-119": "Buffer Overflow - memory boundary violation",
        "CWE-20": "Improper Input Validation",
        "CWE-787": "Out-of-bounds Write",
        "CWE-125": "Out-of-bounds Read",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-862": "Missing Authorization",
        "CWE-434": "Unrestricted Upload of File",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-22": "Path Traversal",
        "CWE-287": "Improper Authentication",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-798": "Use of Hard-coded Credentials",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-863": "Incorrect Authorization",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
    }
    
    insights = []
    for cwe in cwe_ids:
        if cwe in pattern_map:
            insights.append(f"{cwe}: {pattern_map[cwe]}")
        else:
            insights.append(f"{cwe}: see CWE dictionary")
    
    return "; ".join(insights) if insights else "No recognized CWE patterns"


@mcp.tool()
async def get_cve_context_for_mitigation(cve_id: str) -> str:
    """
    Build a structured context prompt for AI mitigation generation.
    Combines local DB data with live NVD fallback and CISA KEV flagging.
    Output is formatted as a ready-to-use LLM prompt.
    
    Args:
        cve_id: Vulnerability ID
    
    Returns:
        Formatted text with all CVE metadata ready for LLM consumption
    """
    cve = await _resolve_cve(cve_id)
    if not cve:
        return f"ERROR: CVE {cve_id} not found in local database or NVD API. Cannot generate mitigation."
    
    await _ensure_kev_loaded()
    kev_info = is_cve_in_kev(cve_id)
    
    cwe_ids = cve.get("cwe_ids", [])
    products = cve.get("affected_products", [])
    product_lines = [
        f"- {p.get('vendor', 'unknown')} {p.get('product', 'unknown')} {p.get('version') or '(all versions)'}"
        for p in products
    ] or ["- No specific products listed"]
    
    # Build KEV warning block if applicable
    kev_block = ""
    if kev_info:
        kev_block = f"""
⚠️  CISA KNOWN EXPLOITED VULNERABILITY (KEV) ⚠️
This CVE is confirmed to be ACTIVELY EXPLOITED in the wild.
- Date added to KEV: {kev_info['date_added']}
- Required action: {kev_info['required_action']}
- Due date: {kev_info['due_date']}
- Known ransomware usage: {kev_info['known_ransomware_usage']}
Treat this as URGENT priority for patching.
"""
    
    context = f"""CVE ID: {cve['cve_id']}
CVSS Score: {cve['cvss_score']}
Severity: {cve['severity']}
CVSS Vector: {cve.get('cvss_vector') or 'N/A'}
Published: {cve.get('published_date', 'N/A')}
Data Source: {cve.get('source', 'unknown')}

CWE IDs: {', '.join(cwe_ids) if cwe_ids else 'N/A'}
Pattern: {_interpret_cwe_pattern(cwe_ids)}
{kev_block}
Description:
{cve['description']}

Affected Products:
{chr(10).join(product_lines)}

References:
{chr(10).join(f'- {r["url"]}' for r in cve.get('references', [])[:10]) or '- No references available'}

Generate a mitigation plan with:
1. **Risk Assessment**: Brief summary of the threat and exploitation likelihood
2. **Immediate Actions**: Steps to take right now (patching, workarounds, isolation)
3. **Long-term Recommendations**: Architectural improvements and detection strategies
4. **Specific Commands**: Exact commands or configuration changes for common platforms
5. **References**: Links to official advisories and vendor patches
"""
    
    return context


if __name__ == "__main__":
    # Start MCP server (stdio transport for Tauri integration)
    mcp.run()