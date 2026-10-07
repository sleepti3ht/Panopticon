import aiohttp
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from config import NVD_API_KEY, NVD_BASE_URL, NVD_REQUEST_DELAY
from db import init_db, insert_cve

logger = logging.getLogger(__name__)

def parse_cpe(cpe_string: str) -> dict:
    """
    Parse CPE 2.3 string.
    Format: cpe:2.3:part:vendor:product:version:update:edition:language:...
    Example: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    parts = cpe_string.split(":")
    if len(parts) < 6:
        return {"vendor": "unknown", "product": "unknown", "version": "*", "cpe_string": cpe_string}
    
    return {
        "vendor": parts[3].lower().replace("_", " "),
        "product": parts[4].lower().replace("_", " "),
        "version": parts[5] if parts[5] != "*" else None,
        "cpe_string": cpe_string
    }

def extract_cvss(cve_item: dict) -> tuple[float, str, str]:
    """Extract CVSS score. Priority: v3.1 > v3.0 > v2."""
    metrics = cve_item.get("metrics", {})
    
    # CVSS v3.1 and v3.0
    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        if version_key in metrics and metrics[version_key]:
            metric = metrics[version_key][0]
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
            return score, vector, severity
    
    # CVSS v2 (fallback)
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric = metrics["cvssMetricV2"][0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore", 0.0)
        vector = cvss_data.get("vectorString", "")
        # CVSS v2 has different thresholds
        if score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        return score, vector, severity
    
    return 0.0, "", "UNKNOWN"

def parse_nvd_cve(vuln: dict) -> dict:
    """Normalize a single CVE from NVD API response."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    
    # Description (take English)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), 
        "No description"
    )
    
    # CVSS and severity
    score, vector, severity = extract_cvss(cve)
    
    # Fix severity: if UNKNOWN but CVSS is high, determine by score
    if severity == "UNKNOWN" and score > 0:
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    
    # CPE (affected products)
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and "criteria" in match:
                    affected.append(parse_cpe(match["criteria"]))
    
    # CWE
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                cwe_ids.append(cwe_val)
    
    # References (links to advisories, patches, exploits)
    references = []
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if url:
            source = ref.get("source", "")
            tags = ref.get("tags", [])
            references.append({
                "url": url,
                "source": source,
                "tags": ",".join(tags) if tags else ""
            })
    
    return {
        "cve_id": cve_id,
        "description": description[:2000],
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": severity,
        "published_date": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "affected_products": affected,
        "cwe_ids": cwe_ids,
        "references": references
    }

async def fetch_latest_cves(limit: int = 4000):
    """
    Fetch the most recent CVEs with CPE data.
    
    Fetches CVEs from the last ~90 days (Q4 2025) and stops when reaching
    the specified limit of CVEs with valid CPE data.
    
    Args:
        limit: Maximum number of CVEs with CPE to ingest (default: 4000)
    
    Returns:
        Total number of CVEs ingested
    """
    await init_db()
    
    # Calculate date range: last 90 days from today
    # NVD API 2.0 has strict 120-day limit per request
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=90)
    
    logger.info(f"Fetching latest CVEs from {start_date.date()} to {end_date.date()}")
    logger.info(f"Target: {limit} CVEs with CPE data")
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        logger.info(f"Rate limit: {NVD_REQUEST_DELAY:.1f}s between requests.")
    
    total_ingested = 0
    total_skipped_no_cpe = 0
    
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
        "startIndex": 0
    }
    
    async with aiohttp.ClientSession() as session:
        while total_ingested < limit:
            await asyncio.sleep(NVD_REQUEST_DELAY)
            
            async with session.get(NVD_BASE_URL, params=params, headers=headers) as resp:
                if resp.status == 403:
                    logger.error("403 Forbidden. Check API key or rate limit.")
                    break
                if resp.status == 404:
                    logger.error("404 Not Found. Date range exceeds 120 days or is invalid.")
                    break
                if resp.status == 503:
                    logger.warning("503 Service Unavailable. Retrying in 30s...")
                    await asyncio.sleep(30)
                    continue
                resp.raise_for_status()
                data = await resp.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            
            logger.info(f"Fetched {len(vulnerabilities)} CVEs (offset {params['startIndex']}/{total_results})")
            
            batch_ingested = 0
            batch_skipped = 0
            
            for vuln in vulnerabilities:
                if total_ingested >= limit:
                    break
                
                cve_data = parse_nvd_cve(vuln)
                if cve_data["affected_products"]:
                    await insert_cve(cve_data)
                    batch_ingested += 1
                    total_ingested += 1
                else:
                    batch_skipped += 1
                    total_skipped_no_cpe += 1
            
            logger.info(f"Batch: {batch_ingested} ingested, {batch_skipped} skipped (no CPE). Total: {total_ingested}/{limit}")
            
            # Check if we reached the limit or end of data
            current_offset = params["startIndex"] + len(vulnerabilities)
            if current_offset >= total_results or not vulnerabilities:
                logger.info("Reached end of available data")
                break
            
            if total_ingested >= limit:
                logger.info(f"Reached target limit: {limit} CVEs")
                break
            
            params["startIndex"] = current_offset
    
    logger.info(f"Ingestion complete. Total ingested: {total_ingested}, skipped (no CPE): {total_skipped_no_cpe}")
    return total_ingested


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Fetch 2000-4000 most recent CVEs with CPE data
    # This will pull from the last ~90 days (Q4 2025)
    asyncio.run(fetch_latest_cves(limit=4000))