import aiohttp
import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone
from config import NVD_API_KEY, NVD_BASE_URL, NVD_REQUEST_DELAY, INGEST_LOOKBACK_DAYS, INGEST_CHUNK_DAYS
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

async def fetch_latest_cves(limit: int = 4000, lookback_days: int = None):
    """
    Fetch the most recent CVEs with CPE data using a rolling window.
    The window ends at request time (datetime.now) and walks backwards
    in chunks to respect the NVD 120-day-per-request limit.
    """
    await init_db()

    if lookback_days is None:
        lookback_days = INGEST_LOOKBACK_DAYS

    end_date = datetime.now(timezone.utc)
    window_start = end_date - timedelta(days=lookback_days)

    logger.info(f"Rolling window: {window_start.date()} -> {end_date.date()} ({lookback_days} days)")
    logger.info(f"Target: {limit} CVEs with CPE data")

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        logger.info(f"Rate limit: {NVD_REQUEST_DELAY:.1f}s between requests.")

    total_ingested = 0
    total_skipped_no_cpe = 0

    async with aiohttp.ClientSession() as session:
        chunk_end = end_date
        while chunk_end > window_start and total_ingested < limit:
            chunk_start = max(chunk_end - timedelta(days=INGEST_CHUNK_DAYS), window_start)

            params = {
                "pubStartDate": chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate": chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "resultsPerPage": 2000,
                "startIndex": 0,
            }

            while total_ingested < limit:
                await asyncio.sleep(NVD_REQUEST_DELAY)

                async with session.get(NVD_BASE_URL, params=params, headers=headers) as resp:
                    if resp.status == 403:
                        logger.error("403 Forbidden. Check API key or rate limit.")
                        return total_ingested
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
                for vuln in vulnerabilities:
                    if total_ingested >= limit:
                        break
                    cve_data = parse_nvd_cve(vuln)
                    if cve_data["affected_products"]:
                        await insert_cve(cve_data)
                        batch_ingested += 1
                        total_ingested += 1
                    else:
                        total_skipped_no_cpe += 1

                logger.info(f"Batch: {batch_ingested} ingested. Total: {total_ingested}/{limit}")

                current_offset = params["startIndex"] + len(vulnerabilities)
                if current_offset >= total_results or not vulnerabilities:
                    break
                params["startIndex"] = current_offset

            # Move to the previous chunk
            chunk_end = chunk_start - timedelta(seconds=1)

    logger.info(f"Ingestion complete. Total ingested: {total_ingested}, skipped (no CPE): {total_skipped_no_cpe}")
    return total_ingested


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # CLI: python ingestor.py [limit] [lookback_days]
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    lookback = int(sys.argv[2]) if len(sys.argv) > 2 else None
    asyncio.run(fetch_latest_cves(limit=limit, lookback_days=lookback))