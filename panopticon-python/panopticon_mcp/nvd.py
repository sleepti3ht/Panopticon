"""Live NVD API client with rate limiting and bounded LRU cache."""

import asyncio
import sys
import time
from collections import OrderedDict

import httpx

from panopticon_mcp import config

# Bounded LRU cache: cve_id -> (timestamp, normalized data)
_nvd_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
_last_nvd_request = 0.0
# Serializes concurrent NVD calls: without it two parallel tool calls
# both pass the elapsed-check and breach the rate limit (HTTP 403).
_fetch_lock = asyncio.Lock()


async def _rate_limit_delay() -> None:
    """Enforce minimum delay between NVD requests to avoid HTTP 403."""
    global _last_nvd_request
    now = time.time()
    elapsed = now - _last_nvd_request
    if elapsed < config.NVD_REQUEST_DELAY:
        await asyncio.sleep(config.NVD_REQUEST_DELAY - elapsed)
    _last_nvd_request = time.time()


def _cache_get(cve_id: str) -> dict | None:
    """Return fresh cached entry or evict stale one."""
    if cve_id in _nvd_cache:
        ts, data = _nvd_cache[cve_id]
        if time.time() - ts < config.NVD_CACHE_TTL_SECONDS:
            _nvd_cache.move_to_end(cve_id)
            return data
        del _nvd_cache[cve_id]
    return None


def _cache_put(cve_id: str, data: dict) -> None:
    """Insert entry and evict LRU items over capacity."""
    _nvd_cache[cve_id] = (time.time(), data)
    _nvd_cache.move_to_end(cve_id)
    while len(_nvd_cache) > config.NVD_CACHE_MAX_ENTRIES:
        _nvd_cache.popitem(last=False)


def cache_size() -> int:
    """Current number of cached NVD entries (for db_status tool)."""
    return len(_nvd_cache)


async def fetch_cve(cve_id: str) -> dict | None:
    """Fetch a single CVE from NVD API with rate limiting and caching."""
    cached = _cache_get(cve_id)
    if cached is not None:
        return cached

    async with _fetch_lock:
        # Re-check under lock: another coroutine may have populated the cache
        cached = _cache_get(cve_id)
        if cached is not None:
            return cached

        await _rate_limit_delay()

        headers = {}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    config.NVD_BASE_URL, params={"cveId": cve_id}, headers=headers
                )
                if resp.status_code == 404:
                    return None
                if resp.status_code in (403, 503):
                    print(f"NVD API {resp.status_code} for {cve_id}", file=sys.stderr)
                    return None
                if resp.status_code != 200:
                    print(f"NVD API error {resp.status_code} for {cve_id}", file=sys.stderr)
                    return None

                vulns = resp.json().get("vulnerabilities", [])
                if not vulns:
                    return None

                normalized = normalize_cve(vulns[0].get("cve", {}))
                _cache_put(cve_id, normalized)
                return normalized
        except httpx.RequestError as e:
            print(f"NVD request error for {cve_id}: {e}", file=sys.stderr)
            return None
        except Exception as e:  # noqa: BLE001
            print(f"NVD unexpected error for {cve_id}: {e}", file=sys.stderr)
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
        "No description available",
    )[:2000]

    # CVSS extraction with priority: v3.1 > v3.0 > v2
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_vector = ""
    severity = "UNKNOWN"

    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        if metrics.get(version_key):
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
        severity = (
            "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
        )

    # Infer severity from score if still UNKNOWN
    if severity == "UNKNOWN" and cvss_score > 0:
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # CWE IDs
    cwe_ids = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-") and cwe_val not in cwe_ids:
                cwe_ids.append(cwe_val)

    # Affected products from CPE matches
    affected_products = []
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and "criteria" in match:
                    parts = match["criteria"].split(":")
                    if len(parts) >= 6:
                        affected_products.append(
                            {
                                "vendor": parts[3].lower().replace("_", " "),
                                "product": parts[4].lower().replace("_", " "),
                                "version": parts[5] if parts[5] != "*" else None,
                            }
                        )

    # References
    references = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        if url:
            references.append(
                {
                    "url": url,
                    "source": ref.get("source", ""),
                    "tags": ",".join(ref.get("tags", [])),
                }
            )

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
        "source": "nvd_live",  # Distinguish from local DB entries
    }
