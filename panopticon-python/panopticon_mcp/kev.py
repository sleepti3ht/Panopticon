"""CISA KEV catalog client: lazy load, bounded cache, retry-storm guard."""

import asyncio
import sys

import httpx

from panopticon_mcp import config

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: dict[str, dict] = {}
_kev_loaded = False
# Double-checked locking: parallel tool calls must not trigger N concurrent loads
_load_lock = asyncio.Lock()


async def ensure_loaded() -> None:
    """Load KEV catalog once per process; failures mark loaded to stop retries."""
    global _kev_loaded
    if _kev_loaded:
        return
    async with _load_lock:
        if _kev_loaded:
            return
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(CISA_KEV_URL)
                if resp.status_code != 200:
                    print(
                        f"Failed to load CISA KEV: HTTP {resp.status_code}",
                        file=sys.stderr,
                    )
                    _kev_loaded = True
                    return
                data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if not cve_id or len(_kev_cache) >= config.KEV_CACHE_MAX_ENTRIES:
                    continue
                _kev_cache[cve_id] = {
                    "date_added": vuln.get("dateAdded", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "known_ransomware_usage": vuln.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                    "product": vuln.get("product", ""),
                    "vendor": vuln.get("vendorProject", ""),
                    "short_description": vuln.get("shortDescription", ""),
                }
            print(
                f"Loaded {len(_kev_cache)} entries from CISA KEV catalog",
                file=sys.stderr,
            )
        except Exception as e:  # noqa: BLE001
            print(f"CISA KEV load error: {e}", file=sys.stderr)
        _kev_loaded = True


def lookup(cve_id: str) -> dict | None:
    """Return KEV metadata for a CVE or None if not listed."""
    return _kev_cache.get(cve_id)


def cache_size() -> int:
    """Current number of cached KEV entries (for db_status tool)."""
    return len(_kev_cache)
