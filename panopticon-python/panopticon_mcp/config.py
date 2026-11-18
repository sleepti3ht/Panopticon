"""
Configuration for panopticon-mcp-server.
Loads environment variables, defines constants, resolves DB path via cascade.
"""

import os
from pathlib import Path

# NVD API configuration
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting: 0.6s with API key, 6s without
NVD_REQUEST_DELAY = 0.6 if NVD_API_KEY else 6.0

# Cache configuration (bounded to prevent memory leaks in long-running MCP server)
NVD_CACHE_TTL_SECONDS = 3600  # 1 hour
NVD_CACHE_MAX_ENTRIES = 50
KEV_CACHE_MAX_ENTRIES = 2000  # CISA KEV ~1.7k entries, buffer for growth

# Database path resolution
DB_FILENAME = "panopticon.db"


def resolve_db_path(cli_value: str | None = None) -> Path | None:
    """
    Resolve DB path with priority cascade:
    1. CLI flag (--db-path)
    2. Env variable (PANOPTICON_DB_PATH)
    3. Auto-discovery (~/.panopticon/panopticon.db, ./panopticon.db)
    4. None (live-only mode: NVD + KEV, no local DB)

    Returns Path or None for live-only mode.
    """
    if cli_value:
        return Path(cli_value).expanduser().resolve()

    env_value = os.getenv("PANOPTICON_DB_PATH")
    if env_value:
        return Path(env_value).expanduser().resolve()

    for candidate in (
        Path.home() / ".panopticon" / DB_FILENAME,
        Path.cwd() / DB_FILENAME,
    ):
        if candidate.is_file():
            return candidate.resolve()

    return None


# Module-level DB_PATH (set by server.main() after parsing CLI args)
DB_PATH: Path | None = None
