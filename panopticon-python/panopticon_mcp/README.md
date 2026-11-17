# panopticon-mcp

MCP server for CVE intelligence: local SQLite cache (optional), live NVD fallback,
CISA KEV flags, CWE pattern analysis.

## Install

    pip install panopticon-mcp

## Run

    panopticon-mcp                      # live-only mode (NVD + CISA KEV)
    panopticon-mcp --db-path PATH       # local+live mode with Panopticon SQLite DB
    set PANOPTICON_DB_PATH=PATH         # same via env var

Tools: get_cve_details, search_cves, is_cve_exploited, get_cwe_hierarchy,
get_cve_context_for_mitigation, db_status.
