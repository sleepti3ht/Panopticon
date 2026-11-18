"""LLM context builder and CWE pattern interpretation."""

PATTERN_MAP = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection - shell command execution",
    "CWE-79": "Cross-site Scripting (XSS) - input validation issue",
    "CWE-89": "SQL Injection - unsanitized database queries",
    "CWE-119": "Buffer Overflow - memory boundary violation",
    "CWE-125": "Out-of-bounds Read",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free - memory corruption",
    "CWE-434": "Unrestricted Upload of File",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection (JNDI/LDAP injection class)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def interpret_cwe_pattern(cwe_ids: list[str]) -> str:
    """Human-readable insight per CWE ID."""
    if not cwe_ids:
        return "No CWE classification available"
    insights = [
        f"{cwe}: {PATTERN_MAP.get(cwe, 'see CWE dictionary')}" for cwe in cwe_ids
    ]
    return "; ".join(insights)


def build_mitigation_context(cve: dict, kev_info: dict | None) -> str:
    """Format CVE metadata as a ready-to-use mitigation prompt."""
    cwe_ids = cve.get("cwe_ids", [])
    products = cve.get("affected_products", [])
    product_lines = [
        f"- {p.get('vendor', 'unknown')} {p.get('product', 'unknown')} {p.get('version') or '(all versions)'}"
        for p in products
    ] or ["- No specific products listed"]

    kev_block = ""
    if kev_info:
        kev_block = (
            "\nCISA KNOWN EXPLOITED VULNERABILITY (KEV)\n"
            "This CVE is confirmed to be ACTIVELY EXPLOITED in the wild.\n"
            f"- Date added to KEV: {kev_info.get('date_added', '')}\n"
            f"- Required action: {kev_info.get('required_action', '')}\n"
            f"- Due date: {kev_info.get('due_date', '')}\n"
            f"- Known ransomware usage: {kev_info.get('known_ransomware_usage', 'Unknown')}\n"
            "Treat this as URGENT priority for patching.\n"
        )

    ref_lines = (
        "\n".join(f"- {r.get('url', '')}" for r in cve.get("references", [])[:10])
        or "- No references available"
    )

    return f"""CVE ID: {cve.get("cve_id", "")}
CVSS Score: {cve.get("cvss_score", 0.0)}
Severity: {cve.get("severity", "UNKNOWN")}
CVSS Vector: {cve.get("cvss_vector") or "N/A"}
Published: {cve.get("published_date", "N/A")}
Data Source: {cve.get("source", "unknown")}

CWE IDs: {", ".join(cwe_ids) if cwe_ids else "N/A"}
Pattern: {interpret_cwe_pattern(cwe_ids)}
{kev_block}
Description:
{cve.get("description", "")}

Affected Products:
{chr(10).join(product_lines)}

References:
{ref_lines}

Generate a mitigation plan with:
1. **Risk Assessment**: Brief summary of the threat and exploitation likelihood
2. **Immediate Actions**: Steps to take right now (patching, workarounds, isolation)
3. **Long-term Recommendations**: Architectural improvements and detection strategies
4. **Specific Commands**: Exact commands or configuration changes for common platforms
5. **References**: Links to official advisories and vendor patches
"""
