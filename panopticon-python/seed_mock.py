"""
Generate mock data for public repository demos.
Creates 50 fake CVE entries for testing without real NVD data.
CLI usage: python seed_mock.py
"""
import asyncio
import random
from db import init_db, insert_cve

MOCK_VENDORS = [
    ("orange systems", "orange cms"),
    ("banana software", "banana db"),
    ("lemon tech", "lemon proxy"),
    ("grape networks", "grape firewall"),
    ("melon corp", "melon os"),
]

MOCK_CWES = ["CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-416", "CWE-200"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


async def seed():
    """Populate database with 50 mock CVE entries."""
    await init_db()

    for i in range(50):
        vendor, product = random.choice(MOCK_VENDORS)
        severity = random.choice(SEVERITIES)
        cvss = {"CRITICAL": 9.5, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 3.0}[severity]
        cvss += random.uniform(-0.5, 0.5)

        cve_data = {
            "cve_id": f"CVE-2024-{90000 + i}",
            "description": f"Mock vulnerability in {product} allowing remote code execution via crafted input.",
            "cvss_score": round(cvss, 1),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": severity,
            "published_date": "2024-01-15T00:00:00.000",
            "last_modified": "2024-01-16T00:00:00.000",
            "affected_products": [
                {
                    "vendor": vendor,
                    "product": product,
                    "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}",
                    "cpe_string": f"cpe:2.3:a:{vendor.replace(' ', '_')}:{product.replace(' ', '_')}:*:*:*:*:*:*:*:*",
                }
            ],
            "cwe_ids": [random.choice(MOCK_CWES)],
        }
        await insert_cve(cve_data)

    print("Seeded 50 mock CVEs. Safe for GitHub.")


if __name__ == "__main__":
    asyncio.run(seed())