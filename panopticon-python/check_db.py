import sqlite3

conn = sqlite3.connect('panopticon.db')
cursor = conn.cursor()

# 1. List all tables
tables = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]
print(f"Tables found: {tables}")

# 2. Total CVEs count
total_cves = cursor.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
print(f"Total CVEs: {total_cves}")

# 3. Check for duplicates
dupes = cursor.execute("SELECT COUNT(*) - COUNT(DISTINCT cve_id) FROM cves").fetchone()[0]
print(f"Duplicate CVE IDs: {dupes}")

# 4. Severity distribution (fixed: use alias instead of reserved word)
print("\nSeverity Distribution:")
for severity, cnt in cursor.execute("SELECT severity, COUNT(*) AS cnt FROM cves GROUP BY severity ORDER BY cnt DESC"):
    print(f"  {severity}: {cnt}")

# 5. Top Vendors (fixed: same issue)
print("\nTop Vendors:")
for vendor, cnt in cursor.execute("SELECT vendor, COUNT(*) AS cnt FROM affected_products GROUP BY vendor ORDER BY cnt DESC LIMIT 8"):
    print(f"  {vendor}: {cnt}")

conn.close()