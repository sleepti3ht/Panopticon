"""
Persistence layer for Panopticon chat reports.
CLI-driven CRUD over SQLite: save, list, load, delete (single/bulk),
pinning, tagging, and legacy-row cleanup.
"""
import sys
import sqlite3
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DB_PATH = SCRIPT_DIR / "panopticon.db"

# Guardrails for user-supplied tag metadata
MAX_TAGS_PER_REPORT = 8
MAX_TAG_LENGTH = 32


def init_db():
    """Create schema and run idempotent migrations for legacy databases."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            title TEXT NOT NULL,
            messages TEXT NOT NULL,
            model TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Idempotent column migrations for legacy databases
    cursor.execute("PRAGMA table_info(chat_reports)")
    columns = {row[1] for row in cursor.fetchall()}
    if "vendor" not in columns:
        cursor.execute("ALTER TABLE chat_reports ADD COLUMN vendor TEXT DEFAULT ''")
    if "pinned" not in columns:
        cursor.execute("ALTER TABLE chat_reports ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
    if "tags" not in columns:
        cursor.execute("ALTER TABLE chat_reports ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
    conn.commit()
    return conn


def save_report(cve_id, title, messages_json, model, vendor=""):
    """Insert a new chat report and return its row id."""
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO chat_reports (cve_id, title, messages, model, vendor) VALUES (?, ?, ?, ?, ?)",
        (cve_id, title, messages_json, model, vendor),
    )
    conn.commit()
    report_id = cursor.lastrowid
    conn.close()
    return report_id


def _safe_messages(raw):
    """Defensively parse the messages column: legacy rows written by older
    CLI argument orders may contain non-JSON payloads (e.g. the title)."""
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _safe_tags(raw):
    """Defensively parse the tags column; fall back to empty list."""
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def get_reports(cve_id="", tag=None):
    """List reports, pinned first, newest second.
    Optional filters: exact cve_id and tag containment."""
    conn = init_db()
    cursor = conn.cursor()
    query = """
        SELECT id, cve_id, title, model, created_at, vendor, pinned, tags
        FROM chat_reports
    """
    conditions = []
    params = []
    if cve_id and cve_id.strip():
        conditions.append("cve_id = ?")
        params.append(cve_id)
    if tag:
        # Tags are stored as a JSON array string; containment check is
        # acceptable at this scale (hundreds of rows, not millions).
        conditions.append("tags LIKE ?")
        params.append(f'%"{tag}"%')
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY pinned DESC, created_at DESC LIMIT 100"
    cursor.execute(query, params)
    reports = [
        {
            "id": r[0],
            "cve_id": r[1],
            "title": r[2],
            "model": r[3],
            "created_at": r[4],
            "vendor": r[5] or "",
            "pinned": bool(r[6]),
            "tags": _safe_tags(r[7]),
        }
        for r in cursor.fetchall()
    ]
    conn.close()
    return reports


def load_report(report_id):
    """Load a single report with full message history."""
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, cve_id, title, messages, model, created_at, vendor, pinned, tags
           FROM chat_reports WHERE id = ?""",
        (report_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "cve_id": row[1],
        "title": row[2],
        "messages": _safe_messages(row[3]),
        "model": row[4],
        "created_at": row[5],
        "vendor": row[6] or "",
        "pinned": bool(row[7]),
        "tags": _safe_tags(row[8]),
    }


def delete_report(report_id):
    """Delete a single chat report by id. Returns deleted row count."""
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM chat_reports WHERE id = ?", (report_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def delete_reports(report_ids):
    """Delete multiple reports in one transaction. Returns deleted count."""
    ids = [i for i in report_ids if isinstance(i, int)]
    if not ids:
        return 0
    conn = init_db()
    cursor = conn.cursor()
    placeholders = ",".join("?" * len(ids))
    cursor.execute(f"DELETE FROM chat_reports WHERE id IN ({placeholders})", ids)
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def toggle_pin(report_id):
    """Flip the pinned flag. Returns the new state or None if not found."""
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE chat_reports SET pinned = 1 - pinned WHERE id = ?", (report_id,))
    conn.commit()
    cursor.execute("SELECT pinned FROM chat_reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    return bool(row[0]) if row else None


def set_tags(report_id, tags_json):
    """Replace the tag list for a report. Validates and sanitizes input."""
    try:
        tags = json.loads(tags_json)
    except json.JSONDecodeError:
        return {"error": "Invalid tags JSON"}
    if not isinstance(tags, list):
        return {"error": "Tags must be a JSON array of strings"}
    cleaned = []
    for t in tags:
        if isinstance(t, str):
            t = t.strip()[:MAX_TAG_LENGTH]
            if t and t not in cleaned:
                cleaned.append(t)
        if len(cleaned) >= MAX_TAGS_PER_REPORT:
            break
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE chat_reports SET tags = ? WHERE id = ?", (json.dumps(cleaned), report_id))
    conn.commit()
    updated = cursor.rowcount
    conn.close()
    return {"tags": cleaned, "updated": updated}


def purge_invalid():
    """One-time cleanup: remove rows whose messages column is not a JSON array."""
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, messages FROM chat_reports")
    bad_ids = []
    for row in cursor.fetchall():
        try:
            data = json.loads(row[1])
            if not isinstance(data, list):
                bad_ids.append(row[0])
        except (json.JSONDecodeError, TypeError):
            bad_ids.append(row[0])
    if bad_ids:
        cursor.executemany("DELETE FROM chat_reports WHERE id = ?", [(i,) for i in bad_ids])
        conn.commit()
    conn.close()
    return len(bad_ids)


def _parse_id_list(raw):
    """Parse a JSON array of ids from CLI; return empty list on bad input."""
    try:
        data = json.loads(raw)
        return [int(i) for i in data] if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError, ValueError):
        return []


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[]")
        sys.exit(0)

    action = sys.argv[1]

    if action == "save" and len(sys.argv) >= 6:
        vendor = sys.argv[6] if len(sys.argv) > 6 else ""
        print(save_report(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], vendor))
    elif action == "list":
        cve_filter = sys.argv[2] if len(sys.argv) > 2 else ""
        tag_filter = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(get_reports(cve_filter, tag_filter)))
    elif action == "load" and len(sys.argv) >= 3:
        report = load_report(int(sys.argv[2]))
        print(json.dumps(report if report else {"error": "Report not found"}))
    elif action == "delete" and len(sys.argv) >= 3:
        print(delete_report(int(sys.argv[2])))
    elif action == "delete_bulk" and len(sys.argv) >= 3:
        print(json.dumps({"deleted": delete_reports(_parse_id_list(sys.argv[2]))}))
    elif action == "pin" and len(sys.argv) >= 3:
        print(json.dumps({"pinned": toggle_pin(int(sys.argv[2]))}))
    elif action == "tags" and len(sys.argv) >= 4:
        print(json.dumps(set_tags(int(sys.argv[2]), sys.argv[3])))
    elif action == "purge":
        print(purge_invalid())
    else:
        print("[]")