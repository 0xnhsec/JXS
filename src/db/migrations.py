"""
src/db/migrations.py
Idempotent ALTER TABLE migrations for jxs SQLite DB.

Safe to run multiple times — each migration checks column existence first
(catches OperationalError "duplicate column name" and ignores it).

Run order matters: always run all migrations in sequence from top to bottom.

Usage:
    python -m src.db.migrations          # run against default DB
    python -m src.db.migrations --db /path/to/jxs_storage.db
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.db.schema import DEFAULT_DB_PATH, get_connection

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Migration helpers
# ─────────────────────────────────────────────────────────────────────────────

def _add_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> bool:
    """
    Add a column to a table if it doesn't exist.
    Returns True if column was added, False if it already existed.
    """
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()
        logger.info("Migration OK: ALTER TABLE %s ADD COLUMN %s", table, column)
        return True
    except sqlite3.OperationalError as exc:
        if "duplicate column name" in str(exc).lower():
            logger.debug("Column %s.%s already exists, skipping", table, column)
            return False
        raise


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


# ─────────────────────────────────────────────────────────────────────────────
# Migration: 8p — target_url, review_status, review_note
# ─────────────────────────────────────────────────────────────────────────────

def migration_8p_review_fields(conn: sqlite3.Connection) -> dict:
    """
    PRD 8p / 8p-1: Add target_url, review_status, review_note to findings table.

    - target_url     : resolved resource URL (urljoin of resolved_url + match_value)
    - review_status  : workflow state (unreviewed/checked_fp/checked_benign/confirmed_bug/reported)
    - review_note    : free-text manual note per finding

    Idempotent — safe to run against DB that already has these columns.
    """
    added = {}
    added["target_url"]    = _add_column(conn, "findings", "target_url",    "TEXT")
    added["review_status"] = _add_column(conn, "findings", "review_status", "TEXT NOT NULL DEFAULT 'unreviewed'")
    added["review_note"]   = _add_column(conn, "findings", "review_note",   "TEXT")

    # Backfill target_url for existing rows where it's NULL:
    # use resolved_url as fallback (correct for dom_sink / secret_param findings)
    if added["target_url"]:
        result = conn.execute(
            "UPDATE findings SET target_url = resolved_url WHERE target_url IS NULL AND resolved_url IS NOT NULL"
        )
        conn.commit()
        logger.info("Backfilled target_url for %d existing findings", result.rowcount)

    # Backfill review_status for any NULL rows (shouldn't happen with DEFAULT, but defensive)
    conn.execute(
        "UPDATE findings SET review_status = 'unreviewed' WHERE review_status IS NULL"
    )
    conn.commit()

    return added


# ─────────────────────────────────────────────────────────────────────────────
# Migration: 8n — skipped_too_large status in schema comment
# (no ALTER needed — status is TEXT with no constraint, existing values work)
# ─────────────────────────────────────────────────────────────────────────────

def migration_8n_size_guard(conn: sqlite3.Connection) -> dict:
    """
    PRD 8n: js_files.status can now be 'skipped_too_large'.
    No ALTER TABLE needed — status column is TEXT with no CHECK constraint.
    This migration just validates the schema is correct.
    """
    row = conn.execute("PRAGMA table_info(js_files)").fetchall()
    col_names = [r["name"] for r in row]
    assert "status" in col_names, "js_files.status column missing!"
    logger.info("Migration 8n: js_files.status column OK (accepts 'skipped_too_large')")
    return {"status_col": "ok"}


# ─────────────────────────────────────────────────────────────────────────────
# Add index for review_status (speeds up UI filter queries)
# ─────────────────────────────────────────────────────────────────────────────

def migration_add_review_index(conn: sqlite3.Connection) -> dict:
    """Add index on findings.review_status for fast filter queries."""
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(review_status);"
        )
        conn.commit()
        logger.info("Migration OK: CREATE INDEX idx_findings_review")
        return {"index": "created"}
    except sqlite3.Error as exc:
        logger.warning("Index creation failed (may already exist): %s", exc)
        return {"index": "skipped"}


# ─────────────────────────────────────────────────────────────────────────────
# Migration: 8s — sample_payloads for advisories
# ─────────────────────────────────────────────────────────────────────────────

def migration_8s_advisor_payloads(conn: sqlite3.Connection) -> dict:
    """Add sample_payloads column to advisories table."""
    added = _add_column(conn, "advisories", "sample_payloads", "TEXT")
    return {"added": added}


# ─────────────────────────────────────────────────────────────────────────────
# Run all migrations
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Migration: test_only_hosts — verify_scope tag on js_files
# ─────────────────────────────────────────────────────────────────────────────

def migration_test_only_hosts(conn: sqlite3.Connection) -> dict:
    """
    Tambah kolom verify_scope ke js_files.

    verify_scope = 1 berarti file ini di-capture dari host yang ada di
    test_only_hosts scope_config — findings dari file ini perlu verifikasi
    manual apakah host benar-benar in-scope program sebelum di-report.

    Idempotent: safe dijalankan berkali-kali.
    """
    added = _add_column(
        conn, "js_files", "verify_scope",
        "INTEGER NOT NULL DEFAULT 0",  # 0 = normal, 1 = needs scope verification
    )
    # Index untuk fast UI filter "show only verify_scope findings"
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_js_files_verify_scope "
            "ON js_files(verify_scope);"
        )
        conn.commit()
        logger.info("Migration: idx_js_files_verify_scope created")
    except sqlite3.Error as exc:
        logger.warning("verify_scope index skipped: %s", exc)
    return {"verify_scope_added": added}


# ─────────────────────────────────────────────────────────────────────────────
# Migration: 8y — AI Triage Assistant (PRD section 8y)
# ─────────────────────────────────────────────────────────────────────────────

def migration_8y_ai_triage(conn: sqlite3.Connection) -> dict:
    """
    PRD 8y: ai_assessments table — LLM triage hints per finding.

    finding_id UNIQUE = idempotency: re-run only assesses findings that
    don't have a row yet. Rows are HINTS (priority/category/rationale),
    never verdicts — review_status stays human-controlled (PRD 1a/8p-1).

    Idempotent: safe dijalankan berkali-kali.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
            priority INTEGER NOT NULL,
            category TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence_quote TEXT NOT NULL,
            recommended_checks TEXT,
            confidence REAL NOT NULL,
            model TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
        """
    )
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_assessments_priority "
            "ON ai_assessments(priority);"
        )
    except sqlite3.Error as exc:
        logger.warning("ai_assessments priority index skipped: %s", exc)
    conn.commit()
    logger.info("Migration 8y: ai_assessments table OK")
    return {"table": "ok"}


MIGRATIONS: list[tuple[str, callable]] = [
    ("8n_size_guard",       migration_8n_size_guard),
    ("8p_review_fields",    migration_8p_review_fields),
    ("review_index",        migration_add_review_index),
    ("8s_advisor_payloads", migration_8s_advisor_payloads),
    ("test_only_hosts",     migration_test_only_hosts),
    ("8y_ai_triage",        migration_8y_ai_triage),
]


def run_all_migrations(db_path: str | Path = DEFAULT_DB_PATH) -> dict:
    """
    Run all migrations in order. Safe to call on every startup.

    Args:
        db_path: Path to SQLite DB.

    Returns:
        Dict of {migration_name: result} for each migration.
    """
    conn = get_connection(db_path)
    results = {}
    try:
        for name, fn in MIGRATIONS:
            logger.info("Running migration: %s", name)
            try:
                results[name] = fn(conn)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Migration %s FAILED: %s", name, exc)
                results[name] = {"error": str(exc)}
    finally:
        conn.close()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="jxs DB migrations")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Path to SQLite DB")
    args = parser.parse_args()

    results = run_all_migrations(db_path=args.db)
    print("\nMigration results:")
    for name, result in results.items():
        print(f"  {name}: {result}")
