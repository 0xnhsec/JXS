"""
src/db/schema.py
SQLite schema initialization for jxs.

Tables:
  - js_files   : raw captured JS files (deduped by content_hash)
  - findings   : extracted patterns per JS file (endpoints, sinks, secrets, etc.)
  - tech_stack : tech stack detections per JS file
  - advisories : XSS/sink advisory texts derived from findings

WAL mode is enabled on every connection for concurrent mitmproxy + extraction writes.
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "jxs_storage.db"

# ─────────────────────────────────────────────────────────
# DDL Statements
# ─────────────────────────────────────────────────────────

_DDL_JS_FILES = """
CREATE TABLE IF NOT EXISTS js_files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL,
    host          TEXT    NOT NULL,
    scope         TEXT    NOT NULL DEFAULT 'default',
    content_hash  TEXT    NOT NULL UNIQUE,  -- sha256 hex, dedup key
    content       BLOB,                      -- NULL when oversized_skipped
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    is_beautified INTEGER NOT NULL DEFAULT 0, -- 0/1 bool
    status        TEXT    NOT NULL DEFAULT 'captured',
    -- status values: 'captured' | 'extracted' | 'oversized_skipped' | 'skipped_too_large' | 'error'
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_DDL_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    js_file_id   INTEGER NOT NULL REFERENCES js_files(id) ON DELETE CASCADE,
    type         TEXT    NOT NULL,
    -- type values: 'endpoint' | 'sourcemap' | 'dom_sink' | 'secret_param'
    --              | 'high_entropy' | 'secret_mantra' | 'auth_function'
    --              | 'tech_stack' | 'oversized_skipped'
    match_value  TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'info',
    -- severity values: 'high' | 'medium' | 'low' | 'info'
    line_number  INTEGER,          -- NULL if not applicable (minified)
    snippet      TEXT,             -- surrounding code context (~3 lines)
    is_whitelisted INTEGER NOT NULL DEFAULT 0,  -- 1 = downgraded to Info
    resolved_url TEXT,             -- URL of the JS file (source) — for Burp history lookup
    target_url   TEXT,             -- PRD 8p: urljoin(resolved_url, match_value) for endpoint/sourcemap
    review_status TEXT NOT NULL DEFAULT 'unreviewed',
    -- review_status values: 'unreviewed' | 'checked_fp' | 'checked_benign' | 'confirmed_bug' | 'reported'
    review_note  TEXT,             -- PRD 8p-1: free-text manual note
    source_hint  TEXT,             -- PRD 8z.1: proximity source-sink tag
    -- source_hint values: 'likely_tainted' | 'unknown' | NULL (non-sink types)
    -- 'likely_tainted' = source attacker-controlled terdeteksi dalam window
    -- ±300 char di sekitar sink (windowed co-occurrence, BUKAN taint analysis)
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_DDL_TECH_STACK = """
CREATE TABLE IF NOT EXISTS tech_stack (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    js_file_id   INTEGER NOT NULL REFERENCES js_files(id) ON DELETE CASCADE,
    tech_name    TEXT    NOT NULL,
    confidence   REAL    NOT NULL DEFAULT 0.0,  -- 0.0 – 1.0
    evidence     TEXT,           -- the matched string/pattern that triggered detection
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_DDL_ADVISORIES = """
CREATE TABLE IF NOT EXISTS advisories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    sink_type       TEXT    NOT NULL,
    advisory_text   TEXT    NOT NULL,
    context_snippet TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_DDL_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_js_files_scope ON js_files(scope);",
    "CREATE INDEX IF NOT EXISTS idx_js_files_host  ON js_files(host);",
    "CREATE INDEX IF NOT EXISTS idx_js_files_hash  ON js_files(content_hash);",
    "CREATE INDEX IF NOT EXISTS idx_findings_file  ON findings(js_file_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(type);",
    "CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(review_status);",
    "CREATE INDEX IF NOT EXISTS idx_tech_file       ON tech_stack(js_file_id);",
    "CREATE INDEX IF NOT EXISTS idx_advisories_fid  ON advisories(finding_id);",
]

# ─────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────

def get_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Open (and optionally create) a jxs SQLite database.

    - Enables WAL journal mode for concurrent mitmproxy + extraction writes (PRD 8j).
    - Sets row_factory to sqlite3.Row for dict-like access.

    Args:
        db_path: Filesystem path to the .db file.

    Returns:
        An open sqlite3.Connection. Caller is responsible for closing it.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # WAL mode: concurrent readers + one writer without locking (PRD 8j)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    return conn


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """
    Create all tables and indexes if they do not exist.
    Also runs all pending migrations (idempotent).
    Safe to call multiple times (idempotent via IF NOT EXISTS).

    Args:
        db_path: Path to the SQLite database file.
    """
    db_path = Path(db_path)
    logger.info("Initializing jxs DB at %s", db_path)

    conn = get_connection(db_path)
    try:
        cur = conn.cursor()
        for ddl in [_DDL_JS_FILES, _DDL_FINDINGS, _DDL_TECH_STACK, _DDL_ADVISORIES]:
            cur.executescript(ddl)
        for idx in _DDL_INDEXES:
            cur.execute(idx)
        conn.commit()
        logger.info("DB schema initialized OK")
    except sqlite3.Error as exc:
        logger.error("DB init failed: %s", exc)
        raise
    finally:
        conn.close()

    # Run migrations after schema init (idempotent — safe on fresh + existing DBs)
    try:
        from src.db.migrations import run_all_migrations
        run_all_migrations(db_path)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Migrations skipped (non-fatal): %s", exc)


def get_db_stats(db_path: str | Path = DEFAULT_DB_PATH) -> dict:
    """Return row counts for each table — useful for CLI status display."""
    conn = get_connection(db_path)
    try:
        stats = {}
        for table in ("js_files", "findings", "tech_stack", "advisories"):
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0]
        return stats
    finally:
        conn.close()
