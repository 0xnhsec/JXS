"""
src/capture/jxs_mitm_addon.py
mitmproxy passive addon for jxs — Mode B capture.

Run with:
    mitmdump -s src/capture/jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080

Traffic flow:
    Browser (proxy 8082) → mitmproxy [this addon] → Burp (8080) → Internet

Behaviour:
  - Only captures responses with Content-Type: application/javascript or .js URL
  - Deduplicates by SHA-256 content hash (not URL — prevents re-parsing on cache-busting params)
  - Respects scope host_whitelist — out-of-scope hosts are silently ignored
  - Files > MAX_CONTENT_BYTES: saved as metadata-only with status='oversized_skipped'
  - Exceptions in response() are caught and logged — never crash the addon (PRD 8j)
  - All errors go to jxs_capture_errors.log alongside the DB

Usage:
    # With scope filtering:
    SCOPE=infomaniak mitmdump -s src/capture/jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080

    # Without scope (captures all JS, scope='default'):
    mitmdump -s src/capture/jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

# ── Path bootstrap so mitmproxy can import jxs modules ──────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from mitmproxy import http  # noqa: E402 (after sys.path fix)
from src.capture.config import ScopeRegistry  # noqa: E402
from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db  # noqa: E402

# ── Constants ────────────────────────────────────────────────────────────────
MAX_CONTENT_BYTES = 10 * 1024 * 1024  # 10 MB — PRD 8j: skip extraction, meta only
DB_PATH = os.environ.get("JXS_DB_PATH", str(DEFAULT_DB_PATH))
SCOPE_NAME = os.environ.get("SCOPE", None)          # active scope filter (env var)
CONFIG_PATH = os.environ.get("JXS_CONFIG", None)    # optional custom config path
ERROR_LOG = _PROJECT_ROOT / "logs" / "jxs_capture_errors.log"

# ── Logging setup ────────────────────────────────────────────────────────────
ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(ERROR_LOG)),
    ],
)
logger = logging.getLogger("jxs.capture")


# ── Helper ───────────────────────────────────────────────────────────────────

def _is_javascript(flow: http.HTTPFlow) -> bool:
    """Return True if the response looks like a JavaScript file."""
    content_type = flow.response.headers.get("content-type", "").lower()
    url = flow.request.pretty_url.lower().split("?")[0]
    return (
        "javascript" in content_type
        or "ecmascript" in content_type
        or url.endswith(".js")
        or url.endswith(".mjs")
    )


def _save_js_file(
    conn: sqlite3.Connection,
    url: str,
    host: str,
    scope: str,
    content: bytes | None,
    content_hash: str,
    size_bytes: int,
    status: str,
    verify_scope: int = 0,   # 1 if host is in test_only_hosts
) -> None:
    """
    Insert a JS file record into js_files.
    Uses INSERT OR IGNORE so duplicate hashes are silently skipped.
    verify_scope=1 — host was in test_only_hosts; findings need program scope check.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO js_files
            (url, host, scope, content_hash, content, size_bytes, status, verify_scope, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (url, host, scope, content_hash, content, size_bytes, status, verify_scope,
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# ── mitmproxy Addon ──────────────────────────────────────────────────────────

class JXSCapture:
    """
    mitmproxy addon: passive JS capture for jxs.

    Initialised once when mitmproxy loads the addon.
    Stateless per-request: all state lives in SQLite.
    """

    def __init__(self) -> None:
        # DB init (idempotent — safe to call every startup)
        init_db(DB_PATH)
        self._conn: sqlite3.Connection | None = None

        # Scope registry — loads scope_config.json if present
        kwargs = {"config_path": CONFIG_PATH} if CONFIG_PATH else {}
        self._registry = ScopeRegistry(**kwargs)

        self._captured = 0
        self._skipped_dup = 0
        self._skipped_scope = 0
        self._skipped_size = 0
        self._errors = 0

        logger.info(
            "JXSCapture addon started | DB: %s | Active scope filter: %s",
            DB_PATH, SCOPE_NAME or "(none — capture all in-scope hosts)",
        )

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazy connection — open once, reuse across requests."""
        if self._conn is None:
            self._conn = get_connection(DB_PATH)
        return self._conn

    # ── mitmproxy event hook ─────────────────────────────────────────────────

    def response(self, flow: http.HTTPFlow) -> None:  # noqa: C901
        """
        Called by mitmproxy for every completed response.
        Exceptions are caught at the top level — never propagate (PRD 8j).
        """
        try:
            self._handle_response(flow)
        except Exception:  # pylint: disable=broad-except
            self._errors += 1
            logger.error(
                "Unhandled exception processing %s:\n%s",
                flow.request.pretty_url,
                traceback.format_exc(),
            )

    # ── Internal processing ──────────────────────────────────────────────────

    def _handle_response(self, flow: http.HTTPFlow) -> None:
        if not _is_javascript(flow):
            return

        url = flow.request.pretty_url
        host = flow.request.host

        # ── Scope filtering ──────────────────────────────────────────────────
        resolved_scope = self._registry.resolve_scope_for_host(host)

        if SCOPE_NAME:
            # Strict mode: user specified a scope — only capture matching hosts
            scope_cfg = self._registry.get(SCOPE_NAME)
            if scope_cfg and not scope_cfg.is_in_scope(host):
                self._skipped_scope += 1
                logger.debug("Out of scope, skipping: %s", url)
                return
            scope_label = SCOPE_NAME
        else:
            # Permissive mode: capture anything, assign resolved scope or 'default'
            scope_label = resolved_scope or "default"
            scope_cfg   = self._registry.get(scope_label) if scope_label else None

        # Determine if host is test_only — findings need in-scope verification
        verify_scope_flag = 0
        if scope_cfg and scope_cfg.is_test_only_host(host):
            verify_scope_flag = 1
            logger.debug("test_only_host capture [verify_scope=1]: %s", host)

        # ── Content extraction ───────────────────────────────────────────────
        raw_content = flow.response.content  # bytes
        size_bytes = len(raw_content)

        # ── Oversized file handling (PRD 8j) ────────────────────────────────
        if size_bytes > MAX_CONTENT_BYTES:
            content_hash = hashlib.sha256(raw_content).hexdigest()
            _save_js_file(
                self.conn, url, host, scope_label,
                content=None,
                content_hash=content_hash,
                size_bytes=size_bytes,
                status="oversized_skipped",
                verify_scope=verify_scope_flag,
            )
            self._skipped_size += 1
            logger.info("OVERSIZED SKIP (%d MB) %s", size_bytes // (1024*1024), url)
            return

        # ── Normal capture ───────────────────────────────────────────────────
        content_hash = hashlib.sha256(raw_content).hexdigest()

        # Check dedup before DB write (fast path using in-memory check is fine
        # here; INSERT OR IGNORE in DB is the authoritative dedup gate)
        existing = self.conn.execute(
            "SELECT id FROM js_files WHERE content_hash = ?", (content_hash,)
        ).fetchone()
        if existing:
            self._skipped_dup += 1
            logger.debug("Duplicate (hash match), skipping: %s", url)
            return

        _save_js_file(
            self.conn, url, host, scope_label,
            content=raw_content,
            content_hash=content_hash,
            size_bytes=size_bytes,
            status="captured",
            verify_scope=verify_scope_flag,
        )
        self._captured += 1
        logger.info("[+] CAPTURED (%d KB) [scope=%s%s] %s",
                    size_bytes // 1024, scope_label,
                    " verify_scope" if verify_scope_flag else "", url)

    # ── mitmproxy lifecycle hooks ────────────────────────────────────────────

    def done(self) -> None:
        """Called by mitmproxy on shutdown — log session stats."""
        logger.info(
            "JXSCapture session ended | captured=%d dup_skip=%d "
            "scope_skip=%d size_skip=%d errors=%d",
            self._captured, self._skipped_dup,
            self._skipped_scope, self._skipped_size, self._errors,
        )
        if self._conn:
            self._conn.close()


# ── mitmproxy addon registration ─────────────────────────────────────────────
addons = [JXSCapture()]
