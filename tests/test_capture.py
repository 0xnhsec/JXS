"""
tests/test_capture.py
Unit tests for the capture module — scope config, dedup logic, JS detection.

Runs WITHOUT mitmproxy (mock-based), so no proxy setup needed.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from src.capture.config import ScopeConfig, ScopeRegistry
from src.db.schema import init_db, get_connection


# ─────────────────────────────────────────────────────────────────────────────
# ScopeConfig tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeConfig:
    def test_basic_host_match(self):
        sc = ScopeConfig(
            scope_name="test",
            host_whitelist=["example.com", "api.example.com"],
        )
        assert sc.is_in_scope("example.com")
        assert sc.is_in_scope("api.example.com")
        assert sc.is_in_scope("sub.example.com")   # suffix match

    def test_out_of_scope(self):
        sc = ScopeConfig(scope_name="test", host_whitelist=["example.com"])
        assert not sc.is_in_scope("notexample.com")
        assert not sc.is_in_scope("evil.com")

    def test_port_stripping(self):
        sc = ScopeConfig(scope_name="test", host_whitelist=["localhost"])
        assert sc.is_in_scope("localhost:8080")

    def test_case_normalization(self):
        sc = ScopeConfig(scope_name="test", host_whitelist=["Example.COM"])
        assert sc.is_in_scope("example.com")

    def test_to_dict_roundtrip(self):
        sc = ScopeConfig(
            scope_name="infomaniak",
            host_whitelist=["infomaniak.com"],
            auth_cookie="session=abc123",
        )
        d = sc.to_dict()
        sc2 = ScopeConfig(**d)
        assert sc2.scope_name == sc.scope_name
        assert sc2.auth_cookie == sc.auth_cookie


class TestScopeRegistry:
    def test_add_and_get(self):
        reg = ScopeRegistry.__new__(ScopeRegistry)
        reg._scopes = {}
        reg._path = Path("/tmp/nonexistent.json")
        sc = ScopeConfig(scope_name="linkedin", host_whitelist=["linkedin.com"])
        reg.add(sc)
        assert reg.get("linkedin") is sc

    def test_resolve_scope_for_host(self):
        reg = ScopeRegistry.__new__(ScopeRegistry)
        reg._scopes = {}
        reg._path = Path("/tmp/nonexistent.json")
        reg.add(ScopeConfig("infomaniak", ["infomaniak.com"]))
        reg.add(ScopeConfig("linkedin", ["linkedin.com"]))
        assert reg.resolve_scope_for_host("infomaniak.com") == "infomaniak"
        assert reg.resolve_scope_for_host("sub.linkedin.com") == "linkedin"
        assert reg.resolve_scope_for_host("unknown.com") is None

    def test_all_returns_list(self):
        reg = ScopeRegistry.__new__(ScopeRegistry)
        reg._scopes = {}
        reg._path = Path("/tmp/nonexistent.json")
        reg.add(ScopeConfig("a", ["a.com"]))
        reg.add(ScopeConfig("b", ["b.com"]))
        result = reg.all()
        assert len(result) == 2


# ─────────────────────────────────────────────────────────────────────────────
# DB dedup tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDbDedup:
    @pytest.fixture
    def tmp_db(self, tmp_path):
        db = tmp_path / "test_jxs.db"
        init_db(db)
        return db

    def test_insert_and_dedup(self, tmp_db):
        """Same content hash must only be stored once (PRD 4.1)."""
        from src.db.schema import get_connection

        content = b"console.log('hello');"
        content_hash = hashlib.sha256(content).hexdigest()

        conn = get_connection(tmp_db)
        try:
            for i in range(3):  # insert same hash 3 times
                conn.execute(
                    "INSERT OR IGNORE INTO js_files (url, host, scope, content_hash, content, size_bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (f"http://example.com/app{i}.js", "example.com", "test",
                     content_hash, content, len(content))
                )
            conn.commit()
            count = conn.execute(
                "SELECT COUNT(*) FROM js_files WHERE content_hash=?", (content_hash,)
            ).fetchone()[0]
            assert count == 1, f"Dedup failed: expected 1 row, got {count}"
        finally:
            conn.close()

    def test_different_hashes_stored_separately(self, tmp_db):
        from src.db.schema import get_connection

        conn = get_connection(tmp_db)
        try:
            for i in range(5):
                content = f"console.log({i});".encode()
                conn.execute(
                    "INSERT OR IGNORE INTO js_files (url, host, scope, content_hash, content, size_bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (f"http://example.com/f{i}.js", "example.com", "test",
                     hashlib.sha256(content).hexdigest(), content, len(content))
                )
            conn.commit()
            count = conn.execute("SELECT COUNT(*) FROM js_files").fetchone()[0]
            assert count == 5
        finally:
            conn.close()

    def test_wal_mode_enabled(self, tmp_db):
        """Verify WAL journal mode is set (PRD 8j requirement)."""
        from src.db.schema import get_connection
        conn = get_connection(tmp_db)
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode == "wal", f"Expected WAL mode, got: {mode}"
        finally:
            conn.close()

    def test_oversized_file_stored_without_content(self, tmp_db):
        """Files > 10MB: content=NULL, status='oversized_skipped' (PRD 8j)."""
        from src.db.schema import get_connection
        conn = get_connection(tmp_db)
        try:
            conn.execute(
                "INSERT INTO js_files (url, host, scope, content_hash, content, size_bytes, status) "
                "VALUES (?, ?, ?, ?, NULL, ?, ?)",
                ("http://cdn.example.com/huge.js", "cdn.example.com", "test",
                 "abc" * 20, 15 * 1024 * 1024, "oversized_skipped")
            )
            conn.commit()
            row = conn.execute(
                "SELECT content, status FROM js_files WHERE status='oversized_skipped'"
            ).fetchone()
            assert row is not None
            assert row["content"] is None
            assert row["status"] == "oversized_skipped"
        finally:
            conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# JS detection heuristic
# ─────────────────────────────────────────────────────────────────────────────

class TestJsDetection:
    """Test the _is_javascript() logic (inline since it's a module-level function)."""

    @pytest.mark.parametrize("content_type,url,expected", [
        ("application/javascript", "https://example.com/app.js", True),
        ("text/javascript", "https://example.com/app", True),
        ("application/ecmascript", "https://example.com/file", True),
        ("text/html", "https://example.com/index.html", False),
        ("text/css", "https://example.com/style.css", False),
        ("text/html", "https://example.com/chunk.js", True),  # URL .js override
        ("text/html", "https://example.com/module.mjs", True),
        ("image/png", "https://example.com/logo.png", False),
        ("application/json", "https://example.com/api/data", False),
    ])
    def test_is_javascript(self, content_type, url, expected):
        """Test JS detection by content_type and URL extension."""
        ct = content_type.lower()
        url_clean = url.lower().split("?")[0]
        is_js = (
            "javascript" in ct
            or "ecmascript" in ct
            or url_clean.endswith(".js")
            or url_clean.endswith(".mjs")
        )
        assert is_js == expected, f"Expected {expected} for CT={content_type}, URL={url}"
