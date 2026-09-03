"""
tests/test_extraction.py

Validates the extraction engine against fixture JS files.

PRD 8f Done Criteria:
  - Extraction runs on 10 fixture files (5 categories)
  - False positive rate for dom_sink < 20%
  - All expected patterns detected

PRD 8k Blocker:
  - DOM_SINK_PATTERN must be validated against real JS content
  - Test counts TP/FP/FN and asserts FP rate < 20%

PRD 8z.1:
  - Proximity source-sink heuristic — findings.source_hint
    ('likely_tainted' | 'unknown' | NULL) via extract_file + temp DB

Run:
    python -m pytest tests/test_extraction.py -v
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path

# ── Path bootstrap ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from src.extraction.patterns import (
    DOM_SINK_PATTERN,
    ENDPOINT_PATTERN,
    FETCH_PATTERN,
    SOURCEMAP_PATTERN,
    SECRET_PARAM_PATTERN,
    AUTH_FUNCTION_PATTERN,
    SECRET_WHITELIST_CONTEXT,
    HIGH_ENTROPY_PATTERN,
    NAVIGATION_SINK_PATTERN,
    SOURCE_HINT_PATTERN,
    SOURCE_HINT_SINK_TYPES,
)
from src.extraction.vendor_classifier import classify
from src.xss_advisor.advisor import generate_advisory, SINK_ADVISORIES

FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# DOM_SINK_PATTERN tests (PRD 8k BLOCKER)
# ─────────────────────────────────────────────────────────────────────────────

class TestDomSinkPattern:
    """
    Critical: DOM sinks are High severity. FP rate MUST be < 20% per PRD 8f.
    """

    def test_detects_innerHTML(self):
        content = "el.innerHTML = userInput;"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "innerHTML" in str(matches), f"Expected innerHTML match, got: {matches}"

    def test_detects_outerHTML(self):
        content = "el.outerHTML = '<div>' + data + '</div>';"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "outerHTML" in str(matches)

    def test_detects_eval(self):
        content = "const result = eval(userCode);"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "eval" in str(matches)

    def test_detects_document_write(self):
        content = "document.write('<script src=\"' + src + '\"></script>');"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "document.write" in str(matches)

    def test_detects_dangerous_set_inner_html(self):
        content = "dangerouslySetInnerHTML = { __html: content };"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "dangerouslySetInnerHTML" in str(matches)

    def test_detects_insert_adjacent_html(self):
        content = "el.insertAdjacentHTML('beforeend', msg);"
        matches = DOM_SINK_PATTERN.findall(content)
        assert "insertAdjacentHTML" in str(matches)

    def test_detects_location_href(self):
        """location.href moved to NAVIGATION_SINK_PATTERN (PRD 8x revision,
        patterns.py L177-184) — must NOT be a DOM sink anymore."""
        content = "location.href = redirectUrl;"
        assert len(DOM_SINK_PATTERN.findall(content)) == 0, \
            "location.href must NOT match DOM_SINK_PATTERN (moved to navigation_sink)"
        assert "location.href" in str(NAVIGATION_SINK_PATTERN.findall(content))

    def test_detects_window_open(self):
        """window.open moved to NAVIGATION_SINK_PATTERN — must NOT be a DOM sink."""
        content = "window.open(url, '_blank');"
        assert len(DOM_SINK_PATTERN.findall(content)) == 0, \
            "window.open must NOT match DOM_SINK_PATTERN (moved to navigation_sink)"
        assert "window.open" in str(NAVIGATION_SINK_PATTERN.findall(content))

    def test_no_match_textContent(self):
        """textContent is NOT a DOM sink — should NOT match."""
        content = "el.textContent = userInput;"
        matches = DOM_SINK_PATTERN.findall(content)
        assert len(matches) == 0, f"textContent should NOT match DOM_SINK_PATTERN, got: {matches}"

    def test_no_match_innerText(self):
        """innerText is NOT a DOM sink — should NOT match."""
        content = "el.innerText = safeText;"
        matches = DOM_SINK_PATTERN.findall(content)
        assert len(matches) == 0, f"innerText should NOT match DOM_SINK_PATTERN, got: {matches}"

    def test_fixture_dom_sinks(self):
        """
        Run DOM_SINK_PATTERN against the full fixture file.
        Expected: >= 6 TP (innerHTML, outerHTML, eval, document.write,
                              dangerouslySetInnerHTML, insertAdjacentHTML)
        False positives (textContent, innerText) should NOT be found.

        PRD 8f: FP rate must be < 20% of all matches.
        """
        content = load_fixture("fixture_dom_sinks.js")
        matches = list(DOM_SINK_PATTERN.finditer(content))
        match_values = [m.group(0).strip() for m in matches]

        print(f"\nDOM_SINK_PATTERN found {len(matches)} matches:")
        for mv in match_values:
            print(f"  - {mv!r}")

        # Known true positives expected (location.href & window.open moved to
        # NAVIGATION_SINK_PATTERN — not DOM sinks anymore)
        expected_tp = [
            "innerHTML", "eval", "dangerouslySetInnerHTML",
            "document.write", "insertAdjacentHTML", "outerHTML"
        ]

        # Known false positives that must NOT appear
        expected_fp = ["textContent", "innerText"]

        detected_tp = [ep for ep in expected_tp if any(ep.lower() in mv.lower() for mv in match_values)]
        detected_fp = [fp for fp in expected_fp if any(fp.lower() in mv.lower() for mv in match_values)]

        tp_count = len(detected_tp)
        fp_count = len(detected_fp)
        total = tp_count + fp_count

        if total > 0:
            fp_rate = fp_count / total
        else:
            fp_rate = 0.0

        print(f"\nTP: {tp_count}/{len(expected_tp)} | FP: {fp_count} | FP rate: {fp_rate:.1%}")
        print(f"Detected TP: {detected_tp}")
        print(f"Detected FP: {detected_fp}")

        assert tp_count >= 6, f"Expected >= 6 TP detections, got {tp_count}: {detected_tp}"
        assert fp_count == 0, f"textContent/innerText must NOT match, got FP: {detected_fp}"
        assert fp_rate < 0.20, f"FP rate {fp_rate:.1%} exceeds 20% threshold (PRD 8f/8k)"

    def test_fixture_minified(self):
        """DOM sinks should be found in minified content too."""
        content = load_fixture("fixture_minified.js")
        matches = list(DOM_SINK_PATTERN.finditer(content))
        match_values = [m.group(0).strip() for m in matches]
        print(f"\nMinified DOM sink matches: {match_values}")
        assert any("innerHTML" in mv for mv in match_values), "innerHTML not found in minified"
        assert any("eval" in mv for mv in match_values), "eval not found in minified"


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint pattern tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEndpointPattern:
    def test_api_path(self):
        content = 'const url = "/api/v1/users";'
        matches = ENDPOINT_PATTERN.findall(content)
        assert any("/api/" in m for m in matches), f"No /api/ match in {matches}"

    def test_graphql(self):
        content = 'fetch("/graphql", { method: "POST" })'
        matches = ENDPOINT_PATTERN.findall(content) + FETCH_PATTERN.findall(content)
        assert any("graphql" in m.lower() for m in matches)

    def test_admin_endpoint(self):
        content = 'return fetch("/admin/users/" + id);'
        matches = FETCH_PATTERN.findall(content)
        assert any("admin" in m for m in matches), f"No admin match in {matches}"

    def test_no_static_asset(self):
        """Static paths like /static/images/logo.png should NOT match API endpoint pattern."""
        content = 'const img = "/static/images/logo.png";'
        matches = ENDPOINT_PATTERN.findall(content)
        assert len(matches) == 0, f"Static asset should NOT match ENDPOINT_PATTERN: {matches}"

    def test_fixture_endpoints(self):
        content = load_fixture("fixture_endpoints.js")
        endpoint_matches = ENDPOINT_PATTERN.findall(content)
        fetch_matches = FETCH_PATTERN.findall(content)
        all_matches = endpoint_matches + fetch_matches
        print(f"\nEndpoint matches: {all_matches}")
        assert len(all_matches) >= 5, f"Expected >= 5 endpoint matches, got {len(all_matches)}"


# ─────────────────────────────────────────────────────────────────────────────
# Sourcemap pattern tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSourcemapPattern:
    def test_sourcemap_comment(self):
        content = "//# sourceMappingURL=https://cdn.example.com/app.js.map"
        matches = SOURCEMAP_PATTERN.findall(content)
        assert len(matches) == 1
        assert "map" in matches[0]

    def test_sourcemap_in_minified(self):
        content = load_fixture("fixture_minified.js")
        matches = SOURCEMAP_PATTERN.findall(content)
        assert len(matches) >= 1, f"Sourcemap not found in minified fixture: {matches}"

    def test_sourcemap_in_endpoints_fixture(self):
        content = load_fixture("fixture_endpoints.js")
        matches = SOURCEMAP_PATTERN.findall(content)
        assert len(matches) >= 1, f"Sourcemap not found in endpoints fixture"


# ─────────────────────────────────────────────────────────────────────────────
# Secret / whitelist tests (empirical case from PRD 8d/8g)
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretPattern:
    def test_detects_token_param(self):
        content = "fetch('https://api.example.com/data?token=secrettoken123456789012345678')"
        matches = SECRET_PARAM_PATTERN.findall(content)
        assert len(matches) > 0, "Should detect token= in URL"

    def test_detects_apikey_param(self):
        content = "const url = 'https://api.example.com?apikey=abcdefghijklmnop123456';"
        matches = SECRET_PARAM_PATTERN.findall(content)
        assert len(matches) > 0

    def test_google_maps_whitelist(self):
        """
        Empirically validated case from PRD 8g (nasa.gov).
        Google Maps API key should be whitelisted — downgraded to Info.
        """
        content = "const src = 'https://maps.googleapis.com/maps/api/js?key=AIzaSyBNshGFexamplekey1234567890';"
        # Should match SECRET_PARAM_PATTERN...
        secret_matches = SECRET_PARAM_PATTERN.findall(content)
        # ...but whitelist context should trigger
        whitelist_match = SECRET_WHITELIST_CONTEXT.search(content)
        print(f"\nGoogle Maps test: secret_match={bool(secret_matches)}, whitelisted={bool(whitelist_match)}")
        assert whitelist_match is not None, "Google Maps URL should match SECRET_WHITELIST_CONTEXT"

    def test_auth_functions(self):
        content = load_fixture("fixture_secrets.js")
        matches = AUTH_FUNCTION_PATTERN.findall(content)
        print(f"\nAuth function matches: {matches}")
        assert len(matches) >= 2, f"Expected >= 2 auth function matches, got {len(matches)}"


# ─────────────────────────────────────────────────────────────────────────────
# Vendor classifier tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVendorClassifier:
    def test_jquery_filename(self):
        result = classify("jquery-3.7.0.min.js", "// jQuery content", 50_000)
        assert result.label == "vendor", f"Expected vendor, got {result.label}. Reasons: {result.reasons}"

    def test_custom_app_code(self):
        content = "function loginUser(username, password) { return fetch('/api/login'); }"
        result = classify("app-bundle.js", content, 2_000)
        assert result.label in ("custom", "unknown"), f"Expected custom/unknown for app code, got {result.label}"

    def test_vendor_content_signature(self):
        content = load_fixture("fixture_vendor.js")
        result = classify("some-bundle.js", content, len(content))
        print(f"\nVendor fixture classification: {result.label} ({result.confidence:.2f}) — {result.reasons}")
        assert result.label == "vendor", f"jQuery fixture should be classified as vendor, got {result.label}"

    def test_no_vendor_indicators(self):
        content = "async function fetchUserData(id) { const r = await fetch('/api/user/' + id); return r.json(); }"
        result = classify("userService.js", content, 200)
        print(f"\nCustom code classification: {result.label} ({result.confidence:.2f})")
        assert result.label in ("custom", "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# XSS Advisor tests
# ─────────────────────────────────────────────────────────────────────────────

class TestXssAdvisor:
    """
    PRD 8f: Every dom_sink match must produce 1 specific advisory text (not generic).
    """

    @pytest.mark.parametrize("sink", list(SINK_ADVISORIES.keys()))
    def test_each_sink_has_advisory(self, sink):
        """Every sink type in SINK_ADVISORIES must produce a non-empty advisory."""
        advisory = generate_advisory("dom_sink", sink)
        assert advisory, f"No advisory for sink type: {sink}"
        assert len(advisory) > 50, f"Advisory too short for {sink}: {advisory!r}"

    def test_innerHTML_advisory_is_specific(self):
        advisory = generate_advisory("dom_sink", "innerHTML")
        assert "innerHTML" in advisory.lower() or "xss" in advisory.lower()
        assert "sanitize" in advisory.lower() or "dompurify" in advisory.lower()

    def test_eval_advisory_is_specific(self):
        advisory = generate_advisory("dom_sink", "eval")
        assert "eval" in advisory.lower()
        assert "breakpoint" in advisory.lower() or "devtools" in advisory.lower()

    def test_location_href_advisory_mentions_redirect(self):
        advisory = generate_advisory("dom_sink", "location.href")
        assert "redirect" in advisory.lower() or "javascript:" in advisory.lower()

    def test_unknown_sink_gets_generic_fallback(self):
        advisory = generate_advisory("dom_sink", "unknown_sink_xyz")
        assert len(advisory) > 30, "Unknown sink should get generic fallback advisory"

    @pytest.mark.parametrize("sink", list(SINK_ADVISORIES.keys()))
    def test_no_payload_in_advisory(self, sink):
        """PRD 8c: advisories must not contain auto-executing payloads.
        Mentioning a PoC example for MANUAL testing is allowed.
        Auto-fire means the tool itself executes the payload — not that it
        can't describe what to test with.
        """
        advisory = generate_advisory("dom_sink", sink)
        # Advisory MUST NOT contain auto-executing inline script elements
        # that would execute in the UI rendering context:
        assert "<script>alert" not in advisory, (
            f"Advisory for '{sink}' contains auto-executing script payload — "
            f"this violates PRD 8c (no auto-fire). Advisory text: {advisory[:100]!r}"
        )
        # PoC examples like <img src=x onerror=alert(1)> in manual testing
        # instructions are ACCEPTABLE per PRD 8c (manual steps, not auto-fire)


# ─────────────────────────────────────────────────────────────────────────────
# Overall FP rate summary (PRD 8f compliance check)
# ─────────────────────────────────────────────────────────────────────────────

class TestOverallFPRate:
    """
    Run all patterns against all fixtures and calculate overall FP rate.
    PRD 8f: FP rate < 20% for dom_sink findings.
    """

    FIXTURE_FILES = [
        "fixture_dom_sinks.js",
        "fixture_endpoints.js",
        "fixture_secrets.js",
        "fixture_vendor.js",
        "fixture_minified.js",
    ]

    # Known non-sink strings that DOM_SINK_PATTERN must NOT match
    KNOWN_FP_STRINGS = [
        "textContent",
        "innerText",
        "createTextNode",
        "createElementNS",
    ]

    def test_dom_sink_fp_rate_across_all_fixtures(self):
        all_matches = []
        for fname in self.FIXTURE_FILES:
            content = load_fixture(fname)
            for m in DOM_SINK_PATTERN.finditer(content):
                all_matches.append((fname, m.group(0).strip()))

        fp_count = sum(
            1 for _, mv in all_matches
            if any(fp.lower() in mv.lower() for fp in self.KNOWN_FP_STRINGS)
        )
        tp_count = len(all_matches) - fp_count
        total = len(all_matches)

        print(f"\n=== DOM_SINK_PATTERN FP Rate Report ===")
        print(f"Total matches across {len(self.FIXTURE_FILES)} fixtures: {total}")
        print(f"True Positives: {tp_count}")
        print(f"False Positives: {fp_count}")
        if total > 0:
            fp_rate = fp_count / total
            print(f"FP Rate: {fp_rate:.1%}")
            assert fp_rate < 0.20, (
                f"DOM_SINK_PATTERN FP rate {fp_rate:.1%} exceeds 20% threshold (PRD 8f/8k). "
                f"FP matches: {[(f, mv) for f, mv in all_matches if any(fp.lower() in mv.lower() for fp in self.KNOWN_FP_STRINGS)]}"
            )
        else:
            print("WARNING: No DOM sink matches found across all fixtures!")


# ─────────────────────────────────────────────────────────────────────────────
# PRD 8z.1 — Proximity source-sink heuristic (source_hint) + migration 8z
# ─────────────────────────────────────────────────────────────────────────────

class TestSourceHintExtraction:
    """
    PRD 8z.1: finding sink dalam window ±300 char dari source attacker-
    controlled → source_hint='likely_tainted'; sink tanpa source → 'unknown';
    tipe non-sink → NULL. Windowed co-occurrence, BUKAN taint analysis.
    """

    @pytest.fixture
    def tmp_db(self, tmp_path):
        """DB temp fresh — init_db sudah jalanin semua migrasi (idempoten)."""
        db = tmp_path / "test_8z1.db"
        from src.db.schema import init_db
        init_db(db)
        return db

    def _extract_content(self, tmp_db, content: str, url: str = "http://example.com/app.js"):
        """Insert 1 js_files row + run extract_file → return findings rows."""
        from src.db.schema import get_connection
        from src.extraction.extractor import extract_file

        content_bytes = content.encode("utf-8")
        conn = get_connection(tmp_db)
        try:
            cur = conn.execute(
                "INSERT INTO js_files (url, host, scope, content_hash, content, size_bytes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    url,
                    "example.com",
                    "test",
                    hashlib.sha256(content_bytes + uuid.uuid4().bytes).hexdigest(),
                    content_bytes,
                    len(content_bytes),
                ),
            )
            js_file_id = cur.lastrowid
            extract_file(
                js_file_id=js_file_id,
                url=url,
                content_bytes=content_bytes,
                size_bytes=len(content_bytes),
                conn=conn,
            )
            rows = conn.execute(
                "SELECT id, type, match_value, source_hint, snippet "
                "FROM findings WHERE js_file_id = ?",
                (js_file_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def test_source_hint_pattern_compiles_and_matches(self):
        """Sanity: SOURCE_HINT_PATTERN match sumber attacker-controlled."""
        assert SOURCE_HINT_PATTERN.search("new URLSearchParams(location.search)")
        assert SOURCE_HINT_PATTERN.search("document.referrer")
        assert SOURCE_HINT_PATTERN.search("window.name")
        assert SOURCE_HINT_PATTERN.search("event.data /* postMessage */")
        assert not SOURCE_HINT_PATTERN.search("var greeting = 'hello world';")

    def test_sink_types_constant(self):
        """Berlaku HANYA untuk 4 tipe sink (PRD 8z.1 aturan poin 1)."""
        assert SOURCE_HINT_SINK_TYPES == frozenset(
            {"dom_sink", "new_function", "attr_sink", "navigation_sink"}
        )

    def test_dom_sink_near_source_is_likely_tainted(self, tmp_db):
        """8z.6 DoD poin 1: sink + source dalam ±300 char → 'likely_tainted'."""
        content = (
            "function handleSearch() {\n"
            "  const params = new URLSearchParams(location.search);\n"
            "  const q = params.get('q');\n"
            "  el.innerHTML = q;\n"
            "}\n"
        )
        findings = self._extract_content(tmp_db, content)
        dom_sinks = [f for f in findings if f["type"] == "dom_sink"]
        assert dom_sinks, f"expected dom_sink finding, got: {[(f['type'], f['match_value']) for f in findings]}"
        assert all(f["source_hint"] == "likely_tainted" for f in dom_sinks)

    def test_dom_sink_far_from_source_is_unknown(self, tmp_db):
        """8z.6 DoD poin 1: sink tanpa source di sekitar → 'unknown'."""
        content = (
            "var config = { version: '1.2.3' };\n"
            'el.innerHTML = "static content";\n'
            "var another = { debug: false };\n"
        )
        findings = self._extract_content(tmp_db, content)
        dom_sinks = [f for f in findings if f["type"] == "dom_sink"]
        assert dom_sinks, f"expected dom_sink finding, got: {[(f['type'], f['match_value']) for f in findings]}"
        assert all(f["source_hint"] == "unknown" for f in dom_sinks)

    def test_navigation_sink_near_source_is_likely_tainted(self, tmp_db):
        """navigation_sink termasuk 4 tipe yang dapat tag (PRD 8z.1)."""
        content = (
            "const target = new URLSearchParams(location.search).get('next');\n"
            "location.href = target;\n"
        )
        findings = self._extract_content(tmp_db, content)
        nav_sinks = [f for f in findings if f["type"] == "navigation_sink"]
        assert nav_sinks, f"expected navigation_sink finding, got: {[(f['type'], f['match_value']) for f in findings]}"
        assert all(f["source_hint"] == "likely_tainted" for f in nav_sinks)

    def test_endpoint_finding_source_hint_null(self, tmp_db):
        """8z.6 DoD poin 1: endpoint (non-sink) → source_hint NULL."""
        content = 'fetch("/api/v1/users", { method: "POST" });\n'
        findings = self._extract_content(tmp_db, content)
        assert findings, "expected endpoint/endpoint_fetch findings"
        assert all(
            f["type"] in ("endpoint", "endpoint_fetch") for f in findings
        ), f"unexpected types: {[f['type'] for f in findings]}"
        assert all(f["source_hint"] is None for f in findings)


class TestMigration8zSourceHint:
    """PRD 8z.1 — migration 8z_source_hint idempoten (fresh DDL + ALTER path)."""

    def test_migration_idempotent_on_fresh_db(self, tmp_path):
        """init_db (DDL baru sudah punya kolom) → run_all_migrations 2x tanpa error."""
        from src.db.migrations import run_all_migrations
        from src.db.schema import get_connection, init_db

        db = tmp_path / "test_mig_8z.db"
        init_db(db)   # DDL fresh sudah memuat source_hint → PRAGMA check skip ALTER
        results1 = run_all_migrations(db)
        results2 = run_all_migrations(db)  # run kedua — harus idempoten
        assert results1["8z_source_hint"] == {"source_hint": "ok"}
        assert results2["8z_source_hint"] == {"source_hint": "ok"}

        conn = get_connection(db)
        try:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
            assert "source_hint" in cols
            idx = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_findings_source_hint'"
            ).fetchone()
            assert idx is not None, "idx_findings_source_hint harus dibuat"
        finally:
            conn.close()

    def test_migration_alters_legacy_db(self, tmp_path):
        """DB legacy (DDL lama TANPA kolom) → ALTER menambahkan source_hint."""
        from src.db.migrations import run_all_migrations
        from src.db.schema import get_connection

        db = tmp_path / "test_mig_8z_legacy.db"
        conn = get_connection(db)
        try:
            # Simulasi DB lama: findings tanpa kolom source_hint
            conn.execute(
                """
                CREATE TABLE findings (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    js_file_id   INTEGER NOT NULL,
                    type         TEXT    NOT NULL,
                    match_value  TEXT    NOT NULL,
                    severity     TEXT    NOT NULL DEFAULT 'info',
                    line_number  INTEGER,
                    snippet      TEXT,
                    is_whitelisted INTEGER NOT NULL DEFAULT 0,
                    resolved_url TEXT,
                    target_url   TEXT,
                    review_status TEXT NOT NULL DEFAULT 'unreviewed',
                    review_note  TEXT,
                    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

        results = run_all_migrations(db)
        assert results["8z_source_hint"] == {"source_hint": "ok"}

        conn = get_connection(db)
        try:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
            assert "source_hint" in cols
            # values sesuai PRD 8z.1 — 'likely_tainted' | 'unknown' | NULL
            conn.execute(
                "INSERT INTO findings (js_file_id, type, match_value, source_hint) "
                "VALUES (1, 'dom_sink', 'innerHTML', 'likely_tainted')"
            )
            conn.commit()
            row = conn.execute(
                "SELECT source_hint FROM findings WHERE type='dom_sink'"
            ).fetchone()
            assert row["source_hint"] == "likely_tainted"
        finally:
            conn.close()
