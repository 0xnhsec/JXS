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

Run:
    cd /home/ardxcryz/jxs
    python -m pytest tests/test_extraction.py -v
"""

from __future__ import annotations

import sys
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
        assert fp_rate < 0.20, f"FP rate {fp_rate:.1%} exceeds 20% threshold (PRD 8f)"

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
