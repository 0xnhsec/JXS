"""
src/extraction/vendor_classifier.py
Heuristic classifier to distinguish vendor/UI bundles from custom application logic.

Why this matters:
  - Severity rules differ: "sensitive keyword in custom logic" = Medium vs. vendor = Low/ignore
  - Vendor bundles (React, jQuery, lodash) have many false-positive DOM sinks and
    high-entropy strings that are not security issues.
  - Reduces noise in the findings table so Bangkit can focus on real findings.

Heuristics (combined scoring):
  1. Filename pattern match (jQuery, lodash, webpack, react, angular, vue, bootstrap, etc.)
  2. Minification ratio (average characters per non-empty line > threshold)
  3. Known vendor comment signatures in content
  4. File size threshold (very large files are almost always vendor bundles)

Classification result:
  'vendor'   — known third-party library, apply Low/ignore severity
  'custom'   — looks like application-specific code, apply full severity rules
  'unknown'  — cannot determine, treat conservatively as 'custom'
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ── Filename patterns that strongly indicate vendor code ─────────────────────
VENDOR_FILENAME_PATTERNS = re.compile(
    r"(?:^|[/\\])"
    r"(?:jquery|lodash|underscore|react|angular|vue|backbone|ember|knockout|"
    r"bootstrap|foundation|materialize|bulma|tailwind|alpine|htmx|"
    r"webpack|rollup|parcel|vite|esbuild|babel|polyfill|core-js|"
    r"moment|dayjs|luxon|date-fns|axios|superagent|fetch|ky|"
    r"dagre|d3|chart\.js|three|leaflet|mapbox|openlayers|zustand|"
    r"fontawesome|animate|swiper|slick|glide|"
    r"socket\.io|pusher|ably|"
    r"popper|tippy|flatpickr|pikaday|"
    r"highlight\.js|prism|codemirror|ace|monaco|"
    r"tinymce|quill|ckeditor|"
    r"dompurify|sanitize|xss|"
    r"modernizr|detectizr|"
    r"requirejs|almond|systemjs|"
    r"stripe|braintree|paypal|"
    r"gtag|analytics|hotjar|mixpanel|segment|amplitude|"
    r"sentry|bugsnag|rollbar|"
    r"vendor|bundle|chunk|runtime|emitter|"
    r"(?:\.min|\.bundle|\.umd|\.cjs|\.esm|\.production))",
    re.IGNORECASE,
)

# ── Build-tool output filename patterns (content-hash / numeric chunk IDs) ────
# Matches files like: main.ac652d277abd65c3.js  p-1a502752.entry.js  356.js
# These are always the output of a bundler (webpack/vite/rollup), never raw source.
#
# Bug history (2026-07-12): original pattern used [a-f0-9] (hex only) for both
# Stencil p-HASH and webpack/vite hash patterns. This missed:
#   - Stencil base62 hashes: p-vUKPA-Wq.js, p-Cn0TKsE0.js, p-MGekxLEz.js
#   - Vite base64url hashes: main-hNWVrx56.js, useFramesStore-Ck056IKp.js
#   - Dash-separator format: app-b9ad640378cbf47b7441.js
# Fix: use [a-zA-Z0-9_\-] (full alphanumeric+dash) for all hash segments.
BUILD_HASH_PATTERN = re.compile(
    r"/(?:"
    r"[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]{8,}(?:\.entry)?\.js"  # name.HASH.js (dot-sep, any charset)
    r"|[a-zA-Z0-9_\-]+-[a-zA-Z0-9_\-]{6,}\.js"               # name-HASH.js (dash-sep, vite style)
    r"|p-[a-zA-Z0-9_\-]{5,}\.(?:entry\.)?js"                  # p-HASH.js (Stencil, base62)
    r"|\d{2,4}\.js"                                             # 356.js (numeric webpack chunk)
    r"|[a-zA-Z0-9_\-]+\.min\.js"                               # name.min.js
    r")",
    re.IGNORECASE,
)

# ── Query-string cache-busting hash — e.g. common.js?ver=26dd641bbae9828e ─────
# Angular/webpack often serves files with plain names but adds cache-busting hash
# as a query parameter (?ver=, ?v=, ?version=, ?hash=). These are always bundler
# output even though the filename looks generic (common.js, main.js, scripts.js).
QUERY_HASH_PATTERN = re.compile(
    r"\.js\?(?:ver|v|version|hash)=[a-zA-Z0-9_\-]{8,}",
    re.IGNORECASE,
)


# ── Content signatures inside JS files indicating vendor code ────────────────
VENDOR_CONTENT_SIGNATURES = [
    re.compile(r"@license\s+React", re.IGNORECASE),
    re.compile(r"jQuery\s+JavaScript\s+Library", re.IGNORECASE),
    re.compile(r"Lodash\s+<https://lodash\.com/>", re.IGNORECASE),
    re.compile(r"@preserve\s+jQuery", re.IGNORECASE),
    re.compile(r"\/\*\!\s*(?:Bootstrap|Materialize|Bulma)", re.IGNORECASE),
    re.compile(r"Angular\s+v\d+\.\d+", re.IGNORECASE),
    re.compile(r"Vue\.js\s+v\d+", re.IGNORECASE),
    re.compile(r"Webpack\s+runtime", re.IGNORECASE),
    re.compile(r"DOMPurify\s+\d+\.\d+", re.IGNORECASE),
    re.compile(r"Moment\.js\s+project", re.IGNORECASE),
    re.compile(r"https://github\.com/chartjs", re.IGNORECASE),
    re.compile(r"three\.js\s+r\d+", re.IGNORECASE),
]

# Minification ratio: if avg line length exceeds this, likely minified
MINIFICATION_AVG_LINE_LENGTH_THRESHOLD = 200

# Size thresholds
VENDOR_SIZE_BYTES_THRESHOLD = 500 * 1024   # > 500 KB → likely vendor
CUSTOM_SIZE_BYTES_THRESHOLD = 5 * 1024     # < 5 KB → possibly tiny util


@dataclass
class ClassificationResult:
    label: str          # 'vendor' | 'custom' | 'unknown'
    confidence: float   # 0.0 – 1.0
    reasons: list[str]  # human-readable reasons for the classification


def classify(filename: str, content: str | bytes, size_bytes: int) -> ClassificationResult:
    """
    Classify a JS file as vendor, custom, or unknown.

    Args:
        filename : URL or file path (used for filename heuristics)
        content  : decoded JS source (str) or raw bytes
        size_bytes: file size in bytes

    Returns:
        ClassificationResult with label, confidence, and reasons
    """
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    vendor_score = 0.0
    reasons: list[str] = []

    # ── Heuristic 1a: filename pattern (known library names) ──────────────────
    if VENDOR_FILENAME_PATTERNS.search(filename):
        vendor_score += 0.5
        reasons.append("filename matches vendor pattern")

    # ── Heuristic 1b: build-tool output pattern (hash/numeric chunk) ──────────
    # Files like main.ac652d27.js or 356.js are always bundler output, not raw
    # custom source — classify as vendor regardless of content.
    if BUILD_HASH_PATTERN.search(filename):
        vendor_score += 0.5
        reasons.append("filename matches build-tool output pattern (hash/numeric chunk)")

    # ── Heuristic 1c: query-string cache-busting hash ─────────────────────────
    # Angular/webpack serve files with plain names + ?ver=HASH or ?v=HASH.
    # Example: common.js?ver=26dd641bbae9828e — webpack bundle despite generic name.
    if QUERY_HASH_PATTERN.search(filename):
        vendor_score += 0.5
        reasons.append("URL has cache-busting hash in query string (?ver=/v=/version=)")

    # ── Heuristic 2: content signature ───────────────────────────────────────
    for sig in VENDOR_CONTENT_SIGNATURES:
        if sig.search(content[:8192]):   # check first 8 KB for speed
            vendor_score += 0.6          # strong signal — one signature is sufficient
            reasons.append(f"content signature: {sig.pattern[:50]!r}")
            break  # one signature is enough

    # ── Heuristic 3: minification ratio ──────────────────────────────────────
    lines = [ln for ln in content.splitlines() if ln.strip()]
    if lines:
        avg_len = sum(len(ln) for ln in lines) / len(lines)
        if avg_len > MINIFICATION_AVG_LINE_LENGTH_THRESHOLD:
            vendor_score += 0.2
            reasons.append(f"high minification ratio (avg line {avg_len:.0f} chars)")

    # ── Heuristic 4: size-based ───────────────────────────────────────────────
    if size_bytes > VENDOR_SIZE_BYTES_THRESHOLD:
        vendor_score += 0.15
        reasons.append(f"large file ({size_bytes // 1024} KB, likely vendor bundle)")

    # ── Final decision ────────────────────────────────────────────────────────
    confidence = min(vendor_score, 1.0)

    if vendor_score >= 0.4:   # lowered from 0.5 — content signature alone (0.6) is sufficient
        label = "vendor"
    elif vendor_score == 0.0:
        label = "custom"
        reasons.append("no vendor indicators found")
        confidence = 0.8
    else:
        label = "unknown"
        confidence = 0.4

    return ClassificationResult(label=label, confidence=confidence, reasons=reasons)


def is_vendor(filename: str, content: str | bytes, size_bytes: int) -> bool:
    """Convenience wrapper — True if classified as vendor."""
    return classify(filename, content, size_bytes).label == "vendor"
