"""
src/techstack/detector.py
Rule-based tech stack detection for jxs.

Approach: adapt Wappalyzer fingerprint pattern logic as Python rules (PRD 8h).
NOT a dependency on Wappalyzer browser extension — pure regex/string rules
derived from their open-source fingerprint definitions.

Rule schema:
  Each rule is a TechRule dataclass with:
    - name        : display name (e.g. "React")
    - category    : "framework" | "library" | "cms" | "analytics" | "cdn" | "other"
    - patterns    : list of regex patterns to match against JS content
    - url_patterns: list of regex patterns to match against JS file URL
    - confidence  : base confidence score (0.0 – 1.0)

Detection runs in two phases:
  1. URL-based match (fast, no content needed)
  2. Content-based match (accurate, runs on decoded content)

Results saved to tech_stack table.

PRD 8f Done Criteria: identify at least 3 tech from 1 target with known ground truth.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

TechCategory = Literal["framework", "library", "cms", "analytics", "cdn", "build_tool", "security", "other"]


@dataclass
class TechRule:
    name: str
    category: TechCategory
    patterns: list[str]         # content regex patterns
    url_patterns: list[str] = field(default_factory=list)   # URL regex patterns
    confidence: float = 0.75    # base confidence

    def __post_init__(self) -> None:
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.patterns]
        self._compiled_url_patterns = [re.compile(p, re.IGNORECASE) for p in self.url_patterns]

    def match_content(self, content: str) -> tuple[bool, str]:
        """Return (matched, evidence_string)."""
        for pat in self._compiled_patterns:
            m = pat.search(content[:20_000])   # check first 20 KB for speed
            if m:
                return True, m.group(0)[:100]
        return False, ""

    def match_url(self, url: str) -> tuple[bool, str]:
        for pat in self._compiled_url_patterns:
            m = pat.search(url)
            if m:
                return True, m.group(0)[:100]
        return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions — adapted from Wappalyzer fingerprints
# ─────────────────────────────────────────────────────────────────────────────
TECH_RULES: list[TechRule] = [
    # ── JavaScript Frameworks ────────────────────────────────────────────────
    TechRule(
        name="React",
        category="framework",
        patterns=[
            r"React\.createElement",
            r"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
            r"ReactDOM\.render|createRoot\(",
            r'"react":\s*"[\d.]+',
        ],
        url_patterns=[r"react(?:\.min|\.development|\.production)?\.js"],
        confidence=0.9,
    ),
    TechRule(
        name="Vue.js",
        category="framework",
        patterns=[
            r"Vue\.(?:component|directive|mixin|use)\(",
            r"__vue_",
            r"createApp\(",
            r'"vue":\s*"[\d.]+',
            r"defineComponent\(",
        ],
        url_patterns=[r"vue(?:\.min|\.esm|\.runtime)?\.js"],
        confidence=0.9,
    ),
    TechRule(
        name="Angular",
        category="framework",
        patterns=[
            r"@angular/core",
            r"platformBrowserDynamic\(\)",
            r"NgModule\(",
            r"ɵɵdefineComponent",
        ],
        url_patterns=[r"angular(?:\.min)?\.js", r"main\.[a-f0-9]+\.js"],
        confidence=0.85,
    ),
    TechRule(
        name="Next.js",
        category="framework",
        patterns=[
            r"__NEXT_DATA__",
            r"next/dist/",
            r"_next/static/",
            r"NextRouter",
        ],
        url_patterns=[r"_next/static/chunks/", r"_next/static/js/"],
        confidence=0.95,
    ),
    TechRule(
        name="Nuxt.js",
        category="framework",
        patterns=[
            r"__nuxt",
            r"nuxt\.js",
            r"\$nuxt",
        ],
        url_patterns=[r"_nuxt/"],
        confidence=0.9,
    ),
    TechRule(
        name="Svelte",
        category="framework",
        patterns=[
            r"svelte/internal",
            r"SvelteComponent",
            r"create_fragment",
            r"mount_component",
        ],
        url_patterns=[r"svelte(?:\.min)?\.js"],
        confidence=0.85,
    ),

    # ── Libraries ────────────────────────────────────────────────────────────
    TechRule(
        name="jQuery",
        category="library",
        patterns=[
            r"jQuery\s+v[\d.]+",
            r"jquery\.fn\.jquery",
            r"\$\.ajax\(",
            r"jQuery\.fn",
        ],
        url_patterns=[r"jquery(?:-\d+\.\d+\.\d+)?(?:\.min)?\.js"],
        confidence=0.95,
    ),
    TechRule(
        name="Lodash",
        category="library",
        patterns=[
            r"Lodash\s+<https://lodash\.com/>",
            r"var\s+_\s*=\s*_\s*\|\|",
            r"exports\.__chain",
        ],
        url_patterns=[r"lodash(?:\.min)?\.js"],
        confidence=0.9,
    ),
    TechRule(
        name="Axios",
        category="library",
        patterns=[
            r"axios\.create\(",
            r"axios\.interceptors",
            r'"axios":\s*"[\d.]+',
        ],
        url_patterns=[r"axios(?:\.min)?\.js"],
        confidence=0.85,
    ),
    TechRule(
        name="Moment.js",
        category="library",
        patterns=[
            r"moment\.utc\(",
            r"Moment\.js\s+project",
            r'require\("moment"\)',
        ],
        url_patterns=[r"moment(?:\.min)?\.js"],
        confidence=0.9,
    ),

    # ── Build Tools / Bundlers ────────────────────────────────────────────────
    TechRule(
        name="Webpack",
        category="build_tool",
        patterns=[
            r"webpackJsonp",
            r"__webpack_require__",
            r"webpackChunk",
            r"/\*! For license information please see",
        ],
        url_patterns=[r"webpack(?:-runtime)?\.js", r"runtime\.[a-f0-9]+\.js"],
        confidence=0.9,
    ),
    TechRule(
        name="Vite",
        category="build_tool",
        patterns=[
            r"import\.meta\.env\.VITE_",
            r"@vite/client",
            r"viteDevServer",
        ],
        url_patterns=[r"/@vite/", r"/vite\.svg"],
        confidence=0.9,
    ),

    # ── CMS ──────────────────────────────────────────────────────────────────
    TechRule(
        name="WordPress",
        category="cms",
        patterns=[
            r"wp-content/themes/",
            r"wp-includes/js/",
            r"window\.wp\s*=",
            r"wpApiSettings",
        ],
        url_patterns=[r"wp-(?:content|includes|admin)/", r"wp-json/"],
        confidence=0.95,
    ),
    TechRule(
        name="Drupal",
        category="cms",
        patterns=[
            r"Drupal\.behaviors",
            r"Drupal\.settings",
            r"drupalSettings",
        ],
        url_patterns=[r"/sites/default/files/js/", r"/modules/contrib/"],
        confidence=0.9,
    ),

    # ── Analytics & Tracking ─────────────────────────────────────────────────
    TechRule(
        name="Google Analytics (GA4)",
        category="analytics",
        patterns=[
            r"gtag\('config',\s*'G-",
            r"ga\('create',",
            r"_gaq\.push\(",
            r"GoogleAnalyticsObject",
        ],
        url_patterns=[r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag"],
        confidence=0.95,
    ),
    TechRule(
        name="Hotjar",
        category="analytics",
        patterns=[r"hj\s*=\s*window\.hj", r"hjid", r"hotjar"],
        url_patterns=[r"static\.hotjar\.com"],
        confidence=0.9,
    ),
    TechRule(
        name="Sentry",
        category="other",
        patterns=[
            r"Sentry\.init\(",
            r"@sentry/browser",
            r"Raven\.config\(",
        ],
        url_patterns=[r"browser\.sentry-cdn\.com"],
        confidence=0.9,
    ),

    # ── Security ─────────────────────────────────────────────────────────────
    TechRule(
        name="DOMPurify",
        category="security",
        patterns=[
            r"DOMPurify\.sanitize\(",
            r"DOMPurify\s+\d+\.\d+",
        ],
        url_patterns=[r"dompurify(?:\.min)?\.js"],
        confidence=0.9,
    ),
    TechRule(
        name="Stripe",
        category="other",
        patterns=[
            r"Stripe\s*\(",
            r"stripe\.createToken\(",
            r"StripeV3",
        ],
        url_patterns=[r"js\.stripe\.com"],
        confidence=0.95,
    ),
    TechRule(
        name="reCAPTCHA",
        category="security",
        patterns=[
            r"grecaptcha\.execute\(",
            r"grecaptcha\.ready\(",
            r"google\.com/recaptcha",
        ],
        url_patterns=[r"www\.google\.com/recaptcha/"],
        confidence=0.95,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Detection function
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TechDetection:
    tech_name: str
    category: str
    confidence: float
    evidence: str
    match_source: str   # 'url' | 'content'


def detect(url: str, content: str | bytes) -> list[TechDetection]:
    """
    Run all tech rules against a JS file URL and content.

    Args:
        url     : JS file URL
        content : decoded JS source or raw bytes

    Returns:
        List of TechDetection results (deduplicated by tech_name)
    """
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    detections: dict[str, TechDetection] = {}

    for rule in TECH_RULES:
        if rule.name in detections:
            continue

        # Phase 1: URL match (fast)
        url_matched, url_evidence = rule.match_url(url)
        if url_matched:
            detections[rule.name] = TechDetection(
                tech_name=rule.name,
                category=rule.category,
                confidence=rule.confidence * 0.8,   # slightly lower — URL alone is less definitive
                evidence=url_evidence,
                match_source="url",
            )
            continue

        # Phase 2: Content match
        content_matched, content_evidence = rule.match_content(content)
        if content_matched:
            detections[rule.name] = TechDetection(
                tech_name=rule.name,
                category=rule.category,
                confidence=rule.confidence,
                evidence=content_evidence,
                match_source="content",
            )

    return list(detections.values())


def run_tech_detection(
    scope: str | None = None,
    db_path: str | Path = None,
) -> dict:
    """
    Run tech detection on all extracted JS files and save results to DB.

    Args:
        scope   : filter by scope (None = all)
        db_path : path to SQLite DB

    Returns:
        Summary dict
    """
    from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db

    if db_path is None:
        db_path = DEFAULT_DB_PATH

    init_db(db_path)
    conn = get_connection(db_path)

    try:
        query = """
            SELECT id, url, content FROM js_files
            WHERE status IN ('extracted', 'captured') AND content IS NOT NULL
        """
        params: list = []
        if scope:
            query += " AND scope=?"
            params.append(scope)

        rows = conn.execute(query, params).fetchall()
        logger.info("Tech detection: %d files to process", len(rows))

        total_detections = 0
        for row in rows:
            try:
                detected = detect(row["url"], row["content"])
                for d in detected:
                    conn.execute(
                        """
                        INSERT INTO tech_stack (js_file_id, tech_name, confidence, evidence)
                        VALUES (?, ?, ?, ?)
                        """,
                        (row["id"], d.tech_name, d.confidence, d.evidence),
                    )
                    total_detections += 1
                if detected:
                    conn.commit()
                    logger.debug(
                        "[id=%d] detected: %s",
                        row["id"], [d.tech_name for d in detected],
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("[id=%d] tech detection failed: %s", row["id"], exc)

        summary = {"files_processed": len(rows), "total_detections": total_detections}
        logger.info("Tech detection complete: %s", summary)
        return summary

    finally:
        conn.close()
