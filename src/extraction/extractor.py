"""
src/extraction/extractor.py
Main extraction pipeline for jxs.

Pipeline per JS file (PRD 4.3 & 8e):
  1. Fetch unprocessed js_files from DB (status='captured')
  2. Decode content (UTF-8 with fallback)
  3. If size < 1.5 MB → js-beautify (for readability in snippets)
     If size >= 1.5 MB → skip beautify, regex runs on minified content
  4. Run all regex patterns (EXTRACTION_PATTERNS from patterns.py)
  5. Whitelist context check → downgrade to Info if matches whitelist
  6. Vendor classification → downgrade severity if vendor bundle
  7. Run mantra for secret scanning
  8. Save all findings to `findings` table
  9. Update js_files.status → 'extracted'

Designed to be:
  - Idempotent: skip files already 'extracted'
  - Run manually or triggered via API POST /extract/{scope}
  - Observable: rich logging + progress output

Usage:
    python -m src.extraction.extractor --scope infomaniak
    python -m src.extraction.extractor --all
"""

from __future__ import annotations

import logging
import re
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urljoin

# ── Path bootstrap ────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db
from src.extraction.mantra_runner import (
    mantra_findings_to_db_rows,
    run_mantra,
)
from src.extraction.patterns import (
    EXTRACTION_PATTERNS,
    SECRET_WHITELIST_CONTEXT,
)
from src.extraction.vendor_classifier import classify

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
BEAUTIFY_SIZE_THRESHOLD = 1.5 * 1024 * 1024   # 1.5 MB — PRD 8e
MAX_SCAN_SIZE_BYTES    = 75 * 1024 * 1024     # 75 MB — PRD 8n benchmark: 80 MB = 32.5s (limit ~30s)
SNIPPET_CONTEXT_CHARS = 150                    # chars before/after match for snippet

# Severity downgrade map for vendor bundles
# PRD 8w: 'low' ditambahkan — storage_get default severity adalah low,
# vendor downgrade-nya → info (sudah cukup karena context vendor library)
_VENDOR_SEVERITY_MAP = {
    "high":   "medium",   # DOM sink in vendor → still flag but lower
    "medium": "low",
    "low":    "info",     # storage_get in vendor → info
    "info":   "info",
}


# ─────────────────────────────────────────────────────────────────────────────
# Beautify
# ─────────────────────────────────────────────────────────────────────────────

def _beautify(content: str) -> str:
    """Run js-beautify on content. Returns original if beautify fails."""
    try:
        import jsbeautifier  # lazy import — not needed for oversized files
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.max_preserve_newlines = 2
        return jsbeautifier.beautify(content, opts)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("js-beautify failed: %s — proceeding with raw content", exc)
        return content


# ─────────────────────────────────────────────────────────────────────────────
# Snippet extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_snippet(content: str, match: re.Match, context_chars: int = SNIPPET_CONTEXT_CHARS) -> str:
    """Return ±context_chars around the match position for display in UI."""
    start = max(0, match.start() - context_chars)
    end = min(len(content), match.end() + context_chars)
    snippet = content[start:end]
    # Truncate very long lines (minified content can be 1MB on one line)
    if len(snippet) > context_chars * 3:
        snippet = snippet[: context_chars * 3] + "…"
    return snippet.strip()


def _line_number_for(content: str, match: re.Match) -> int | None:
    """Return 1-indexed line number of match start position."""
    return content[: match.start()].count("\n") + 1


# ─────────────────────────────────────────────────────────────────────────────
# Core extraction for one JS file
# ─────────────────────────────────────────────────────────────────────────────

def extract_file(
    js_file_id: int,
    url: str,
    content_bytes: bytes,
    size_bytes: int,
    conn: sqlite3.Connection,
) -> int:
    """
    Run full extraction pipeline for a single JS file.

    Args:
        js_file_id    : PK from js_files table
        url           : original JS file URL (for logging)
        content_bytes : raw JS content
        size_bytes    : file size in bytes
        conn          : open SQLite connection

    Returns:
        Number of findings saved.
    """
    logger.info("Extracting [id=%d] %s (%d KB)", js_file_id, url, size_bytes // 1024)

    # ── 0. Size guard (PRD 8n) ───────────────────────────────────────────────
    if size_bytes > MAX_SCAN_SIZE_BYTES:
        logger.warning(
            "[id=%d] file too large (%d MB > limit %d MB), skipping extraction → skipped_too_large",
            js_file_id, size_bytes // (1024 * 1024), MAX_SCAN_SIZE_BYTES // (1024 * 1024),
        )
        conn.execute("UPDATE js_files SET status='skipped_too_large' WHERE id=?", (js_file_id,))
        conn.commit()
        return 0

    # ── 1. Decode ────────────────────────────────────────────────────────────
    try:
        content_str = content_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.error("[id=%d] decode failed: %s", js_file_id, exc)
        return 0

    # ── 2. Beautify decision (PRD 8e) ────────────────────────────────────────
    is_beautified = False
    if size_bytes < BEAUTIFY_SIZE_THRESHOLD:
        content_str = _beautify(content_str)
        is_beautified = True
        logger.debug("[id=%d] beautified", js_file_id)
    else:
        logger.debug("[id=%d] skipping beautify (>= 1.5 MB)", js_file_id)

    # ── 3. Vendor classification ─────────────────────────────────────────────
    classification = classify(url, content_str, size_bytes)
    is_vendor = classification.label == "vendor"
    logger.debug(
        "[id=%d] vendor=%s (confidence=%.2f, reasons=%s)",
        js_file_id, is_vendor, classification.confidence, classification.reasons,
    )

    findings_to_insert: list[dict] = []

    # ── 4. Regex extraction ──────────────────────────────────────────────────
    for pattern_name, (pattern, base_severity) in EXTRACTION_PATTERNS.items():
        try:
            for match in pattern.finditer(content_str):
                # Grab the most-specific capture group (first non-None group, or full match)
                groups = [g for g in match.groups() if g is not None]
                match_value = groups[0] if groups else match.group(0)

                severity = base_severity
                is_whitelisted = 0

                # ── 5. Whitelist context check ────────────────────────────
                surrounding = _extract_snippet(content_str, match, context_chars=300)
                if SECRET_WHITELIST_CONTEXT.search(surrounding):
                    severity = "info"
                    is_whitelisted = 1

                # ── 6. Vendor severity downgrade ──────────────────────────
                if is_vendor and not is_whitelisted:
                    severity = _VENDOR_SEVERITY_MAP.get(severity, "info")

                snippet = _extract_snippet(content_str, match)
                line_no = _line_number_for(content_str, match)

                # PRD 8p — target_url: resolve relative paths for endpoint/sourcemap
                _URL_TYPES = ("endpoint", "endpoint_fetch", "sourcemap")
                if pattern_name in _URL_TYPES and match_value:
                    target_url = urljoin(url, match_value)
                else:
                    target_url = url  # dom_sink, secret_param, etc — same as resolved_url

                findings_to_insert.append({
                    "js_file_id":    js_file_id,
                    "type":          pattern_name,
                    "match_value":   match_value[:500],   # cap length
                    "severity":      severity,
                    "line_number":   line_no,
                    "snippet":       snippet[:1000],       # cap length
                    "is_whitelisted": is_whitelisted,
                    "resolved_url":  url,                 # JS file URL — for Burp history lookup
                    "target_url":    target_url,           # PRD 8p — resolved resource URL
                    "review_status": "unreviewed",         # PRD 8p-1 — default
                })
        except re.error as exc:
            logger.error("[id=%d] regex error in pattern '%s': %s", js_file_id, pattern_name, exc)

    # ── 7. mantra secret scan ────────────────────────────────────────────────
    mantra_raw = run_mantra(content_bytes, source_url=url)
    mantra_rows = mantra_findings_to_db_rows(mantra_raw, js_file_id)
    findings_to_insert.extend(mantra_rows)

    # ── 8. Batch insert findings ────────────────────────────────────────────────
    # Ensure resolved_url + target_url are populated for every row (mantra rows may lack them)
    for row in findings_to_insert:
        row.setdefault("resolved_url", url)
        row.setdefault("target_url", url)
        row.setdefault("review_status", "unreviewed")
        row.setdefault("review_note", None)

    inserted = 0
    for row in findings_to_insert:
        try:
            conn.execute(
                """
                INSERT INTO findings
                    (js_file_id, type, match_value, severity, line_number, snippet,
                     is_whitelisted, resolved_url, target_url, review_status, review_note)
                VALUES (:js_file_id, :type, :match_value, :severity, :line_number, :snippet,
                        :is_whitelisted, :resolved_url, :target_url, :review_status, :review_note)
                """,
                row,
            )
            inserted += 1
        except sqlite3.Error as exc:
            logger.error("[id=%d] DB insert failed for finding: %s", js_file_id, exc)

    conn.commit()

    # ── 9. Update js_files status ────────────────────────────────────────────
    conn.execute(
        "UPDATE js_files SET status=?, is_beautified=? WHERE id=?",
        ("extracted", int(is_beautified), js_file_id),
    )
    conn.commit()

    logger.info(
        "[id=%d] done — %d finding(s) saved [vendor=%s]",
        js_file_id, inserted, is_vendor,
    )
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# Batch extraction
# ─────────────────────────────────────────────────────────────────────────────

def run_extraction(
    scope: str | None = None,
    db_path: str | Path = DEFAULT_DB_PATH,
    limit: int | None = None,
) -> dict:
    """
    Run extraction pipeline over all unprocessed JS files in DB.

    Args:
        scope   : if provided, only process files in this scope
        db_path : path to SQLite DB
        limit   : max files to process (None = all)

    Returns:
        Summary dict: {processed, total_findings, skipped_errors}
    """
    init_db(db_path)
    conn = get_connection(db_path)

    try:
        # Fetch files with status='captured' (not yet extracted or skipped)
        query = "SELECT id, url, content, size_bytes FROM js_files WHERE status='captured'"
        params: list = []
        if scope:
            query += " AND scope=?"
            params.append(scope)
        if limit:
            query += f" LIMIT {int(limit)}"

        rows = conn.execute(query, params).fetchall()
        total_files = len(rows)
        logger.info(
            "Starting extraction: %d file(s) to process (scope=%s)",
            total_files, scope or "all",
        )

        processed = 0
        total_findings = 0
        skipped_errors = 0

        for row in rows:
            if row["content"] is None:
                logger.warning("File id=%d has no content (oversized_skipped?), skipping", row["id"])
                skipped_errors += 1
                continue
            try:
                findings_count = extract_file(
                    js_file_id=row["id"],
                    url=row["url"],
                    content_bytes=row["content"],
                    size_bytes=row["size_bytes"],
                    conn=conn,
                )
                total_findings += findings_count
                processed += 1
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Extraction failed for id=%d: %s", row["id"], exc)
                conn.execute(
                    "UPDATE js_files SET status='error' WHERE id=?", (row["id"],)
                )
                conn.commit()
                skipped_errors += 1

        summary = {
            "processed": processed,
            "total_findings": total_findings,
            "skipped_errors": skipped_errors,
            "total_files": total_files,
        }
        logger.info("Extraction complete: %s", summary)
        return summary

    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="jxs extraction engine")
    parser.add_argument("--scope", help="Only process files in this scope")
    parser.add_argument("--all", action="store_true", help="Process all scopes")
    parser.add_argument("--limit", type=int, help="Max files to process")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Path to SQLite DB")
    args = parser.parse_args()

    scope_arg = None if args.all else args.scope
    summary = run_extraction(scope=scope_arg, db_path=args.db, limit=args.limit)
    print(f"\nExtraction Summary: {summary}")
