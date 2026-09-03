"""
src/extraction/mantra_runner.py
Subprocess wrapper for mantra — Go-based secret/API key scanner.

mantra homepage: https://github.com/MrEmpy/mantra
Expected call: mantra -f <file_path> -o json

PRD 8h compliance:
  - timeout=30 on subprocess.run — hang on large files won't block the pipeline
  - Returns [] on any error (timeout, non-zero returncode, JSON decode fail)
  - Caller should never get an exception from this module

Output schema (from mantra JSON output):
  [
    { "match": "AIzaSy...", "type": "Google API Key", "line": 42 },
    ...
  ]

If mantra is not installed, all calls return [] with a one-time WARNING log.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Track whether we've already warned about mantra not being installed
_mantra_missing_warned = False

MANTRA_TIMEOUT_SECONDS = 30   # PRD 8h: must use timeout
MANTRA_BINARY = os.environ.get("MANTRA_BIN", "mantra")


def _mantra_available() -> bool:
    """Check if mantra binary exists in PATH or at MANTRA_BIN env var."""
    global _mantra_missing_warned
    try:
        result = subprocess.run(
            [MANTRA_BINARY, "--version"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        if not _mantra_missing_warned:
            logger.warning(
                "mantra binary not found at '%s'. Secret scanning via mantra is disabled. "
                "Install from: https://github.com/MrEmpy/mantra",
                MANTRA_BINARY,
            )
            _mantra_missing_warned = True
        return False


def run_mantra(content: bytes | str, source_url: str = "") -> list[dict]:
    """
    Run mantra against JS content and return parsed findings.

    Args:
        content   : JS file content (bytes or str)
        source_url: URL of the JS file (for logging context only)

    Returns:
        List of dicts with keys: match, type, line (or empty list on any error)
    """
    if not _mantra_available():
        return []

    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")

    # Write content to a temp file (mantra expects a file path, not stdin)
    with tempfile.NamedTemporaryFile(
        suffix=".js", delete=False, mode="wb"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [MANTRA_BINARY, "-f", tmp_path, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=MANTRA_TIMEOUT_SECONDS,
        )

        if result.returncode != 0:
            logger.warning(
                "mantra exited with code %d for %s: %s",
                result.returncode, source_url or tmp_path,
                result.stderr[:200],
            )
            return []

        if not result.stdout.strip():
            return []

        try:
            findings = json.loads(result.stdout)
            if not isinstance(findings, list):
                logger.warning("mantra returned unexpected JSON shape for %s", source_url)
                return []
            logger.debug("mantra found %d secret(s) in %s", len(findings), source_url)
            return findings

        except json.JSONDecodeError as exc:
            logger.warning("mantra JSON decode failed for %s: %s", source_url, exc)
            return []

    except subprocess.TimeoutExpired:
        logger.warning(
            "mantra timed out (%ds) for %s — returning empty results",
            MANTRA_TIMEOUT_SECONDS, source_url,
        )
        return []

    except Exception as exc:  # pylint: disable=broad-except
        logger.error("mantra unexpected error for %s: %s", source_url, exc)
        return []

    finally:
        # Always clean up the temp file
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass


def mantra_findings_to_db_rows(
    mantra_output: list[dict], js_file_id: int
) -> list[dict]:
    """
    Convert mantra JSON output into rows ready for the findings table.

    Args:
        mantra_output: raw list from run_mantra()
        js_file_id   : FK to js_files.id

    Returns:
        List of dicts matching findings table columns
    """
    rows = []
    for item in mantra_output:
        if not isinstance(item, dict):
            continue
        rows.append({
            "js_file_id":  js_file_id,
            "type":        "secret_mantra",
            "match_value": item.get("match", ""),
            "severity":    "high",          # mantra findings default to High
            "line_number": item.get("line"),
            "snippet":     item.get("match", ""),
            "is_whitelisted": 0,
        })
    return rows
