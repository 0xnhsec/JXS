"""
src/capture/katana_runner.py
katana integration — PRD 8q.

Posisi di pipeline: Capture layer, fast JS discovery SEBELUM mitmproxy/Playwright.
Bukan pengganti — layer tambahan untuk broad initial discovery.

Two-layer scope enforcement (wajib, bukan opsional — PRD 8q, prinsip 4.2):
  Layer 1: katana native flag -cs (crawl-scope) — batasi crawl di level crawl
  Layer 2: filter_katana_output() — Python filter WAJIB sebelum data masuk DB,
           reuse host_whitelist yang sama dari scope_config

Public API:
  run_katana_crawl(urls, scope_config, ...)  → list[str]  (filtered JS URLs)
  ingest_katana_results(js_urls, scope, ...) → dict       (summary: saved/dup/error)

Usage dari CLI (via jxs_cli.py):
  python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov
  python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov --katana-depth 2
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

KATANA_BINARY = shutil.which("katana") or str(Path.home() / "go" / "bin" / "katana")
KATANA_TIMEOUT = 120  # seconds — max crawl time per target, prevent hang

# ─────────────────────────────────────────────────────────────────────────────
# Layer 2: Python-side scope filter (PRD 8q — reuse host_whitelist from scope_config)
# ─────────────────────────────────────────────────────────────────────────────

def filter_katana_output(raw_urls: list[str], host_whitelist: list[str]) -> list[str]:
    """
    PRD 8q Layer 2 — filter URLs sebelum masuk ke DB.

    Reuse host_whitelist dari scope_config (sama persis dengan mitmproxy addon filter).
    Out-of-scope URLs di-drop secara SILENT — ini expected behavior, bukan error.
    Hanya JS-like URLs yang lolos (filter berdasarkan ekstensi + Content-Type hint).

    Args:
        raw_urls: Raw output dari katana (satu URL per baris)
        host_whitelist: List of allowed hostnames from scope_config

    Returns:
        Filtered list — hanya URL in-scope yang kemungkinan JS
    """
    filtered = []
    dropped_scope = 0
    dropped_nojs = 0

    for url in raw_urls:
        url = url.strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        # ── Scope check (suffix match, sama seperti mitmproxy addon) ─────────
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            dropped_scope += 1
            continue

        host = host.lower().split(":")[0]  # strip port
        in_scope = any(
            host == w.lower() or host.endswith(f".{w.lower()}")
            for w in host_whitelist
        )
        if not in_scope:
            dropped_scope += 1
            continue  # SILENT DROP — expected, not an error

        # ── JS-like URL filter ────────────────────────────────────────────────
        path = urlparse(url).path.lower()
        qs = urlparse(url).query.lower()

        # Accept if .js in path, or ?type=js, or generic path endpoints worth downloading
        is_js_candidate = (
            path.endswith(".js")
            or ".js?" in path
            or ".js&" in path
            or "javascript" in qs
        )

        # Also accept paths that commonly serve JS (katana -jc output may include API endpoints)
        # We're conservative — only take what's clearly JS
        if not is_js_candidate:
            dropped_nojs += 1
            continue

        filtered.append(url)

    logger.info(
        "filter_katana_output: %d in → %d JS in-scope, %d dropped (scope), %d dropped (non-JS)",
        len(raw_urls), len(filtered), dropped_scope, dropped_nojs,
    )
    return filtered


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1: katana subprocess runner
# ─────────────────────────────────────────────────────────────────────────────

def _build_crawl_scope_flag(host_whitelist: list[str]) -> str:
    """
    Build -cs (crawl-scope) regex value for katana from host_whitelist.

    katana v1.1+ uses -cs as a *regex* pattern (not glob).
    Old format 'target.com,*.target.com' was glob-style and causes:
      [ERR] could not compile regex *.target.com: missing argument to repetition operator

    Correct format per katana docs:
      -cs '(target\\.com|.*\\.target\\.com)'

    This generates a single regex that matches:
      - exact domain: target.com
      - all subdomains: sub.target.com, deep.sub.target.com, etc.

    Dots in domain names are escaped (\\.) to be treated as literal dots, not
    regex any-char wildcards — prevents 'targetXcom' from being in-scope.
    """
    import re
    parts = []
    for host in host_whitelist:
        host = host.lower().strip()
        if not host:
            continue
        escaped = re.escape(host)   # e.g. "bojonegorokab\\.go\\.id"
        # Match exact host OR any subdomain depth
        parts.append(escaped)               # exact: bojonegorokab.go.id
        parts.append(r".*\." + escaped)     # subdomains: *.bojonegorokab.go.id
    if not parts:
        return ".*"
    return "(" + "|".join(parts) + ")"



def run_katana_crawl(
    urls: list[str],
    host_whitelist: list[str],
    depth: int = 3,
    timeout: int = KATANA_TIMEOUT,
    extra_flags: Optional[list[str]] = None,
    katana_binary: str = KATANA_BINARY,
) -> list[str]:
    """
    PRD 8q — Run katana crawl + apply two-layer scope enforcement.

    Layer 1: -cs flag (native katana crawl-scope)
    Layer 2: filter_katana_output() (Python-side, always applied)

    Args:
        urls          : Entry point URLs to crawl (passed via -u or -list)
        host_whitelist: Allowed hosts from scope_config (PRD 4.2)
        depth         : Crawl depth (default 3 — PRD 8q spec)
        timeout       : Max subprocess runtime in seconds
        extra_flags   : Additional katana flags (e.g. ['-H', 'Cookie: ...'])
        katana_binary : Path to katana binary

    Returns:
        Filtered list of in-scope JS URLs discovered by katana.
        Empty list if katana not found or crawl fails.
    """
    if not Path(katana_binary).exists() and not shutil.which(katana_binary):
        logger.error(
            "katana binary not found at '%s'. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
            katana_binary,
        )
        return []

    cs_flag = _build_crawl_scope_flag(host_whitelist)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="jxs_katana_urls_"
    ) as f:
        url_list_file = f.name
        for url in urls:
            f.write(url + "\n")

    with tempfile.NamedTemporaryFile(
        mode="r", suffix=".txt", delete=False, prefix="jxs_katana_out_"
    ) as f:
        output_file = f.name

    cmd = [
        katana_binary,
        "-list", url_list_file,     # entry point URL list
        "-jc",                       # JS-in-JS discovery (follow fetch/import in JS content)
        "-d", str(depth),            # crawl depth
        "-cs", cs_flag,              # Layer 1 scope enforcement
        "-o", output_file,           # write output to file
        "-silent",                   # suppress banner/info to stderr
        "-nc",                       # no color
        "-timeout", "10",            # per-request timeout (seconds)
    ]

    if extra_flags:
        cmd.extend(extra_flags)

    logger.info(
        "Running katana: %s (depth=%d, scope=%s)",
        " ".join(cmd[:6]) + " ...", depth, cs_flag[:60],
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.error("katana timed out after %d seconds (target may be very large)", timeout)
        _cleanup_temp_files(url_list_file, output_file)
        return []
    except FileNotFoundError:
        logger.error("katana binary not executable: %s", katana_binary)
        _cleanup_temp_files(url_list_file, output_file)
        return []
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("katana subprocess error: %s", exc)
        _cleanup_temp_files(url_list_file, output_file)
        return []

    if result.returncode not in (0, 1):  # katana exits 1 if some URLs fail — acceptable
        logger.warning("katana exited %d. stderr: %s", result.returncode, result.stderr[:500])

    # Read output file
    try:
        raw_urls = Path(output_file).read_text().splitlines()
    except Exception as exc:
        logger.error("Could not read katana output: %s", exc)
        raw_urls = []
    finally:
        _cleanup_temp_files(url_list_file, output_file)

    logger.info("katana raw output: %d URLs", len(raw_urls))

    # Layer 2 — always applied, no exception
    filtered = filter_katana_output(raw_urls, host_whitelist)
    return filtered


def _cleanup_temp_files(*paths: str) -> None:
    for p in paths:
        try:
            Path(p).unlink(missing_ok=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Ingest katana results into jxs DB
# ─────────────────────────────────────────────────────────────────────────────

def ingest_katana_results(
    js_urls: list[str],
    scope: str,
    conn,
    auth_cookie: Optional[str] = None,
    scope_cfg=None,  # ScopeConfig | None — used to tag test_only_hosts
) -> dict:
    """
    Download JS files discovered by katana and save to js_files table.

    Reuses the same save logic as mitmproxy addon (dedup by content_hash).
    Each URL is stored as an individual row (PRD 8r traceability mandate).
    NOT allowed to merge/concatenate files — each URL = 1 row.

    Args:
        js_urls    : Filtered JS URLs from run_katana_crawl() (already scope-filtered)
        scope      : Scope name (e.g. 'nasa')
        conn       : Active SQLite connection
        auth_cookie: Optional session cookie header value
        scope_cfg  : ScopeConfig for active scope; used to detect test_only_hosts
                     and set verify_scope=1 on the saved row.

    Returns:
        Summary dict: {saved, duplicates, errors, total}
    """
    saved = 0
    duplicates = 0
    errors = 0

    for url in js_urls:
        try:
            headers = {"User-Agent": "jxs/0.1 katana-ingest (+recon)"}
            if auth_cookie:
                headers["Cookie"] = auth_cookie

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()

        except Exception as exc:
            logger.warning("[katana-ingest] Download failed for %s: %s", url, exc)
            errors += 1
            continue

        content_hash = hashlib.sha256(content).hexdigest()
        host = urlparse(url).hostname or ""
        size_bytes = len(content)

        # Determine if this host is test_only — tag for scope verification
        verify_scope = 1 if (scope_cfg and scope_cfg.is_test_only_host(host)) else 0

        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO js_files
                    (url, host, scope, content_hash, content, size_bytes, status, verify_scope)
                VALUES (?, ?, ?, ?, ?, ?, 'captured', ?)
                """,
                (url, host, scope, content_hash, content, size_bytes, verify_scope),
            )
            conn.commit()

            if cur.rowcount == 0:
                duplicates += 1
                logger.debug("[katana-ingest] Duplicate (hash exists): %s", url)
            else:
                saved += 1
                logger.info(
                    "[katana-ingest] [+] %s (%d KB)%s", url, size_bytes // 1024,
                    " [verify_scope]" if verify_scope else "",
                )

        except Exception as exc:
            logger.error("[katana-ingest] DB insert failed for %s: %s", url, exc)
            errors += 1

    summary = {
        "total": len(js_urls),
        "saved": saved,
        "duplicates": duplicates,
        "errors": errors,
    }
    logger.info("[katana-ingest] done: %s", summary)
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point (standalone test)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import json

    _PROJECT_ROOT = Path(__file__).resolve().parents[2]
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="katana runner standalone test")
    parser.add_argument("url", help="Entry point URL to crawl")
    parser.add_argument("--whitelist", nargs="+", required=True, help="Allowed hosts (e.g. nasa.gov www.nasa.gov)")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=KATANA_TIMEOUT)
    args = parser.parse_args()

    results = run_katana_crawl(
        urls=[args.url],
        host_whitelist=args.whitelist,
        depth=args.depth,
        timeout=args.timeout,
    )
    print(json.dumps(results, indent=2))
    print(f"\nTotal in-scope JS URLs: {len(results)}")
