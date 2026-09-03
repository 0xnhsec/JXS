"""
src/cli/jxs_cli.py
jxs CLI entry point — PRD 8m.

Subcommands:
  scan    — run extraction pipeline + output findings as JSON or table
  status  — show DB stats per scope
  export  — generate snippet.md per confirmed_bug finding (PRD 8t)

Usage:
  python -m src.cli.jxs_cli scan --scope nasa
  python -m src.cli.jxs_cli scan --scope nasa --format table
  python -m src.cli.jxs_cli scan --url-list js.txt --scope nasa
  python -m src.cli.jxs_cli status
  python -m src.cli.jxs_cli status --scope nasa
  python -m src.cli.jxs_cli export --scope nasa --status confirmed_bug
  python -m src.cli.jxs_cli export --scope nasa --status confirmed_bug --include-source

Reuses the same Extraction Engine as the UI (not separate logic).
Output: JSON to stdout (pipeable to jq), or --format table for human reading.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import textwrap
from pathlib import Path
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db
from src.extraction.extractor import run_extraction
from src.capture.katana_runner import run_katana_crawl, ingest_katana_results
from src.capture.config import ScopeRegistry

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("JXS_DB_PATH", str(DEFAULT_DB_PATH))

REVIEW_STATUS_VALUES = [
    "unreviewed",
    "checked_fp",
    "checked_benign",
    "confirmed_bug",
    "reported",
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _color(text: str, code: str) -> str:
    """ANSI color if stdout is a tty."""
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

SEV_COLOR = {
    "high":   "31",   # red
    "medium": "33",   # yellow
    "low":    "37",   # white/gray
    "info":   "34",   # blue
}

STATUS_COLOR = {
    "confirmed_bug": "32",  # green
    "reported":      "32",
    "checked_fp":    "90",  # dark gray
    "checked_benign":"90",
    "unreviewed":    "37",
}


def _print_table(findings: list[dict]) -> None:
    """Print findings as a compact table to stdout."""
    if not findings:
        print("(no findings)")
        return

    cols = ["id", "type", "severity", "review_status", "match_value", "target_url"]
    col_widths = {c: max(len(c), max((len(str(f.get(c, "") or "")) for f in findings), default=0)) for c in cols}
    col_widths["match_value"] = min(col_widths["match_value"], 50)
    col_widths["target_url"] = min(col_widths["target_url"], 60)

    header = "  ".join(c.ljust(col_widths[c]) for c in cols)
    print(_color(header, "1"))  # bold
    print("-" * len(header))

    for f in findings:
        sev = f.get("severity", "info")
        status = f.get("review_status", "unreviewed")
        row_parts = []
        for c in cols:
            val = str(f.get(c, "") or "")
            if c in ("match_value", "target_url"):
                val = val[:col_widths[c]]
            row_parts.append(val.ljust(col_widths[c]))
        line = "  ".join(row_parts)

        color = SEV_COLOR.get(sev, "37")
        if status == "checked_fp":
            color = "90"
        print(_color(line, color))


# ─────────────────────────────────────────────────────────────────────────────
# subcommand: scan
# ─────────────────────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    """
    Run extraction pipeline and output findings.
    Reuses run_extraction() — same engine as UI, no separate logic.
    Supports three modes:
      1. --katana-url : discover JS via katana crawl first, then extract
      2. --url-list   : feed URL list, download + extract
      3. --scope      : extract already-captured files in DB
    """
    init_db(DB_PATH)

    # ── katana-all mode: scan seluruh host di whitelist sekaligus ─────────────
    if getattr(args, 'katana_all', False):
        scope = args.scope
        if not scope:
            print("[ERROR] --scope required with --katana-all", file=sys.stderr)
            return 1

        registry = ScopeRegistry()
        sc = registry.get(scope)
        if not sc:
            print(f"[ERROR] scope '{scope}' not found in scope_config.json", file=sys.stderr)
            return 1

        if not sc.host_whitelist:
            print(f"[ERROR] scope '{scope}' has empty host_whitelist", file=sys.stderr)
            return 1

        # Build URL list — https://{host} untuk setiap entry di whitelist
        all_urls = [f"https://{h}" for h in sc.host_whitelist]
        depth   = getattr(args, "katana_depth", 2)     # default depth 2 untuk bulk
        timeout = getattr(args, "katana_timeout", 600)  # default 10 menit untuk bulk

        print(f"[jxs scan/katana-all] Scanning {len(all_urls)} hosts for scope '{scope}'",
              file=sys.stderr)
        print(f"[jxs scan/katana-all] depth={depth} timeout={timeout}s", file=sys.stderr)
        if len(all_urls) > 10:
            print(f"[jxs scan/katana-all] First 5: {all_urls[:5]} ...", file=sys.stderr)
        else:
            print(f"[jxs scan/katana-all] URLs: {all_urls}", file=sys.stderr)

        # Katana support multi-URL natively via -list flag
        js_urls = run_katana_crawl(
            urls=all_urls,
            host_whitelist=sc.host_whitelist + sc.test_only_hosts,
            depth=depth,
            timeout=timeout,
        )

        print(f"[jxs scan/katana-all] {len(js_urls)} in-scope JS URLs discovered", file=sys.stderr)

        if js_urls:
            conn = get_connection(DB_PATH)
            try:
                summary = ingest_katana_results(
                    js_urls=js_urls,
                    scope=scope,
                    conn=conn,
                    auth_cookie=sc.auth_cookie,
                    scope_cfg=sc,
                )
            finally:
                conn.close()
            print(f"[jxs scan/katana-all] Ingest: {summary}", file=sys.stderr)

            print(f"[jxs scan/katana-all] Running extraction for scope '{scope}'...",
                  file=sys.stderr)
            extr_summary = run_extraction(scope=scope, db_path=DB_PATH,
                                          limit=getattr(args, 'limit', None))
            print(f"[jxs scan/katana-all] Extraction: {extr_summary}", file=sys.stderr)
        else:
            print("[jxs scan/katana-all] No JS found — check connectivity and host list",
                  file=sys.stderr)
        return 0

    # ── katana mode (PRD 8q) ───────────────────────────────────────────────
    if args.katana_url:
        scope = args.scope
        if not scope:
            print("[ERROR] --scope required with --katana-url (for DB storage + scope enforcement)",
                  file=sys.stderr)
            return 1

        # Load scope config for host_whitelist (Layer 2 enforcement)
        registry = ScopeRegistry()
        sc = registry.get(scope)
        if not sc:
            print(f"[ERROR] scope '{scope}' not found in scope_config.json", file=sys.stderr)
            print("  Add it via: POST /scopes API or create scope_config.json manually", file=sys.stderr)
            return 1

        depth = getattr(args, "katana_depth", 3)
        print(
            f"[jxs scan/katana] Crawling {args.katana_url} depth={depth} scope={scope}",
            file=sys.stderr
        )
        print(
            f"[jxs scan/katana] host_whitelist  = {sc.host_whitelist}",
            file=sys.stderr
        )
        if sc.test_only_hosts:
            print(
                f"[jxs scan/katana] test_only_hosts = {sc.test_only_hosts} (findings will be tagged verify_scope)",
                file=sys.stderr
            )

        # Run katana — two-layer enforcement is inside run_katana_crawl()
        js_urls = run_katana_crawl(
            urls=[args.katana_url],
            host_whitelist=sc.host_whitelist,
            depth=depth,
        )

        print(f"[jxs scan/katana] {len(js_urls)} in-scope JS URLs discovered", file=sys.stderr)

        if not js_urls:
            print("[jxs scan/katana] No JS URLs found — check URL, depth, and host_whitelist",
                  file=sys.stderr)
        else:
            # Ingest into DB (individual rows per URL — PRD 8r traceability)
            conn = get_connection(DB_PATH)
            try:
                summary = ingest_katana_results(
                    js_urls=js_urls,
                    scope=scope,
                    conn=conn,
                    auth_cookie=sc.auth_cookie,
                    scope_cfg=sc,   # pass ScopeConfig for test_only_hosts tagging
                )
            finally:
                conn.close()
            print(f"[jxs scan/katana] Ingest: {summary}", file=sys.stderr)

            # Run extraction on newly ingested files
            print(f"[jxs scan/katana] Running extraction for scope '{scope}'...", file=sys.stderr)
            extr_summary = run_extraction(scope=scope, db_path=DB_PATH, limit=args.limit)
            print(f"[jxs scan/katana] Extraction: {extr_summary}", file=sys.stderr)

    # ── URL list mode (--url-list) ────────────────────────────────────────────
    if args.url_list:
        url_file = Path(args.url_list)
        if not url_file.exists():
            print(f"[ERROR] url-list file not found: {url_file}", file=sys.stderr)
            return 1

        urls = [l.strip() for l in url_file.read_text().splitlines() if l.strip()]
        print(f"[jxs scan] URL list mode: {len(urls)} URLs from {url_file}", file=sys.stderr)

        import hashlib, time
        import urllib.request

        conn = get_connection(DB_PATH)
        scope = args.scope or "cli"
        added = 0
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "jxs/0.1 (+recon)"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    content = resp.read()

                content_hash = hashlib.sha256(content).hexdigest()
                host = urlparse(url).hostname or ""
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO js_files
                           (url, host, scope, content_hash, content, size_bytes, status)
                           VALUES (?, ?, ?, ?, ?, ?, 'captured')""",
                        (url, host, scope, content_hash, content, len(content)),
                    )
                    conn.commit()
                    added += 1
                    print(f"  [+] {url} ({len(content)//1024} KB)", file=sys.stderr)
                except Exception as db_exc:
                    print(f"  [dup/err] {url}: {db_exc}", file=sys.stderr)

            except Exception as exc:
                print(f"  [SKIP] {url}: {exc}", file=sys.stderr)

        conn.close()
        print(f"[jxs scan] Added {added} new JS files → running extraction for scope '{scope}'", file=sys.stderr)

        summary = run_extraction(scope=scope, db_path=DB_PATH, limit=args.limit)
        print(f"[jxs scan] Extraction: {summary}", file=sys.stderr)

    else:
        # ── Scope mode (--scope) ──────────────────────────────────────────────
        scope = args.scope
        if not scope:
            print("[ERROR] --scope or --url-list required", file=sys.stderr)
            return 1

        print(f"[jxs scan] Running extraction for scope '{scope}'...", file=sys.stderr)
        summary = run_extraction(scope=scope, db_path=DB_PATH, limit=args.limit)
        print(f"[jxs scan] {summary}", file=sys.stderr)

    # ── Fetch and output findings ─────────────────────────────────────────────
    conn = get_connection(DB_PATH)
    try:
        query = """
            SELECT f.id, f.type, f.match_value, f.severity, f.line_number,
                   f.snippet, f.is_whitelisted, f.resolved_url, f.target_url,
                   f.review_status, f.review_note, j.url as js_url, j.host
            FROM findings f
            JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ?
        """
        params: list = [args.scope or "cli"]

        if args.type:
            query += " AND f.type = ?"
            params.append(args.type)
        if args.severity:
            query += " AND f.severity = ?"
            params.append(args.severity)
        if not args.include_whitelisted:
            query += " AND f.is_whitelisted = 0"
        if args.review_status:
            query += " AND f.review_status = ?"
            params.append(args.review_status)

        query += " ORDER BY f.severity DESC, f.created_at DESC"
        if args.limit:
            query += f" LIMIT {args.limit}"

        rows = conn.execute(query, params).fetchall()
        findings = [dict(r) for r in rows]

    finally:
        conn.close()

    print(f"[jxs scan] {len(findings)} findings returned", file=sys.stderr)

    if args.format == "table":
        _print_table(findings)
    else:
        # JSON to stdout — pipeable to jq
        output = findings if not args.output else None
        if args.output:
            Path(args.output).write_text(json.dumps(findings, indent=2, default=str))
            print(f"[jxs scan] Wrote {len(findings)} findings → {args.output}", file=sys.stderr)
        else:
            print(json.dumps(findings, indent=2, default=str))

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# subcommand: status
# ─────────────────────────────────────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> int:
    """Show DB stats — file counts + finding breakdown per scope."""
    init_db(DB_PATH)
    conn = get_connection(DB_PATH)
    try:
        if args.scope:
            scopes = [args.scope]
        else:
            rows = conn.execute("SELECT DISTINCT scope FROM js_files ORDER BY scope").fetchall()
            scopes = [r["scope"] for r in rows]

        if not scopes:
            print("No scopes found in DB.")
            return 0

        for scope in scopes:
            js_count = conn.execute(
                "SELECT COUNT(*) FROM js_files WHERE scope=?", (scope,)
            ).fetchone()[0]

            status_counts = dict(conn.execute(
                "SELECT status, COUNT(*) FROM js_files WHERE scope=? GROUP BY status", (scope,)
            ).fetchall())

            finding_total = conn.execute(
                """SELECT COUNT(*) FROM findings f
                   JOIN js_files j ON j.id = f.js_file_id
                   WHERE j.scope = ? AND f.is_whitelisted = 0""",
                (scope,)
            ).fetchone()[0]

            sev_counts = dict(conn.execute(
                """SELECT f.severity, COUNT(*) FROM findings f
                   JOIN js_files j ON j.id = f.js_file_id
                   WHERE j.scope = ? AND f.is_whitelisted = 0
                   GROUP BY f.severity""",
                (scope,)
            ).fetchall())

            review_counts = dict(conn.execute(
                """SELECT f.review_status, COUNT(*) FROM findings f
                   JOIN js_files j ON j.id = f.js_file_id
                   WHERE j.scope = ? AND f.is_whitelisted = 0
                   GROUP BY f.review_status""",
                (scope,)
            ).fetchall())

            print(f"\n{'='*60}")
            print(_color(f"  SCOPE: {scope}", "1;36"))
            print(f"{'='*60}")
            print(f"  JS files  : {js_count}")
            for st, cnt in sorted(status_counts.items()):
                print(f"    {st:<22}: {cnt}")

            print(f"\n  Findings  : {finding_total} (non-whitelisted)")
            for sev in ("high", "medium", "low", "info"):
                cnt = sev_counts.get(sev, 0)
                if cnt:
                    print(f"    {_color(sev, SEV_COLOR.get(sev,'37')):<22}: {cnt}")

            print(f"\n  Review status breakdown:")
            for rv_st in REVIEW_STATUS_VALUES:
                cnt = review_counts.get(rv_st, 0)
                color = STATUS_COLOR.get(rv_st, "37")
                bar = "█" * min(cnt // max(finding_total // 20, 1), 40) if finding_total else ""
                print(f"    {_color(rv_st, color):<28}: {cnt:>5}  {bar}")

    finally:
        conn.close()

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# subcommand: export (PRD 8t — PoC Export)
# ─────────────────────────────────────────────────────────────────────────────

def _safe_dirname(url: str) -> str:
    """Convert a JS file URL to a filesystem-safe directory name."""
    parsed = urlparse(url)
    name = (parsed.path or "unknown").lstrip("/").replace("/", "_")
    name = re.sub(r"[^\w\-.]", "_", name)
    return name[:80] or "unknown"


SNIPPET_TEMPLATE = """\
## Finding: [{type}] in {resolved_url}

- **Match:** `{match_value}`
- **Target URL:** `{target_url}`
- **Severity:** {severity} — *auto-tagged by jxs, adjust with CVSS calculator before reporting*
- **Review status:** {review_status}
- **Review note:** {review_note}

### Code Snippet
```js
{snippet}
```

---
*Generated by jxs export — {export_time}*
"""


def cmd_export(args: argparse.Namespace) -> int:
    """
    PRD 8t — Generate snippet.md per finding.

    Output path: targets/<scope>/<jsfile-dir>/snippet-<id>.md
    """
    import datetime

    init_db(DB_PATH)
    conn = get_connection(DB_PATH)
    try:
        query = """
            SELECT f.id, f.type, f.match_value, f.severity, f.snippet,
                   f.resolved_url, f.target_url, f.review_status, f.review_note,
                   j.url as js_url, j.content as js_content
            FROM findings f
            JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ?
        """
        params: list = [args.scope]

        if args.status:
            query += " AND f.review_status = ?"
            params.append(args.status)

        query += " ORDER BY f.severity DESC, f.id"
        rows = conn.execute(query, params).fetchall()
        findings = [dict(r) for r in rows]

    finally:
        conn.close()

    if not findings:
        print(f"[jxs export] No findings matching scope={args.scope} status={args.status}")
        return 0

    export_root = Path("targets") / args.scope
    export_time = datetime.datetime.now().isoformat(timespec="seconds")
    written = 0

    for f in findings:
        jsfile_dir = _safe_dirname(f.get("resolved_url") or f.get("js_url") or "unknown")
        out_dir = export_root / jsfile_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        # Write snippet.md
        snippet_path = out_dir / f"snippet-{f['id']}.md"
        content = SNIPPET_TEMPLATE.format(
            type=f.get("type", ""),
            resolved_url=f.get("resolved_url", ""),
            match_value=f.get("match_value", ""),
            target_url=f.get("target_url", ""),
            severity=f.get("severity", ""),
            review_status=f.get("review_status", ""),
            review_note=f.get("review_note") or "(none)",
            snippet=f.get("snippet") or "(no snippet)",
            export_time=export_time,
        )
        snippet_path.write_text(content, encoding="utf-8")
        print(f"  [+] {snippet_path}")
        written += 1

        # Write source.js if --include-source and content available
        if args.include_source and f.get("js_content"):
            source_path = out_dir / "source.js"
            if not source_path.exists():
                source_bytes = f["js_content"]
                if isinstance(source_bytes, bytes):
                    source_path.write_bytes(source_bytes)
                else:
                    source_path.write_text(str(source_bytes), encoding="utf-8")
                print(f"  [src] {source_path}")

    print(f"\n[jxs export] {written} snippet files written → {export_root}/")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# subcommand: review (update review_status on a finding by id)
# ─────────────────────────────────────────────────────────────────────────────

def cmd_review(args: argparse.Namespace) -> int:
    """Update review_status (and optionally review_note) for a finding."""
    init_db(DB_PATH)

    if args.status not in REVIEW_STATUS_VALUES:
        print(f"[ERROR] invalid status '{args.status}'. Valid: {REVIEW_STATUS_VALUES}", file=sys.stderr)
        return 1

    conn = get_connection(DB_PATH)
    try:
        if args.note is not None:
            conn.execute(
                "UPDATE findings SET review_status=?, review_note=? WHERE id=?",
                (args.status, args.note, args.finding_id),
            )
        else:
            conn.execute(
                "UPDATE findings SET review_status=? WHERE id=?",
                (args.status, args.finding_id),
            )
        conn.commit()
        print(f"[jxs review] finding id={args.finding_id} → {args.status}")
    finally:
        conn.close()

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jxs",
        description="jxs — JavaScript Analysis & Mapping Tool for Bug Bounty (PRD 8m)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              jxs scan --scope nasa
              jxs scan --scope nasa --format table --severity high
              jxs scan --url-list js.txt --scope nasa --output findings.json
              jxs status
              jxs status --scope nasa
              jxs export --scope nasa --status confirmed_bug
              jxs export --scope nasa --status confirmed_bug --include-source
              jxs review 42 confirmed_bug --note "innerHTML sink, user-controlled via hash"
        """),
    )
    parser.add_argument("--db", default=DB_PATH, help="Path to jxs SQLite DB")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Run extraction and output findings")
    p_scan.add_argument("--scope", help="Scope name (required unless --url-list)")
    p_scan.add_argument("--url-list", dest="url_list", help="File with JS URLs, one per line")
    p_scan.add_argument("--katana-url", dest="katana_url",
                        help="Entry point URL for katana crawl (PRD 8q). Requires --scope.")
    p_scan.add_argument("--katana-all", dest="katana_all", action="store_true",
                        help="Crawl ALL hosts in scope's host_whitelist at once. "
                             "Builds https://{host} URL for each entry. Requires --scope.")
    p_scan.add_argument("--katana-depth", dest="katana_depth", type=int, default=3,
                        help="katana crawl depth (default: 3; bulk --katana-all default: 2)")
    p_scan.add_argument("--katana-timeout", dest="katana_timeout", type=int, default=600,
                        help="Max katana subprocess runtime in seconds (default: 600 for bulk, "
                             "120 for single-URL). Raise for large scopes.")
    p_scan.add_argument("--output", "-o", help="Write JSON findings to file instead of stdout")
    p_scan.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    p_scan.add_argument("--type", help="Filter by finding type")
    p_scan.add_argument("--severity", help="Filter by severity (high/medium/low/info)")
    p_scan.add_argument("--review-status", dest="review_status", help="Filter by review status")
    p_scan.add_argument("--include-whitelisted", dest="include_whitelisted", action="store_true")
    p_scan.add_argument("--limit", type=int, help="Max findings to return")

    # ── status ────────────────────────────────────────────────────────────────
    p_status = sub.add_parser("status", help="Show DB stats per scope")
    p_status.add_argument("--scope", help="Filter to one scope (default: all)")

    # ── export ────────────────────────────────────────────────────────────────
    p_export = sub.add_parser("export", help="Generate snippet.md per finding (PRD 8t)")
    p_export.add_argument("--scope", required=True, help="Scope name")
    p_export.add_argument("--status", default="confirmed_bug",
                          choices=REVIEW_STATUS_VALUES, help="Filter by review status")
    p_export.add_argument("--include-source", dest="include_source", action="store_true",
                          help="Also export raw source.js per JS file")

    # ── review ────────────────────────────────────────────────────────────────
    p_review = sub.add_parser("review", help="Update review_status for a finding")
    p_review.add_argument("finding_id", type=int, help="Finding ID (from scan output)")
    p_review.add_argument("status", choices=REVIEW_STATUS_VALUES, help="New review status")
    p_review.add_argument("--note", help="Optional note text")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    global DB_PATH

    logging.basicConfig(
        level=logging.WARNING,   # quiet by default — only show jxs scan progress
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = build_parser()
    args = parser.parse_args()

    if hasattr(args, "db") and args.db:
        DB_PATH = args.db

    dispatch = {
        "scan":   cmd_scan,
        "status": cmd_status,
        "export": cmd_export,
        "review": cmd_review,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
