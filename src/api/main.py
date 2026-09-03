"""
src/api/main.py
FastAPI localhost API server for jxs UI.

Endpoints:
  GET  /health                        — server health check
  GET  /scopes                        — list all configured scopes
  POST /scopes                        — create/update a scope config
  GET  /scope/{scope}/graph           — React Flow graph data (nodes + edges)
  GET  /scope/{scope}/findings        — all findings with optional filters
  GET  /scope/{scope}/stats           — summary counts for a scope
  GET  /js-file/{id}                  — detail: JS file + findings + advisories
  GET  /js-file/{id}/content          — raw JS content (for in-UI code viewer)
  POST /extract/{scope}               — trigger extraction pipeline for a scope
  POST /techstack/{scope}             — trigger tech detection for a scope
  POST /advisor/{scope}               — trigger XSS advisor for a scope

Start with:
    uvicorn src.api.main:app --host 127.0.0.1 --port 8888 --reload

The UI (src/ui) proxies all /api/* requests to this server.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Literal, Optional

# ── Path bootstrap ────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.capture.config import ScopeConfig, ScopeRegistry
from src.db.schema import DEFAULT_DB_PATH, get_connection, get_db_stats, init_db
from src.extraction.extractor import run_extraction
from src.techstack.detector import run_tech_detection
from src.xss_advisor.advisor import run_xss_advisor

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

DB_PATH = os.environ.get("JXS_DB_PATH", str(DEFAULT_DB_PATH))

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="jxs API",
    description="JavaScript Analysis & Mapping Tool — localhost API for bug bounty",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singleton registry — reloaded when scope POST is called
_scope_registry = ScopeRegistry()

# Ensure DB is initialized on startup
init_db(DB_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class ScopeCreateRequest(BaseModel):
    scope_name: str
    host_whitelist: list[str]
    auth_cookie: Optional[str] = None
    host_list_file: Optional[str] = None


class ReviewUpdateRequest(BaseModel):
    review_status: Literal[
        "unreviewed", "checked_fp", "checked_benign", "confirmed_bug", "reported"
    ]
    review_note: Optional[str] = None


class GraphNode(BaseModel):
    id: str
    type: str        # 'jsFile' | 'endpoint' | 'domSink' | 'sourcemap' | 'techStack'
    data: dict
    position: dict = {"x": 0, "y": 0}   # layout done in UI with dagre


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str = "default"


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    scope: str
    total_js_files: int
    total_findings: int


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "db": DB_PATH}


# ─────────────────────────────────────────────────────────────────────────────
# Scopes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/scopes")
def list_scopes():
    """List all configured scopes."""
    conn = get_connection(DB_PATH)
    try:
        rows = conn.execute(
            "SELECT scope, COUNT(*) as js_count FROM js_files GROUP BY scope"
        ).fetchall()
        scope_counts = {r["scope"]: r["js_count"] for r in rows}

        scopes = _scope_registry.all()
        result = []
        for sc in scopes:
            result.append({
                **sc.to_dict(),
                "js_file_count": scope_counts.get(sc.scope_name, 0),
            })

        # Also include scopes that exist in DB but not in config
        for scope_name, count in scope_counts.items():
            if not any(s["scope_name"] == scope_name for s in result):
                result.append({
                    "scope_name": scope_name,
                    "host_whitelist": [],
                    "auth_cookie": None,
                    "host_list_file": None,
                    "js_file_count": count,
                })
        return {"scopes": result}
    finally:
        conn.close()


@app.post("/scopes", status_code=201)
def create_scope(req: ScopeCreateRequest):
    """Create or update a scope configuration."""
    sc = ScopeConfig(
        scope_name=req.scope_name,
        host_whitelist=req.host_whitelist,
        auth_cookie=req.auth_cookie,
        host_list_file=req.host_list_file,
    )
    _scope_registry.add(sc)
    _scope_registry.save()
    return {"message": f"Scope '{req.scope_name}' saved", "scope": sc.to_dict()}


# ─────────────────────────────────────────────────────────────────────────────
# Graph data
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "high":   "#ef4444",   # red
    "medium": "#f59e0b",   # amber
    "low":    "#6b7280",   # gray
    "info":   "#3b82f6",   # blue
}


@app.get("/scope/{scope}/graph", response_model=GraphResponse)
def get_graph(scope: str):
    """
    Build React Flow graph data for a scope.

    Node types:
      - jsFile     : one node per JS file (grey base)
      - endpoint   : aggregated endpoint findings (green)
      - domSink    : DOM sink findings (red — high severity)
      - sourcemap  : sourcemap leak findings (red)
      - techStack  : detected tech stack (purple)

    Edges: jsFile → finding nodes
    """
    conn = get_connection(DB_PATH)
    try:
        js_files = conn.execute(
            "SELECT id, url, host, size_bytes, status, verify_scope FROM js_files WHERE scope=?",
            (scope,)
        ).fetchall()

        if not js_files:
            raise HTTPException(status_code=404, detail=f"No JS files found for scope '{scope}'")

        findings = conn.execute(
            """
            SELECT f.id, f.js_file_id, f.type, f.match_value, f.severity, f.snippet,
                   f.is_whitelisted, f.resolved_url, f.target_url, f.review_status, f.review_note,
                   j.verify_scope
            FROM findings f
            JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ?
            """,
            (scope,)
        ).fetchall()

        tech_stack = conn.execute(
            """
            SELECT ts.js_file_id, ts.tech_name, ts.confidence, ts.evidence
            FROM tech_stack ts
            JOIN js_files j ON j.id = ts.js_file_id
            WHERE j.scope = ?
            """,
            (scope,)
        ).fetchall()

        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []

        # ── JS File nodes ──────────────────────────────────────────────────────
        for jsf in js_files:
            file_findings = [f for f in findings if f["js_file_id"] == jsf["id"]]
            # Determine worst severity for color coding
            severities = [f["severity"] for f in file_findings if not f["is_whitelisted"]]
            worst = "info"
            for sev in ("high", "medium", "low", "info"):
                if sev in severities:
                    worst = sev
                    break

            nodes.append(GraphNode(
                id=f"jsfile-{jsf['id']}",
                type="jsFile",
                data={
                    "id": jsf["id"],
                    "url": jsf["url"],
                    "host": jsf["host"],
                    "size_bytes": jsf["size_bytes"],
                    "status": jsf["status"],
                    "verify_scope": jsf["verify_scope"],
                    "finding_count": len(file_findings),
                    "worst_severity": worst,
                    "color": SEVERITY_COLOR.get(worst, "#6b7280"),
                },
            ))

        # ── Finding nodes + edges ──────────────────────────────────────────────
        _dedup_endpoints: dict[str, str] = {}   # match_value → node_id

        for finding in findings:
            fid = finding["id"]
            file_node_id = f"jsfile-{finding['js_file_id']}"

            if finding["type"] in ("endpoint", "endpoint_fetch"):
                # Deduplicate endpoint nodes across files
                ep_key = finding["match_value"]
                if ep_key not in _dedup_endpoints:
                    node_id = f"endpoint-{fid}"
                    _dedup_endpoints[ep_key] = node_id
                    nodes.append(GraphNode(
                        id=node_id,
                        type="endpoint",
                        data={
                            "id":            fid,
                            "match_value":   finding["match_value"],
                            "severity":      finding["severity"],
                            "color":         SEVERITY_COLOR.get(finding["severity"], "#6b7280"),
                            "is_whitelisted": bool(finding["is_whitelisted"]),
                            "verify_scope":  finding["verify_scope"],
                            "resolved_url":  finding["resolved_url"],
                            "target_url":    finding["target_url"],
                            "review_status": finding["review_status"] or "unreviewed",
                            "review_note":   finding["review_note"],
                        },
                    ))
                edges.append(GraphEdge(
                    id=f"edge-{file_node_id}-{_dedup_endpoints[ep_key]}-{fid}",
                    source=file_node_id,
                    target=_dedup_endpoints[ep_key],
                ))

            elif finding["type"] == "dom_sink":
                node_id = f"domsink-{fid}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="domSink",
                    data={
                        "id":            fid,
                        "finding_id":    fid,
                        "match_value":   finding["match_value"],
                        "snippet":       finding["snippet"],
                        "severity":      finding["severity"],
                        "color":         SEVERITY_COLOR.get(finding["severity"], "#ef4444"),
                        "is_whitelisted": bool(finding["is_whitelisted"]),
                        "verify_scope":  finding["verify_scope"],
                        "resolved_url":  finding["resolved_url"],
                        "target_url":    finding["target_url"],
                        "review_status": finding["review_status"] or "unreviewed",
                        "review_note":   finding["review_note"],
                    },
                ))
                edges.append(GraphEdge(
                    id=f"edge-{file_node_id}-{node_id}",
                    source=file_node_id,
                    target=node_id,
                ))

            elif finding["type"] == "sourcemap":
                node_id = f"sourcemap-{fid}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="sourcemap",
                    data={
                        "id":            fid,
                        "finding_id":    fid,
                        "match_value":   finding["match_value"],
                        "severity":      "high",
                        "color":         "#ef4444",
                        "verify_scope":  finding["verify_scope"],
                        "resolved_url":  finding["resolved_url"],
                        "target_url":    finding["target_url"],
                        "review_status": finding["review_status"] or "unreviewed",
                        "review_note":   finding["review_note"],
                    },
                ))
                edges.append(GraphEdge(
                    id=f"edge-{file_node_id}-{node_id}",
                    source=file_node_id,
                    target=node_id,
                ))

        # ── Tech stack nodes ───────────────────────────────────────────────────
        _tech_seen: set[str] = set()
        for ts in tech_stack:
            key = f"{ts['js_file_id']}-{ts['tech_name']}"
            if key in _tech_seen:
                continue
            _tech_seen.add(key)
            node_id = f"tech-{ts['js_file_id']}-{ts['tech_name'].lower().replace(' ', '-')}"
            nodes.append(GraphNode(
                id=node_id,
                type="techStack",
                data={
                    "tech_name": ts["tech_name"],
                    "confidence": ts["confidence"],
                    "evidence": ts["evidence"],
                    "color": "#8b5cf6",
                },
            ))
            edges.append(GraphEdge(
                id=f"edge-jsfile-{ts['js_file_id']}-{node_id}",
                source=f"jsfile-{ts['js_file_id']}",
                target=node_id,
            ))

        return GraphResponse(
            nodes=nodes,
            edges=edges,
            scope=scope,
            total_js_files=len(js_files),
            total_findings=len(findings),
        )

    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Findings list
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/scope/{scope}/findings")
def get_findings(
    scope: str,
    type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    include_whitelisted: bool = Query(False),
    verify_scope_only: bool = Query(False),  # show only test_only_hosts findings
    limit: int = Query(500, le=5000),
    offset: int = Query(0),
):
    """List findings for a scope with optional filters."""
    conn = get_connection(DB_PATH)
    try:
        query = """
            SELECT f.*, j.url as js_url, j.host, j.verify_scope
            FROM findings f
            JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ?
        """
        params: list = [scope]

        if type:
            query += " AND f.type = ?"
            params.append(type)
        if severity:
            query += " AND f.severity = ?"
            params.append(severity)
        if not include_whitelisted:
            query += " AND f.is_whitelisted = 0"
        if verify_scope_only:
            query += " AND j.verify_scope = 1"

        query += f" ORDER BY f.severity DESC, f.created_at DESC LIMIT {limit} OFFSET {offset}"

        rows = conn.execute(query, params).fetchall()
        return {"findings": [dict(r) for r in rows], "count": len(rows)}
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Scope stats
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/scope/{scope}/stats")
def get_scope_stats(scope: str):
    """Summary statistics for a scope."""
    conn = get_connection(DB_PATH)
    try:
        js_count = conn.execute(
            "SELECT COUNT(*) FROM js_files WHERE scope=?", (scope,)
        ).fetchone()[0]

        severity_counts = conn.execute(
            """
            SELECT f.severity, COUNT(*) as count
            FROM findings f JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ? AND f.is_whitelisted = 0
            GROUP BY f.severity
            """,
            (scope,)
        ).fetchall()

        type_counts = conn.execute(
            """
            SELECT f.type, COUNT(*) as count
            FROM findings f JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ? AND f.is_whitelisted = 0
            GROUP BY f.type
            """,
            (scope,)
        ).fetchall()

        tech_list = conn.execute(
            """
            SELECT DISTINCT ts.tech_name, MAX(ts.confidence) as confidence
            FROM tech_stack ts JOIN js_files j ON j.id = ts.js_file_id
            WHERE j.scope = ?
            GROUP BY ts.tech_name
            ORDER BY confidence DESC
            """,
            (scope,)
        ).fetchall()

        return {
            "scope": scope,
            "js_file_count": js_count,
            "severity_breakdown": {r["severity"]: r["count"] for r in severity_counts},
            "type_breakdown": {r["type"]: r["count"] for r in type_counts},
            "detected_tech": [{"name": r["tech_name"], "confidence": r["confidence"]} for r in tech_list],
        }
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# JS File detail
# ─────────────────────────────────────────────────────────────────────────────

def _enrich_advisories(advisories) -> list[dict]:
    """
    PRD 8s — Enrich advisory rows with sample_payloads + testing_steps.
    Parses sample_payloads JSON column, adds testing_steps + source_ref
    from XSS_ADVISOR_PAYLOADS dict (real-time lookup, not stored in DB).
    """
    import json as _json
    from src.xss_advisor.advisor import get_payloads_for_sink

    enriched = []
    for a in advisories:
        row = dict(a)
        sink_type = row.get("sink_type", "")

        # Parse sample_payloads JSON string → list
        raw_payloads = row.get("sample_payloads")
        if raw_payloads:
            try:
                row["sample_payloads"] = _json.loads(raw_payloads)
            except Exception:
                row["sample_payloads"] = []
        else:
            # Fallback: lookup fresh from dict if not stored yet
            payload_data = get_payloads_for_sink(sink_type)
            row["sample_payloads"] = payload_data["sample_payloads"]

        # Always enrich with testing_steps + source_ref + context (from dict)
        payload_data = get_payloads_for_sink(sink_type)
        row["testing_steps"] = payload_data["testing_steps"]
        row["source_ref"]    = payload_data["source_ref"]
        row["context"]       = payload_data["context"]

        enriched.append(row)
    return enriched

@app.get("/js-file/{file_id}")
def get_js_file(file_id: int):
    """Full detail for one JS file: metadata + findings + advisories."""
    conn = get_connection(DB_PATH)
    try:
        jsf = conn.execute(
            "SELECT id, url, host, scope, size_bytes, status, is_beautified, created_at "
            "FROM js_files WHERE id=?",
            (file_id,)
        ).fetchone()
        if not jsf:
            raise HTTPException(status_code=404, detail=f"JS file id={file_id} not found")

        findings = conn.execute(
            "SELECT * FROM findings WHERE js_file_id=? ORDER BY severity DESC",
            (file_id,)
        ).fetchall()

        advisories = conn.execute(
            """
            SELECT a.* FROM advisories a
            JOIN findings f ON f.id = a.finding_id
            WHERE f.js_file_id=?
            """,
            (file_id,)
        ).fetchall()

        tech = conn.execute(
            "SELECT tech_name, confidence, evidence FROM tech_stack WHERE js_file_id=?",
            (file_id,)
        ).fetchall()

        return {
            "js_file": dict(jsf),
            "findings": [dict(f) for f in findings],
            "advisories": _enrich_advisories(advisories),
            "tech_stack": [dict(t) for t in tech],
        }
    finally:
        conn.close()


@app.get("/js-file/{file_id}/content")
def get_js_content(file_id: int):
    """Return raw JS content for in-UI code viewer. Truncated at 500 KB for safety."""
    conn = get_connection(DB_PATH)
    try:
        row = conn.execute(
            "SELECT content, url, size_bytes FROM js_files WHERE id=?",
            (file_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"JS file id={file_id} not found")
        if row["content"] is None:
            return {"content": None, "message": "File was oversized_skipped, content not stored"}

        MAX_RETURN_BYTES = 500 * 1024
        content_bytes = row["content"][:MAX_RETURN_BYTES]
        content_str = content_bytes.decode("utf-8", errors="replace")
        return {
            "content": content_str,
            "url": row["url"],
            "size_bytes": row["size_bytes"],
            "truncated": row["size_bytes"] > MAX_RETURN_BYTES,
        }
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline triggers
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/extract/{scope}")
def trigger_extraction(scope: str, limit: Optional[int] = Query(None)):
    """Trigger extraction pipeline for a scope. Runs synchronously (blocking)."""
    try:
        summary = run_extraction(scope=scope, db_path=DB_PATH, limit=limit)
        return {"status": "done", "summary": summary}
    except Exception as exc:
        logger.error("Extraction failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/techstack/{scope}")
def trigger_tech_detection(scope: str):
    """Trigger tech detection for a scope."""
    try:
        summary = run_tech_detection(scope=scope, db_path=DB_PATH)
        return {"status": "done", "summary": summary}
    except Exception as exc:
        logger.error("Tech detection failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/advisor/{scope}")
def trigger_advisor(scope: str):
    """Trigger XSS advisor for a scope."""
    try:
        summary = run_xss_advisor(scope=scope, db_path=DB_PATH)
        return {"status": "done", "summary": summary}
    except Exception as exc:
        logger.error("XSS advisor failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Review Status (PRD 8p-1)
# ─────────────────────────────────────────────────────────────────────────────

@app.patch("/findings/{finding_id}/review")
def update_finding_review(finding_id: int, req: ReviewUpdateRequest):
    """
    PRD 8p-1 — Update review_status and optional review_note for a finding.
    This is the core workflow update: mark findings as checked_fp, confirmed_bug, etc.
    """
    conn = get_connection(DB_PATH)
    try:
        row = conn.execute(
            "SELECT id FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Finding id={finding_id} not found")

        if req.review_note is not None:
            conn.execute(
                "UPDATE findings SET review_status=?, review_note=? WHERE id=?",
                (req.review_status, req.review_note, finding_id),
            )
        else:
            conn.execute(
                "UPDATE findings SET review_status=? WHERE id=?",
                (req.review_status, finding_id),
            )
        conn.commit()
        return {"id": finding_id, "review_status": req.review_status, "updated": True}
    finally:
        conn.close()


@app.get("/scope/{scope}/review-summary")
def get_review_summary(scope: str):
    """
    PRD 8p-1 — Breakdown of review_status counts for a scope.
    Used in UI header bar to show 'unreviewed / confirmed_bug / ...' at a glance.
    """
    conn = get_connection(DB_PATH)
    try:
        rows = conn.execute(
            """
            SELECT f.review_status, COUNT(*) as count
            FROM findings f
            JOIN js_files j ON j.id = f.js_file_id
            WHERE j.scope = ? AND f.is_whitelisted = 0
            GROUP BY f.review_status
            """,
            (scope,)
        ).fetchall()
        breakdown = {r["review_status"]: r["count"] for r in rows}
        total = sum(breakdown.values())

        # Ensure all statuses present (0 for missing)
        all_statuses = ["unreviewed", "checked_fp", "checked_benign", "confirmed_bug", "reported"]
        for st in all_statuses:
            breakdown.setdefault(st, 0)

        return {
            "scope": scope,
            "total": total,
            "breakdown": breakdown,
        }
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# DB stats
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/db/stats")
def db_stats():
    """Overall DB statistics."""
    return get_db_stats(DB_PATH)
