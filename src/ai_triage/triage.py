"""
src/ai_triage/triage.py
PRD 8y — run_ai_triage(scope): orkestrasi AI triage per scope.

Alur (PRD 8y.5):
  init_db → SELECT finding unreviewed yang belum dinilai
          → batch per js_file (≤ max_findings_per_request)
          → LLM call (temperature=0) → validate (evidence gate, schema)
          → gagal validasi → 1 retry dengan pesan error → tetap gagal → skip
          → INSERT ai_assessments (idempoten: finding_id UNIQUE)

PRD 8z.2 hardening:
  - config error (env numerik malformed / key kosong) → summary error,
    TIDAK PERNAH exception (poin 1)
  - partial-batch rejection di-retry sekali sebagai sub-batch, hasil valid
    di-merge (poin 2)
  - content BLOB di-load lazy per file, bukan untuk semua row finding (poin 3)

Disiplin mantra_runner: modul ini TIDAK PERNAH melempar exception ke caller.
Semua kegagalan dikembalikan sebagai summary dict dengan status "error".
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.ai_triage.client import LLMError, chat_json
from src.ai_triage.config import (
    VENDOR_CLASSIFY_SIZE_CAP,
    load_config,
    missing_config_hint,
)
from src.ai_triage.prompt import build_messages, build_retry_messages, parse_model_json, validate_assessments
from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db

logger = logging.getLogger(__name__)

SEVERITY_ORDER_SQL = (
    "CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
    "WHEN 'low' THEN 2 WHEN 'info' THEN 3 ELSE 4 END"
)


def _select_findings(
    conn: sqlite3.Connection, scope: str, limit: int
) -> list[dict]:
    """
    Finding unreviewed yang belum punya ai_assessments, urut severity rank
    (CASE — bukan ORDER BY severity DESC yang alphabetical bug), lalu terbaru.
    """
    rows = conn.execute(
        f"""
        SELECT f.id, f.type, f.match_value, f.severity, f.snippet,
               f.target_url, f.resolved_url, f.is_whitelisted, f.review_status,
               f.source_hint,
               j.id AS js_file_id, j.url AS js_url, j.host,
               j.is_beautified, j.size_bytes
        FROM findings f
        JOIN js_files j ON f.js_file_id = j.id
        WHERE j.scope = ?
          AND f.review_status = 'unreviewed'
          AND f.id NOT IN (SELECT finding_id FROM ai_assessments)
        ORDER BY {SEVERITY_ORDER_SQL}, f.created_at DESC, f.id DESC
        LIMIT ?
        """,
        (scope, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _vendor_label(row: dict) -> str | None:
    """Classify ulang file kecil untuk kasih konteks vendor ke model (PRD 8y.4)."""
    content = row.get("content")
    size = row.get("size_bytes") or 0
    if not content or size > VENDOR_CLASSIFY_SIZE_CAP:
        return None
    try:
        from src.extraction.vendor_classifier import classify

        result = classify(row.get("js_url") or "", content, size)
        return result.label
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("vendor classify gagal untuk %s: %s", row.get("js_url"), exc)
        return None


def _load_file_content(
    conn: sqlite3.Connection, file_id: int, cache: dict[int, bytes | None]
) -> bytes | None:
    """
    Ambil content js_files untuk 1 file id — di-cache per run.

    PRD 8z.2 poin 3: content BLOB tidak lagi di-SELECT untuk SEMUA row
    finding (cukup 1x per file untuk vendor label); di-load lazy di sini.
    """
    if file_id not in cache:
        row = conn.execute(
            "SELECT content FROM js_files WHERE id = ?", (file_id,)
        ).fetchone()
        cache[file_id] = row["content"] if row else None
    return cache[file_id]


def _batch_by_file(
    conn: sqlite3.Connection,
    findings: list[dict],
    max_per_request: int,
) -> list[tuple[dict, list[dict], str | None]]:
    """
    Kelompokkan per js_file, pecah jadi batch ≤ max_per_request.
    Return list of (file_ctx, findings_in_batch, vendor_label).

    PRD 8z.2 poin 3: content file di-load lazy (cached) — hanya dibutuhkan
    untuk vendor label file pertama tiap grup (≤ VENDOR_CLASSIFY_SIZE_CAP).
    """
    files: dict[int, list[dict]] = {}
    for f in findings:
        files.setdefault(f["js_file_id"], []).append(f)

    content_cache: dict[int, bytes | None] = {}
    batches: list[tuple[dict, list[dict], str | None]] = []
    for file_findings in files.values():
        first = file_findings[0]
        file_ctx = {"url": first["js_url"], "host": first["host"]}
        content = _load_file_content(conn, first["js_file_id"], content_cache)
        label = _vendor_label({
            "js_url": first["js_url"],
            "size_bytes": first["size_bytes"],
            "content": content,
        })
        for start in range(0, len(file_findings), max_per_request):
            chunk = file_findings[start : start + max_per_request]
            batches.append((file_ctx, chunk, label))
    return batches


def _filter_to_refs(data: dict, refs: set[str]) -> dict:
    """
    Saring assessments ke ref tertentu saja (PRD 8z.2 poin 2).

    Dipakai di round partial-retry: ref yang sudah valid di round sebelumnya
    tidak dinilai ulang — hanya sisa yang ditolak yang divalidasi ulang.
    """
    items = data.get("assessments")
    if not isinstance(items, list):
        return data
    return {
        **data,
        "assessments": [
            it for it in items
            if isinstance(it, dict) and it.get("ref") in refs
        ],
    }


def _assess_batch(
    batch: tuple[dict, list[dict], str | None],
    *,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout: float,
) -> tuple[list[dict], list[str], dict[str, int], bool]:
    """
    Proses satu batch: call LLM → validate → retry. Total attempt ≤ 2.

    PRD 8z.2 poin 2 — partial-batch retry: batch yang sebagian valid dan
    sebagian ditolak TIDAK langsung selesai (dulu: ref yang ditolak
    permanen ke-skip sampai --force). Sekarang ref yang ditolak di-retry
    SEKALI sebagai sub-batch via build_retry_messages dengan error spesifik
    per-ref; hanya ref itu yang di-validasi ulang; hasil valid di-merge.
    Kalau sub-retry tetap gagal → skip seperti sebelumnya (disiplin sama).

    Returns:
        (valid_rows, errors, token_usage, used_retry)
        valid_rows : semua row valid (round pertama + hasil merge retry)
        errors     : error batch-level (LLM call / JSON parse) + error per-ref
                     yang TETAP ditolak setelah round terakhir (kosong kalau
                     semua ref akhirnya valid)
        used_retry : True kalau round retry (full ATAU parsial) pernah jalan
    """
    file_ctx, chunk, label = batch

    ref_to_finding: dict[str, dict] = {}
    for i, f in enumerate(chunk):
        f["ref"] = f"F{i}"
        ref_to_finding[f["ref"]] = f

    messages = build_messages(file_ctx["url"], file_ctx["host"], chunk, label)

    usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    used_retry = False
    batch_errors: list[str] = []   # batch-level: LLM call / JSON parse
    merged_valid: list[dict] = []
    # PRD 8z.2 poin 2 — ref yang belum valid; awalnya semua, menyusut tiap
    # round. Round retry cuma menilai ulang sisa ini.
    pending_refs: set[str] = set(ref_to_finding)

    for attempt in range(2):
        try:
            raw, usage = chat_json(
                base_url=base_url,
                api_key=api_key,
                model=model,
                messages=messages,
                temperature=temperature,
                timeout=timeout,
            )
        except LLMError as exc:
            batch_errors.append(f"LLM call gagal: {exc}")
            return merged_valid, batch_errors, usage_total, used_retry

        for k in usage_total:
            usage_total[k] += usage.get(k, 0)

        try:
            data = parse_model_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            errors = [f"JSON parse gagal: {exc}"]
            if attempt == 0:
                messages = build_retry_messages(messages, raw, errors)
                used_retry = True
                continue
            return merged_valid, batch_errors + errors, usage_total, used_retry

        # PRD 8z.2 poin 2 — round retry hanya menilai ulang ref yang masih
        # pending; jawaban untuk ref yang sudah valid diabaikan (tidak
        # di-merge dobel — finding_id UNIQUE).
        if attempt == 1:
            data = _filter_to_refs(data, pending_refs)

        valid_rows, errors = validate_assessments(data, ref_to_finding)

        answered = {
            r.get("ref") for r in data.get("assessments", []) if isinstance(r, dict)
        }
        missing = pending_refs - answered
        if missing:
            errors = errors + [f"finding tanpa assessment: {sorted(missing)}"]

        merged_valid.extend(valid_rows)
        valid_ids = {row["finding_id"] for row in valid_rows}
        pending_refs -= {
            ref for ref, f in ref_to_finding.items() if f["id"] in valid_ids
        }

        if not pending_refs:
            # Semua ref akhirnya valid — error round ini tidak relevan lagi.
            return merged_valid, batch_errors, usage_total, used_retry

        if attempt == 0:
            # PRD 8z.2 poin 2 — satu round retry (full kalau semua ditolak,
            # parsial kalau sebagian sudah valid) dengan error per-ref.
            messages = build_retry_messages(messages, raw, errors)
            used_retry = True
            continue

        # attempt == 1 dan masih ada pending → skip permanen (disiplin lama)
        return merged_valid, batch_errors + errors, usage_total, used_retry

    return merged_valid, batch_errors, usage_total, used_retry  # pragma: no cover


def run_ai_triage(
    scope: str,
    db_path: str | Path = DEFAULT_DB_PATH,
    limit: int = 50,
    force: bool = False,
) -> dict:
    """
    PRD 8y entry point. Nilai finding unreviewed di `scope` pakai LLM.

    Args:
        scope  : nama scope (kolom js_files.scope)
        db_path: path SQLite
        limit  : max finding yang diproses run ini
        force  : True = hapus assessment lama di scope ini dulu (re-triage)

    Returns:
        Summary dict — TIDAK PERNAH raise (disiplin mantra_runner).
    """
    # PRD 8z.2 poin 1 — config DI DALAM alur error-handling: env numerik
    # malformed TIDAK PERNAH jadi exception (dulu: JXS_AI_TIMEOUT=abc →
    # uncaught ValueError → HTTP 500). Key kosong → hint lengkap;
    # env malformed → pesan per-var dari config_errors.
    try:
        cfg = load_config()
    except Exception as exc:  # pylint: disable=broad-except  (defensif — load_config sendiri sudah never-raise)
        logger.error("load_config unexpected error: %s", exc)
        return {"status": "error", "error": f"config error: {exc}"}

    if not cfg.is_configured:
        error_parts: list[str] = []
        if not cfg.api_key:
            error_parts.append(missing_config_hint())
        error_parts.extend(cfg.config_errors)
        return {"status": "error", "error": "\n".join(error_parts)}

    summary: dict = {
        "status": "done",
        "scope": scope,
        "model": cfg.model,
        "base_url": cfg.base_url,
        "assessed": 0,
        "rejected": 0,
        "batches": 0,
        "retried_batches": 0,
        "failed_batches": 0,
        "tokens": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "errors": [],
    }

    try:
        init_db(db_path)
        conn = get_connection(db_path)
    except Exception as exc:  # pylint: disable=broad-except
        summary["status"] = "error"
        summary["error"] = f"DB tidak bisa dibuka: {exc}"
        return summary

    try:
        if force:
            deleted = conn.execute(
                """
                DELETE FROM ai_assessments
                WHERE finding_id IN (
                    SELECT f.id FROM findings f
                    JOIN js_files j ON f.js_file_id = j.id
                    WHERE j.scope = ?
                )
                """,
                (scope,),
            ).rowcount
            conn.commit()
            summary["forced_retriage_deleted"] = deleted

        findings = _select_findings(conn, scope, limit)
        if not findings:
            summary["note"] = (
                "tidak ada finding unreviewed yang belum dinilai "
                "(semua sudah assessed / tidak ada finding)"
            )
            return summary

        batches = _batch_by_file(conn, findings, cfg.max_findings_per_request)
        summary["batches"] = len(batches)

        for batch in batches:
            valid_rows, errors, usage, used_retry = _assess_batch(
                batch,
                api_key=cfg.api_key,
                base_url=cfg.base_url,
                model=cfg.model,
                temperature=cfg.temperature,
                timeout=cfg.timeout,
            )

            for k in summary["tokens"]:
                summary["tokens"][k] += usage.get(k, 0)
            if used_retry:
                summary["retried_batches"] += 1

            if valid_rows:
                conn.executemany(
                    """
                    INSERT INTO ai_assessments
                        (finding_id, priority, category, summary,
                         evidence_quote, recommended_checks, confidence, model)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        priority=excluded.priority,
                        category=excluded.category,
                        summary=excluded.summary,
                        evidence_quote=excluded.evidence_quote,
                        recommended_checks=excluded.recommended_checks,
                        confidence=excluded.confidence,
                        model=excluded.model,
                        created_at=datetime('now')
                    """,
                    [
                        (
                            r["finding_id"], r["priority"], r["category"],
                            r["summary"], r["evidence_quote"],
                            r["recommended_checks"], r["confidence"], cfg.model,
                        )
                        for r in valid_rows
                    ],
                )
                conn.commit()
                summary["assessed"] += len(valid_rows)

            if errors:
                summary["rejected"] += len(batch[1]) - len(valid_rows)
                if not valid_rows:
                    summary["failed_batches"] += 1
                for e in errors[:3]:
                    summary["errors"].append(e[:300])
                logger.warning(
                    "batch %s: %d valid, %d ditolak — %s",
                    batch[0]["url"][:80], len(valid_rows),
                    len(batch[1]) - len(valid_rows), errors[:2],
                )

        return summary

    except Exception as exc:  # pylint: disable=broad-except
        logger.error("run_ai_triage unexpected error: %s", exc)
        summary["status"] = "error"
        summary["error"] = str(exc)
        return summary
    finally:
        try:
            conn.close()
        except Exception:  # pylint: disable=broad-except
            pass
