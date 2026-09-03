"""
src/ai_triage/prompt.py
PRD 8y.1 — prompt builder + output validation (correctness gates).

Gate yang diverifikasi programatik (bukan berharap model jujur):
  1. Output harus JSON valid dengan shape {"assessments": [...]}
  2. Setiap assessment harus punya `ref` yang ada di batch
  3. `priority` integer 1..5, `category` di enum terkunci, `confidence` 0..1
  4. `evidence_quote` HARUS substring dari snippet finding terkait
  5. `recommended_checks` array of string, tanpa instruksi auto-fire

Assessment yang gagal gate → tidak ditulis ke DB. Batch yang gagal total
setelah 1 retry → di-skip dengan warning (disiplin mantra_runner).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.ai_triage.config import MAX_SNIPPET_CHARS

# ─────────────────────────────────────────────────────────────────────────────
# Enum terkunci (PRD 8y.4)
# ─────────────────────────────────────────────────────────────────────────────

CATEGORIES: frozenset[str] = frozenset({
    "auth_bypass_candidate",
    "idor_bac_candidate",
    "secret_exposure",
    "sensitive_endpoint",
    "debug_artifact",
    "xss_exploitable",
    "xss_defensive",
    "config_leak",
    "sourcemap_exposure",
    "vendor_noise",
    "benign",
    "other",
})

MAX_EVIDENCE_QUOTE_CHARS = 300
MAX_CHECKS = 6
MAX_CHECK_CHARS = 300

SYSTEM_PROMPT = """\
You are a bug-bounty triage assistant inside `jxs`, a regex-based JS \
analysis tool. You receive findings already extracted by regex (never raw \
bundles): each has a ref, a type, the matched string, a code snippet, and \
URL context. Your job is PRIORITIZATION, not verdicts.

For EVERY finding you must output exactly one assessment object:
- "ref": the finding ref, copied unchanged
- "priority": integer 1..5 — 1 = test first (high report value), \
2 = worth testing soon, 3 = keep for later, 4 = probably benign, \
5 = vendor/library noise
- "category": exactly one of:
  auth_bypass_candidate, idor_bac_candidate, secret_exposure, \
sensitive_endpoint, debug_artifact, xss_exploitable, xss_defensive, \
config_leak, sourcemap_exposure, vendor_noise, benign, other
- "summary": 1-2 sentences, casual Indonesian (gaya dev Indonesia ngobrol), \
istilah teknis tetap English
- "evidence_quote": a substring copied EXACTLY (character-for-character) \
from that finding's "snippet" field — the specific code that justifies \
your assessment. Never paraphrase, never invent code.
- "recommended_checks": array of 0-6 short manual verification steps \
(casual Indonesian). Steps are instructions for the HUMAN to perform in \
browser/Burp/DevTools. Never include instructions to automate attacks or \
auto-fire payloads.
- "confidence": float 0..1 — how sure you are in your own assessment

Hard rules:
1. Only judge what is visible in the snippet and context. If context is \
insufficient, use priority 3, category "other", and low confidence.
2. The evidence_quote MUST be a substring of that finding's snippet. \
Double-check character-by-character before answering.
3. A "High" regex severity does NOT mean priority 1 — vendor libraries, \
defensive code, and internal config commonly produce High regex matches \
that are priority 4-5. Your added value is telling them apart.
4. Do NOT change severity or review status. You output hints only; the \
human decides via the validation checklist.
5. Respond with STRICT JSON only — no markdown fences, no commentary. \
Shape: {"assessments": [ ...one object per input finding... ]}"""


def _finding_context(finding: dict[str, Any], vendor_label: str | None) -> dict[str, Any]:
    """Susun konteks 1 finding untuk prompt — semua field dari DB, tanpa karangan."""
    snippet = (finding.get("snippet") or "")[:MAX_SNIPPET_CHARS]
    ctx: dict[str, Any] = {
        "ref": finding["ref"],
        "type": finding.get("type"),
        "match_value": (finding.get("match_value") or "")[:500],
        "severity": finding.get("severity"),
        "snippet": snippet,
        "target_url": finding.get("target_url"),
        "js_url": finding.get("js_url"),
        "host": finding.get("host"),
        "is_whitelisted": bool(finding.get("is_whitelisted")),
        "review_status": finding.get("review_status"),
    }
    if vendor_label is not None:
        ctx["vendor_label"] = vendor_label
    return ctx


def build_messages(
    file_url: str,
    file_host: str,
    findings: list[dict[str, Any]],
    vendor_label: str | None,
) -> list[dict[str, str]]:
    """Bangun [system, user] messages untuk satu batch (satu js_file)."""
    payload = {
        "js_file": {"url": file_url, "host": file_host},
        "vendor_label": vendor_label,
        "findings": [_finding_context(f, vendor_label) for f in findings],
    }
    user_prompt = (
        "Nilai findings berikut. Balas STRICT JSON sesuai instruksi system.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def build_retry_messages(
    messages: list[dict[str, str]],
    raw_response: str,
    errors: list[str],
) -> list[dict[str, str]]:
    """Retry batch: lampirkan error validasi supaya model memperbaiki dirinya."""
    error_block = "\n".join(f"- {e}" for e in errors[:10])
    fixed = messages + [
        {"role": "assistant", "content": raw_response[:8000]},
        {
            "role": "user",
            "content": (
                "Output kamu GAGAL validasi:\n" + error_block +
                "\n\nPerbaiki dan balas ULANG strict JSON penuh dengan shape yang "
                "sama. Ingat: evidence_quote harus substring EXACT dari snippet."
            ),
        },
    ]
    return fixed


# ─────────────────────────────────────────────────────────────────────────────
# Validation — correctness gates
# ─────────────────────────────────────────────────────────────────────────────

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def parse_model_json(raw: str) -> dict[str, Any]:
    """Parse output model → dict. Toleran terhadap markdown fence."""
    text = _FENCE_RE.sub("", raw.strip()).strip()
    # fallback: ambil blok { ... } terluar jika ada prose di sekeliling
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        text = text[start : end + 1]
    data = json.loads(text)  # ValueError propagates ke caller
    if not isinstance(data, dict):
        raise ValueError("top-level JSON bukan object")
    return data


def validate_assessments(
    data: dict[str, Any],
    ref_to_finding: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Validasi seluruh assessments. Return (valid_rows, errors).

    valid_rows berisi dict siap-insert ke ai_assessments. Row yang gagal
    gate tidak pernah masuk valid_rows (all-or-nothing per row, bukan per batch).
    """
    errors: list[str] = []
    valid: list[dict[str, Any]] = []

    items = data.get("assessments")
    if not isinstance(items, list):
        return [], ["field 'assessments' tidak ada / bukan array"]

    seen_refs: set[str] = set()
    for idx, item in enumerate(items):
        label = f"assessments[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{label}: bukan object")
            continue

        ref = item.get("ref")
        if ref not in ref_to_finding:
            errors.append(f"{label}: ref {ref!r} tidak ada di batch")
            continue
        if ref in seen_refs:
            errors.append(f"{label}: ref {ref!r} duplikat")
            continue

        finding = ref_to_finding[ref]
        snippet = finding.get("snippet") or ""

        priority = item.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool) or not 1 <= priority <= 5:
            errors.append(f"{label} ({ref}): priority {priority!r} bukan integer 1..5")
            continue

        category = item.get("category")
        if category not in CATEGORIES:
            errors.append(f"{label} ({ref}): category {category!r} di luar enum")
            continue

        summary = item.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            errors.append(f"{label} ({ref}): summary kosong")
            continue

        evidence = item.get("evidence_quote")
        if not isinstance(evidence, str) or not evidence.strip():
            errors.append(f"{label} ({ref}): evidence_quote kosong")
            continue
        evidence = evidence.strip()[:MAX_EVIDENCE_QUOTE_CHARS]
        # ── EVIDENCE GATE (PRD 8y.1 point 1) ────────────────────────────────
        if evidence not in snippet:
            errors.append(
                f"{label} ({ref}): evidence_quote BUKAN substring snippet — "
                f"model mengutip kode yang tidak ada di input (REJECTED)"
            )
            continue

        confidence = item.get("confidence")
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0.0 <= float(confidence) <= 1.0
        ):
            errors.append(f"{label} ({ref}): confidence {confidence!r} di luar 0..1")
            continue

        raw_checks = item.get("recommended_checks", [])
        if not isinstance(raw_checks, list):
            errors.append(f"{label} ({ref}): recommended_checks bukan array")
            continue
        checks = [
            c.strip()[:MAX_CHECK_CHARS]
            for c in raw_checks
            if isinstance(c, str) and c.strip()
        ][:MAX_CHECKS]

        seen_refs.add(ref)
        valid.append({
            "finding_id": finding["id"],
            "priority": priority,
            "category": category,
            "summary": summary.strip()[:2000],
            "evidence_quote": evidence,
            "recommended_checks": json.dumps(checks, ensure_ascii=False),
            "confidence": round(float(confidence), 3),
        })

    return valid, errors
