"""
tests/test_ai_triage.py
PRD 8z.2 poin 3 — test suite untuk modul AI triage. NOL akses network.

Cakupan (PRD 8z.6 poin 1 / 8z.2):
  - validate_assessments : evidence gate (quote fabrikasi → ditolak),
                           priority bool/out-of-range, category di luar enum,
                           ref duplikat/asing, normalisasi recommended_checks
  - parse_model_json     : markdown fence, prose di depan, JSON murni
  - chat_json            : via httpx.MockTransport — 429 → retry sukses,
                           401 → LLMError langsung, 5xx 2x → sukses dalam
                           budget retry, respons >1MB → LLMError
  - run_ai_triage        : end-to-end dengan chat_json di-stub (idempoten,
                           partial-retry, env numerik malformed, key kosong)

Disiplin: semua env JXS_AI_* di-set via monkeypatch.setenv — deterministic,
tidak tergantung env mesin; stub LLM tidak pernah buka socket.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
import pytest

from src.ai_triage.client import LLMError, chat_json
from src.ai_triage.config import load_config, missing_config_hint
from src.ai_triage.prompt import (
    MAX_CHECKS,
    build_messages,
    parse_model_json,
    validate_assessments,
)
from src.ai_triage.triage import run_ai_triage
from src.db.schema import get_connection, init_db

SCOPE = "testscope"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers + fixtures
# ─────────────────────────────────────────────────────────────────────────────

SNIPPET = "el.innerHTML = params.get('q');"
EVIDENCE = "params.get('q')"   # substring EXACT dari SNIPPET


def _make_finding(fid: int, snippet: str = SNIPPET) -> dict:
    """Finding dict seperti hasil _select_findings (minimal field yg dipakai)."""
    return {
        "id": fid,
        "type": "dom_sink",
        "match_value": "innerHTML",
        "severity": "high",
        "snippet": snippet,
        "target_url": "http://example.com/app.js",
        "resolved_url": "http://example.com/app.js",
        "is_whitelisted": 0,
        "review_status": "unreviewed",
        "js_file_id": 1,
        "js_url": "http://example.com/app.js",
        "host": "example.com",
    }


def _valid_assessment(ref: str, **overrides) -> dict:
    """Assessment output-model yang lolos semua gate."""
    base = {
        "ref": ref,
        "priority": 1,
        "category": "xss_exploitable",
        "summary": "sink innerHTML dapet input dari query param",
        "evidence_quote": EVIDENCE,
        "recommended_checks": ["cek manual di browser"],
        "confidence": 0.9,
    }
    base.update(overrides)
    return base


def _llm_body(content: str, usage: dict | None = None) -> dict:
    """Body respons OpenAI-compatible minimal."""
    return {
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.fixture
def tmp_db(tmp_path):
    """DB temp fresh + schema + migrasi (init_db idempoten)."""
    db = tmp_path / "test_triage.db"
    init_db(db)
    return db


@pytest.fixture
def seeded_db(tmp_db):
    """DB temp dengan 1 js_files + 2 findings unreviewed (scope=SCOPE)."""
    content = b"el.innerHTML = params.get('q');"
    conn = get_connection(tmp_db)
    try:
        cur = conn.execute(
            "INSERT INTO js_files (url, host, scope, content_hash, content, size_bytes, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'extracted')",
            (
                "http://example.com/app.js",
                "example.com",
                SCOPE,
                hashlib.sha256(content + uuid.uuid4().bytes).hexdigest(),
                content,
                len(content),
            ),
        )
        js_id = cur.lastrowid
        for _ in range(2):
            conn.execute(
                "INSERT INTO findings (js_file_id, type, match_value, severity, "
                "line_number, snippet, is_whitelisted, resolved_url, target_url, "
                "review_status, source_hint) "
                "VALUES (?, 'dom_sink', 'innerHTML', 'high', 1, ?, 0, "
                "'http://example.com/app.js', 'http://example.com/app.js', "
                "'unreviewed', 'likely_tainted')",
                (js_id, SNIPPET),
            )
        conn.commit()
    finally:
        conn.close()
    return tmp_db


@pytest.fixture
def ai_env(monkeypatch):
    """Env JXS_AI_* deterministik — key diset, sisanya dihapus."""
    monkeypatch.setenv("JXS_AI_API_KEY", "test-key-123")
    monkeypatch.setenv("JXS_AI_BASE_URL", "http://mock.local/v1")
    monkeypatch.setenv("JXS_AI_MODEL", "test-model")
    for var in ("JXS_AI_TIMEOUT", "JXS_AI_MAX_FINDINGS_PER_REQUEST", "JXS_AI_TEMPERATURE"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _stub_chat(responses: list[str], calls: list[dict]):
    """
    Stub chat_json: balikin responses berurutan, catat kwargs tiap call.
    Return fungsi dengan signature sama seperti chat_json (kwargs-only).
    """
    def _stub(**kwargs):
        calls.append(kwargs)
        if len(calls) > len(responses):
            raise AssertionError(f"chat_json dipanggil {len(calls)}x (budget {len(responses)})")
        return responses[len(calls) - 1], {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    return _stub


# ─────────────────────────────────────────────────────────────────────────────
# validate_assessments — correctness gates (PRD 8y.1 / 8z.2 poin 3)
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateAssessments:
    def setup_method(self):
        self.finding = _make_finding(1)
        self.ref_map = {"F0": self.finding}

    def test_fabricated_evidence_quote_rejected(self):
        """PRD 8y.1 evidence gate — quote yang tidak ada di snippet DITOLAK."""
        data = {"assessments": [
            _valid_assessment("F0", evidence_quote="kode yang tidak ada 100% di snippet"),
        ]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert valid == []
        assert any("BUKAN substring" in e for e in errors)

    def test_priority_bool_rejected(self):
        """bool True adalah instance int — harus ditolak eksplisit."""
        data = {"assessments": [_valid_assessment("F0", priority=True)]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert valid == []
        assert any("priority" in e for e in errors)

    def test_priority_out_of_range_rejected(self):
        for bad in (6, 0):
            data = {"assessments": [_valid_assessment("F0", priority=bad)]}
            valid, errors = validate_assessments(data, self.ref_map)
            assert valid == [], f"priority={bad} harus ditolak"
            assert any("bukan integer 1..5" in e for e in errors)

    def test_unknown_category_rejected(self):
        data = {"assessments": [_valid_assessment("F0", category="totally_made_up")]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert valid == []
        assert any("di luar enum" in e for e in errors)

    def test_duplicate_ref_second_rejected(self):
        """Ref yang sama dijawab 2x → row pertama valid, kedua ditolak."""
        data = {"assessments": [
            _valid_assessment("F0"),
            _valid_assessment("F0", priority=2, summary="duplikat"),
        ]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert len(valid) == 1
        assert any("duplikat" in e for e in errors)

    def test_unknown_ref_rejected(self):
        data = {"assessments": [_valid_assessment("F99")]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert valid == []
        assert any("tidak ada di batch" in e for e in errors)

    def test_valid_row_passes_and_checks_normalized(self):
        """Row valid lolos; recommended_checks dinormalisasi (strip, cap 6/300)."""
        checks = [f"langkah verifikasi ke-{i}" for i in range(10)]  # 10 > MAX_CHECKS
        data = {"assessments": [_valid_assessment("F0", recommended_checks=checks)]}
        valid, errors = validate_assessments(data, self.ref_map)
        assert errors == []
        assert len(valid) == 1
        row = valid[0]
        assert row["finding_id"] == 1
        assert row["priority"] == 1
        assert row["confidence"] == 0.9
        stored = json.loads(row["recommended_checks"])
        assert isinstance(stored, list)
        assert len(stored) == MAX_CHECKS          # dipotong ke 6
        assert stored[0] == "langkah verifikasi ke-0"
        assert row["evidence_quote"] == EVIDENCE  # exact substring, tidak diubah

    def test_empty_assessments_field(self):
        valid, errors = validate_assessments({}, self.ref_map)
        assert valid == []
        assert any("bukan array" in e for e in errors)


# ─────────────────────────────────────────────────────────────────────────────
# parse_model_json (PRD 8y.1 / 8z.2 poin 3)
# ─────────────────────────────────────────────────────────────────────────────

class TestParseModelJson:
    def test_json_fenced_block(self):
        raw = "```json\n" + json.dumps({"assessments": []}) + "\n```"
        assert parse_model_json(raw) == {"assessments": []}

    def test_json_with_leading_prose(self):
        raw = "Berikut hasilnya ya:\n" + json.dumps({"assessments": [1, 2]})
        assert parse_model_json(raw) == {"assessments": [1, 2]}

    def test_pure_json(self):
        raw = json.dumps({"assessments": [{"ref": "F0"}]})
        assert parse_model_json(raw) == {"assessments": [{"ref": "F0"}]}

    def test_invalid_json_raises(self):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            parse_model_json("ini bukan json sama sekali")


# ─────────────────────────────────────────────────────────────────────────────
# chat_json via httpx.MockTransport — retry semantics (PRD 8y.2 / 8z.2 poin 3)
# ─────────────────────────────────────────────────────────────────────────────

class TestChatJsonMockTransport:
    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        """Skip backoff sleep supaya test cepat (retry logic tetap jalan)."""
        monkeypatch.setattr(time, "sleep", lambda s: None)

    @staticmethod
    def _kwargs(transport):
        return dict(
            base_url="http://mock.local/v1",
            api_key="test-key",
            model="test-model",
            messages=[{"role": "user", "content": "nilai finding ini"}],
            temperature=0.0,
            timeout=5.0,
            transport=transport,
        )

    def test_429_then_200_succeeds_after_retry(self):
        """429 retryable → attempt kedua 200 → sukses, tepat 2 request."""
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) == 1:
                return httpx.Response(429, json={"error": "rate limited"})
            return httpx.Response(200, json=_llm_body('{"assessments": []}'))

        content, usage = chat_json(**self._kwargs(httpx.MockTransport(handler)))
        assert content == '{"assessments": []}'
        assert usage["total_tokens"] == 15
        assert len(calls) == 2, f"harus tepat 2 request, dapat {len(calls)}"

    def test_401_raises_immediately(self):
        """401 non-retryable → LLMError langsung, TANPA retry (1 request)."""
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(401, json={"error": "bad key"})

        with pytest.raises(LLMError, match="HTTP 401"):
            chat_json(**self._kwargs(httpx.MockTransport(handler)))
        assert len(calls) == 1, f"401 tidak boleh retry, dapat {len(calls)} request"

    def test_5xx_twice_then_success(self):
        """5xx 2x → sukses di attempt ke-3 (masih dalam budget retry)."""
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            if len(calls) <= 2:
                return httpx.Response(503, text="upstream down")
            return httpx.Response(200, json=_llm_body('{"ok": true}'))

        content, _ = chat_json(**self._kwargs(httpx.MockTransport(handler)))
        assert content == '{"ok": true}'
        assert len(calls) == 3  # RETRY_BACKOFF_SECONDS=(1.0, 2.5) → 3 attempt

    def test_oversized_response_rejected(self):
        """Respons > 1MB (MAX_RESPONSE_CHARS) → LLMError (sanity cap)."""
        big = "x" * 1_000_001
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json=_llm_body(big))

        with pytest.raises(LLMError, match="terlalu besar"):
            chat_json(**self._kwargs(httpx.MockTransport(handler)))
        assert len(calls) == 1  # non-retryable — langsung raise


# ─────────────────────────────────────────────────────────────────────────────
# load_config — never-raise contract (PRD 8z.2 poin 1)
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_valid_env_configured(self, ai_env):
        cfg = load_config()
        assert cfg.is_configured is True
        assert cfg.config_errors == []
        assert cfg.timeout == 90.0
        assert cfg.max_findings_per_request == 15

    def test_malformed_timeout_no_raise(self, ai_env):
        """JXS_AI_TIMEOUT=abc → TIDAK raise; error jelas + contoh format."""
        ai_env.setenv("JXS_AI_TIMEOUT", "abc")
        cfg = load_config()  # tidak boleh raise
        assert cfg.is_configured is False
        assert len(cfg.config_errors) == 1
        assert "JXS_AI_TIMEOUT='abc'" in cfg.config_errors[0]
        assert "export JXS_AI_TIMEOUT=90.0" in cfg.config_errors[0]
        assert cfg.timeout == 90.0  # fallback default supaya field tetap valid

    def test_empty_key_not_configured(self, ai_env):
        ai_env.setenv("JXS_AI_API_KEY", "  ")
        cfg = load_config()
        assert cfg.is_configured is False
        assert cfg.config_errors == []


# ─────────────────────────────────────────────────────────────────────────────
# run_ai_triage end-to-end — chat_json di-stub, NOL network (PRD 8z.2 poin 3)
# ─────────────────────────────────────────────────────────────────────────────

class TestRunAiTriage:
    def test_all_valid_then_idempotent(self, seeded_db, ai_env, monkeypatch):
        """(a) 2 finding valid → assessed==2; run ke-2 → 0 + note (idempoten)."""
        payload = json.dumps({"assessments": [
            _valid_assessment("F0", priority=1),
            _valid_assessment("F1", priority=2, category="xss_defensive"),
        ]})
        calls: list[dict] = []
        monkeypatch.setattr(
            "src.ai_triage.triage.chat_json", _stub_chat([payload], calls)
        )

        result = run_ai_triage(SCOPE, db_path=seeded_db)
        assert result["status"] == "done"
        assert result["assessed"] == 2
        assert result["rejected"] == 0
        assert result["failed_batches"] == 0
        assert result["retried_batches"] == 0
        assert result["errors"] == []
        assert len(calls) == 1

        conn = get_connection(seeded_db)
        try:
            rows = conn.execute(
                "SELECT priority, evidence_quote FROM ai_assessments"
            ).fetchall()
            assert sorted(r["priority"] for r in rows) == [1, 2]
            assert all(r["evidence_quote"] == EVIDENCE for r in rows)
        finally:
            conn.close()

        # Run kedua — idempoten: semua sudah assessed → 0 baru + note
        result2 = run_ai_triage(SCOPE, db_path=seeded_db)
        assert result2["status"] == "done"
        assert result2["assessed"] == 0
        assert "note" in result2
        assert len(calls) == 1  # tidak ada LLM call baru

    def test_partial_rejection_retried_and_merged(self, seeded_db, ai_env, monkeypatch):
        """(b) F1 evidence fabrikasi → partial-retry round → F1 tetap masuk DB."""
        bad_payload = json.dumps({"assessments": [
            _valid_assessment("F0", priority=1),
            _valid_assessment(
                "F1",
                priority=2,
                category="xss_defensive",
                evidence_quote="quote yang tidak pernah ada di snippet",
            ),
        ]})
        fixed_payload = json.dumps({"assessments": [
            _valid_assessment("F1", priority=2, category="xss_defensive"),
        ]})
        calls: list[dict] = []
        monkeypatch.setattr(
            "src.ai_triage.triage.chat_json",
            _stub_chat([bad_payload, fixed_payload], calls),
        )

        result = run_ai_triage(SCOPE, db_path=seeded_db)
        assert result["status"] == "done"
        assert result["assessed"] == 2, "F1 harus selamat lewat partial-retry"
        assert result["retried_batches"] >= 1
        assert result["failed_batches"] == 0
        assert len(calls) == 2, "harus ada call pertama + 1 partial-retry"

        # Retry round cuma menilai ulang ref yang ditolak — pesan retry
        # harus memuat error per-ref (evidence gate) dari round pertama
        retry_user_msg = calls[1]["messages"][-1]["content"]
        assert "GAGAL validasi" in retry_user_msg
        assert "BUKAN substring" in retry_user_msg

        conn = get_connection(seeded_db)
        try:
            rows = conn.execute(
                "SELECT finding_id, priority FROM ai_assessments"
            ).fetchall()
            assert len(rows) == 2  # kedua finding landa di DB
            assert sorted(r["priority"] for r in rows) == [1, 2]
        finally:
            conn.close()

    def test_malformed_timeout_returns_error_summary(self, seeded_db, ai_env):
        """(c) JXS_AI_TIMEOUT=abc → status error, TANPA exception (PRD 8z.6 poin 2)."""
        ai_env.setenv("JXS_AI_TIMEOUT", "abc")
        result = run_ai_triage(SCOPE, db_path=seeded_db)  # tidak boleh raise
        assert result["status"] == "error"
        assert "JXS_AI_TIMEOUT='abc'" in result["error"]
        assert "export JXS_AI_TIMEOUT=90.0" in result["error"]

        # tidak ada row tertulis
        conn = get_connection(seeded_db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM ai_assessments").fetchone()[0]
            assert count == 0
        finally:
            conn.close()

    def test_empty_api_key_error_no_rows(self, seeded_db, ai_env, monkeypatch):
        """(d) key kosong → status error + hint, tanpa row baru, tanpa LLM call."""
        ai_env.setenv("JXS_AI_API_KEY", "")
        calls: list[dict] = []
        monkeypatch.setattr(
            "src.ai_triage.triage.chat_json",
            _stub_chat(["SHOULD NOT BE CALLED"], calls),
        )

        result = run_ai_triage(SCOPE, db_path=seeded_db)
        assert result["status"] == "error"
        assert "JXS_AI_API_KEY belum diset" in result["error"]
        assert calls == [], "LLM tidak boleh dipanggil kalau key kosong"

        conn = get_connection(seeded_db)
        try:
            count = conn.execute("SELECT COUNT(*) FROM ai_assessments").fetchone()[0]
            assert count == 0
        finally:
            conn.close()
        assert missing_config_hint()  # hint tetap tersedia untuk API layer


# ─────────────────────────────────────────────────────────────────────────────
# Prompt context — source_hint diteruskan ke model (PRD 8z.1)
# ─────────────────────────────────────────────────────────────────────────────

class TestPromptSourceHint:
    def test_source_hint_passed_through(self):
        finding = _make_finding(1)
        finding["ref"] = "F0"           # ref di-set oleh _assess_batch
        finding["source_hint"] = "likely_tainted"
        messages = build_messages("http://example.com/app.js", "example.com", [finding], None)
        assert messages[0]["role"] == "system"
        assert "source_hint" in messages[0]["content"]
        assert "NOT taint analysis" in messages[0]["content"]
        user_payload = json.loads(messages[1]["content"].split("\n\n", 1)[1])
        assert user_payload["findings"][0]["source_hint"] == "likely_tainted"

    def test_source_hint_none_is_null(self):
        finding = _make_finding(1)
        finding["ref"] = "F0"           # ref di-set oleh _assess_batch
        finding["source_hint"] = None   # endpoint / non-sink → NULL
        messages = build_messages("http://example.com/app.js", "example.com", [finding], None)
        user_payload = json.loads(messages[1]["content"].split("\n\n", 1)[1])
        assert user_payload["findings"][0]["source_hint"] is None

    def test_evidence_gate_rules_still_in_system_prompt(self):
        """PRD 8z.1: penjelasan source_hint tidak boleh mengubah evidence gate."""
        messages = build_messages("http://example.com/app.js", "example.com", [], None)
        sys_prompt = messages[0]["content"]
        assert "MUST be a substring" in sys_prompt
        assert "1..5" in sys_prompt
