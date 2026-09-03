"""
src/ai_triage/config.py
PRD 8y.2 — env-first configuration. API key TIDAK PERNAH disimpan ke
DB / JSON / git (beda dengan precedent auth_cookie di scope_config.json
yang sengaja tidak ditiru).

Semua nilai punya default yang aman: tanpa JXS_AI_API_KEY modul tetap
importable, run_ai_triage() hanya mengembalikan summary error.

PRD 8z.2 poin 1 — load_config() TIDAK PERNAH raise untuk env numerik yang
malformed (mis. JXS_AI_TIMEOUT=abc dulu → uncaught ValueError → HTTP 500).
Sekarang tiap env numerik diparse via helper yang mengembalikan
(value, error_message); pesan error yang jelas (dengan contoh format benar)
dikumpulkan di AITriageConfig.config_errors, dan is_configured → False.
run_ai_triage yang menerjemahkan config_errors jadi summary error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 90.0
DEFAULT_MAX_FINDINGS_PER_REQUEST = 15
DEFAULT_TEMPERATURE = 0.0

# Snippet lebih panjang dari ini di-truncate sebelum dikirim ke model
MAX_SNIPPET_CHARS = 1200

# File JS lebih besar dari ini tidak di-classify ulang saat triage (hemat CPU)
VENDOR_CLASSIFY_SIZE_CAP = 3 * 1024 * 1024


def _parse_numeric(
    env_name: str, raw: str, cast: Callable[[str], Any], example: str
) -> tuple[Any, str | None]:
    """
    Parse satu env var numerik → (value, error_message). TIDAK raise.

    PRD 8z.2 poin 1: pesan error harus jelas + kasih contoh format benar,
    mis. "JXS_AI_TIMEOUT='abc' bukan angka valid — pakai contoh:
    export JXS_AI_TIMEOUT=90.0".
    """
    try:
        return cast(raw), None
    except (TypeError, ValueError):
        return None, (
            f"{env_name}='{raw}' bukan angka valid — "
            f"pakai contoh: export {env_name}={example}"
        )


@dataclass(frozen=True)
class AITriageConfig:
    """Frozen config — satu kali dibaca dari env, tidak diubah runtime.

    PRD 8z.2: config_errors berisi pesan env var numerik yang malformed
    (list[str], bisa kosong). is_configured False kalau api_key kosong
    ATAU config_errors tidak kosong — caller (run_ai_triage) wajib cek
    sebelum memakai field lain.
    """

    api_key: str
    base_url: str
    model: str
    timeout: float
    max_findings_per_request: int
    temperature: float
    config_errors: list[str] = field(default_factory=list)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key) and not self.config_errors


def load_config() -> AITriageConfig:
    """
    Baca env var sekali; dipanggil oleh run_ai_triage tiap run.

    PRD 8z.2 poin 1: env numerik malformed TIDAK bikin raise. Field tetap
    diisi default supaya dataclass valid untuk dibaca; pesan error per-var
    dikumpulkan di config_errors.
    """
    errors: list[str] = []

    def _num(env_name: str, default: Any, cast: Callable[[str], Any]) -> Any:
        """Ambil env numerik; malformed → catat error, pakai default."""
        raw = os.environ.get(env_name)
        if raw is None:
            return default
        value, err = _parse_numeric(env_name, raw.strip(), cast, str(default))
        if err is not None:
            errors.append(err)
            return default
        return value

    return AITriageConfig(
        api_key=os.environ.get("JXS_AI_API_KEY", "").strip(),
        base_url=os.environ.get("JXS_AI_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
        model=os.environ.get("JXS_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        timeout=_num("JXS_AI_TIMEOUT", DEFAULT_TIMEOUT, float),
        max_findings_per_request=_num(
            "JXS_AI_MAX_FINDINGS_PER_REQUEST", DEFAULT_MAX_FINDINGS_PER_REQUEST, int
        ),
        temperature=_num("JXS_AI_TEMPERATURE", DEFAULT_TEMPERATURE, float),
        config_errors=errors,
    )


def missing_config_hint() -> str:
    return (
        "JXS_AI_API_KEY belum diset. Contoh:\n"
        "  export JXS_AI_API_KEY='sk-...'\n"
        "  export JXS_AI_BASE_URL='https://api.openai.com/v1'   # default\n"
        "  export JXS_AI_MODEL='gpt-4o-mini'                    # default\n"
        "Provider lain (PRD 8y.2):\n"
        "  Qwen (DashScope): https://dashscope.aliyuncs.com/compatible-mode/v1 + qwen-plus\n"
        "  Gemini:           https://generativelanguage.googleapis.com/v1beta/openai + gemini-2.0-flash\n"
        "  OpenRouter:       https://openrouter.ai/api/v1\n"
        "  Ollama lokal:     http://localhost:11434/v1 (API key boleh 'ollama')"
    )
