"""
src/ai_triage/config.py
PRD 8y.2 — env-first configuration. API key TIDAK PERNAH disimpan ke
DB / JSON / git (beda dengan precedent auth_cookie di scope_config.json
yang sengaja tidak ditiru).

Semua nilai punya default yang aman: tanpa JXS_AI_API_KEY modul tetap
importable, run_ai_triage() hanya mengembalikan summary error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 90.0
DEFAULT_MAX_FINDINGS_PER_REQUEST = 15
DEFAULT_TEMPERATURE = 0.0

# Snippet lebih panjang dari ini di-truncate sebelum dikirim ke model
MAX_SNIPPET_CHARS = 1200

# File JS lebih besar dari ini tidak di-classify ulang saat triage (hemat CPU)
VENDOR_CLASSIFY_SIZE_CAP = 3 * 1024 * 1024


@dataclass(frozen=True)
class AITriageConfig:
    """Frozen config — satu kali dibaca dari env, tidak diubah runtime."""

    api_key: str
    base_url: str
    model: str
    timeout: float
    max_findings_per_request: int
    temperature: float

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)


def load_config() -> AITriageConfig:
    """Baca env var sekali; dipanggil oleh run_ai_triage tiap run."""
    return AITriageConfig(
        api_key=os.environ.get("JXS_AI_API_KEY", "").strip(),
        base_url=os.environ.get("JXS_AI_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
        model=os.environ.get("JXS_AI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        timeout=float(os.environ.get("JXS_AI_TIMEOUT", str(DEFAULT_TIMEOUT))),
        max_findings_per_request=int(
            os.environ.get("JXS_AI_MAX_FINDINGS_PER_REQUEST", str(DEFAULT_MAX_FINDINGS_PER_REQUEST))
        ),
        temperature=float(os.environ.get("JXS_AI_TEMPERATURE", str(DEFAULT_TEMPERATURE))),
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
