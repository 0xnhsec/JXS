"""
src/ai_triage/client.py
PRD 8y.2 — OpenAI-compatible chat completions client (httpx).

Disiplin gaya mantra_runner (PRD 8h):
  - timeout WAJIB di setiap request
  - retry hanya untuk error yang masuk akal (network, 429, 5xx)
  - error dipublish sebagai LLMError dengan pesan pendek — caller
    (triage.py) yang memutuskan skip/log, tidak ada exception bocor
    sampai ke pipeline utama

response_format json_object SENGAJA tidak dipakai — tidak semua endpoint
OpenAI-compatible (Ollama, dsb.) mendukung; validasi JSON ditangani di
prompt.py + retry logic di triage.py (PRD 8y.1 point 2).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

RETRY_BACKOFF_SECONDS = (1.0, 2.5)
MAX_RESPONSE_CHARS = 1_000_000  # sanity cap — respons LLM tidak akan sebesar ini


class LLMError(Exception):
    """Dilempar setelah retry habis atau error non-retryable."""


def _is_retryable(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


def chat_json(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.0,
    timeout: float = 90.0,
) -> tuple[str, dict[str, int]]:
    """
    Satu call /chat/completions. Return (content_text, usage_dict).

    Raises:
        LLMError: setelah retry habis, atau error non-retryable (401/400/...).
    """
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }

    last_error = "unknown"
    for attempt in range(len(RETRY_BACKOFF_SECONDS) + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, headers=headers, json=payload)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise LLMError(f"response bukan JSON valid: {exc}") from exc

                choices = data.get("choices") or []
                if not choices:
                    raise LLMError("response 200 tanpa choices")
                content = (choices[0].get("message") or {}).get("content") or ""
                if not content.strip():
                    raise LLMError("response 200 dengan content kosong")
                if len(content) > MAX_RESPONSE_CHARS:
                    raise LLMError("response terlalu besar (sanity cap)")
                usage = data.get("usage") or {}
                return content, {
                    "prompt_tokens": int(usage.get("prompt_tokens", 0) or 0),
                    "completion_tokens": int(usage.get("completion_tokens", 0) or 0),
                    "total_tokens": int(usage.get("total_tokens", 0) or 0),
                }

            body_excerpt = resp.text[:300]
            if not _is_retryable(resp.status_code):
                raise LLMError(
                    f"HTTP {resp.status_code}: {body_excerpt}"
                )
            last_error = f"HTTP {resp.status_code}: {body_excerpt}"

        except httpx.TimeoutException:
            last_error = f"timeout setelah {timeout}s"
        except httpx.HTTPError as exc:
            last_error = f"network error: {exc.__class__.__name__}: {exc}"
        except LLMError:
            raise  # non-retryable, langsung ke caller
        # pragma: no cover — defensive
        except Exception as exc:  # pylint: disable=broad-except
            raise LLMError(f"unexpected error: {exc}") from exc

        if attempt < len(RETRY_BACKOFF_SECONDS):
            backoff = RETRY_BACKOFF_SECONDS[attempt]
            logger.warning(
                "LLM request gagal (attempt %d): %s — retry dalam %.1fs",
                attempt + 1, last_error, backoff,
            )
            time.sleep(backoff)

    raise LLMError(last_error)
