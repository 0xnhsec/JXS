"""
src/ai_triage — PRD section 8y: AI Triage Assistant.

LLM sebagai narrowing layer kedua: menilai kandidat hasil regex extraction
(priority 1..5, kategori, langkah cek manual) — bukan scanning bundle mentah,
bukan verdict otomatis. Semua output melewati evidence-verification gate.
"""

from src.ai_triage.triage import run_ai_triage  # noqa: F401
