# JXS

Regex-based JavaScript recon/narrowing tool for bug bounty. JXS captures the JS
your browser already loads, extracts endpoints, secrets, DOM sinks and tech
fingerprints, then helps you narrow thousands of files down to the handful
worth testing. It is NOT an auto-scanner — it narrows the haystack; you still
do the hacking.

## Architecture

```
Browser → Burp(8080) ← mitmproxy(8082, jxs addon) → SQLite(WAL) → extraction (regex + mantra) → FastAPI(8888) → React UI(5173)
```

- **Capture**: your browser proxies to mitmproxy (8082), which forwards traffic
  to Burp (8080) and stores JS responses into a SQLite DB (WAL mode).
- **Extraction**: regex rules + jsbeautifier + optional mantra secret scan,
  with severity, scope-verification tags and review workflow.
- **Serving**: FastAPI localhost API + React (Vite) graph UI.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Scope config — edit host_whitelist to your target
cp scope_config.example.json scope_config.json

# 2. Start Burp Suite first (listener 127.0.0.1:8080), then the capture proxy:
SCOPE=your-scope mitmdump -s src/capture/jxs_mitm_addon.py \
  -p 8082 --mode upstream:http://127.0.0.1:8080 \
  --set ssl_insecure=true

# 3. API server
uvicorn src.api.main:app --host 127.0.0.1 --port 8888 --reload

# 4. UI (separate terminal)
cd src/ui
npm install        # or: bun install
npm run dev        # → http://localhost:5173
```

Point your browser proxy at `127.0.0.1:8082` (NOT Burp's port) and browse the
target. CLI alternative: `python -m src.cli.jxs_cli scan --scope your-scope`.

## AI Triage (optional, PRD 8y)

LLM prioritization hints for unreviewed findings. Works with any
OpenAI-compatible provider. Output is a hint, never a verdict — validate
findings manually before reporting.

| Env var | Default | Description |
| --- | --- | --- |
| `JXS_AI_API_KEY` | (none — required to run) | API key for the provider |
| `JXS_AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `JXS_AI_MODEL` | `gpt-4o-mini` | Model name |
| `JXS_AI_TIMEOUT` | `90` | Per-request timeout (seconds) |
| `JXS_AI_MAX_FINDINGS_PER_REQUEST` | `15` | Findings batched per LLM call |
| `JXS_AI_TEMPERATURE` | `0.0` | Sampling temperature |

Provider examples:

```bash
# OpenAI (default — only the key is needed)
export JXS_AI_API_KEY='sk-...'

# Qwen via DashScope (OpenAI-compatible endpoint)
export JXS_AI_API_KEY='sk-...'
export JXS_AI_BASE_URL='https://dashscope.aliyuncs.com/compatible-mode/v1'
export JXS_AI_MODEL='qwen-plus'

# Google Gemini (OpenAI-compatible endpoint)
export JXS_AI_API_KEY='...'
export JXS_AI_BASE_URL='https://generativelanguage.googleapis.com/v1beta/openai/'
export JXS_AI_MODEL='gemini-2.0-flash'

# OpenRouter
export JXS_AI_API_KEY='sk-or-...'
export JXS_AI_BASE_URL='https://openrouter.ai/api/v1'
export JXS_AI_MODEL='openai/gpt-4o-mini'

# Ollama (local — any non-empty key works)
export JXS_AI_API_KEY='ollama'
export JXS_AI_BASE_URL='http://127.0.0.1:11434/v1'
export JXS_AI_MODEL='llama3.1'
```

## Vendor tools

Tools under `vendor/` are NOT bundled with this repo — clone them separately
(licensing and repo-size reasons). See [vendor/README.md](vendor/README.md)
for the list and upstream URLs.

## Docs

- [README-ew.md](README-ew.md) — detailed usage guide (Bahasa Indonesia)
- [PRD-jxs.md](PRD-jxs.md) — product requirements document
- [OBSERVASI-JXS.md](OBSERVASI-JXS.md) — field observations (historical)
