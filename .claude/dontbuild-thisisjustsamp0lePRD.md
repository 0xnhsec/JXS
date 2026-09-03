# PRD: jxs — JavaScript Analysis & Mapping Tool for Bug Bounty

**Author:** Bangkit Eldhianpranata Pengestu (0xnhsec)
**Status:** Draft v1
**First Plan:** 2026-07-09 
**Last updated:** 2026-07-25

---

## 1. Problem Statement

Saat bug hunting di target dengan JS-heavy frontend (SPA, auth flow, login page), proses discovery JS saat ini manual: download file satu-satu, buka LinkFinder/JSFinder terpisah, baca hasil grep secara manual, lalu cross-reference balik ke Burp buat lihat request/response terkait. Tidak ada visibilitas terpusat soal:

- JS file mana yang punya potential issue (endpoint sensitif, DOM sink, secret leak)
- Bagaimana relasi antar JS file, halaman, dan network request
- Coverage gap — JS mana yang belum ter-explore karena butuh multi-step user flow (login → reset password → dst)

LLM (Claude/Qwen/Gemini) tidak scalable untuk exhaustive pattern matching di bundle JS besar — token habis atau hasil miss/ngaco karena tidak ada narrowing sebelum diserahkan ke model.

### TL;DR — Baca ini dulu kalau baru buka PRD ini setelah lama

`jxs` adalah tool regex-based untuk narrowing JS analysis di bug bounty: capture JS via mitmproxy atau katana, ekstrak kandidat (endpoint, DOM sink, sourcemap, secret), visualisasi di React Flow graph, lalu triage manual. Bukan scanner otomatis — setiap finding tetap butuh verifikasi manual sesuai Validation Checklist (8u). Stack aktif: Python backend (FastAPI + SQLite), React UI, CLI (`jxs scan/status/export/review`). Status terakhir: semua komponen inti sudah live (8m CLI ✅, 8q katana ✅, 8s payload dict ✅, 8p-1 review UI ✅, 8t export ✅). Pending: 8u (Validation Checklist belum ada UI-nya, saat ini hanya teks di PRD), 8v (storage scaling open question), 8w (Insecure Storage Detection — backlog, unblocked).

---

### 1a. Batasan Fundamental — `jxs` adalah Regex-Based Candidate Finder, Bukan Vulnerability Scanner

Ini prinsip yang wajib dipahami sebelum membaca bagian manapun di PRD ini, karena menentukan apa yang realistis diharapkan dari tool ini.

**Cara kerja `jxs` di semua modul (Extraction Engine 4.3, vendor classifier 8o, dst) adalah murni regex pattern matching terhadap teks mentah isi file JS.** Tidak ada AST parsing, tidak ada eksekusi kode, tidak ada analisis data-flow otomatis. `jxs` cuma membaca teks dan mencari pola string yang cocok.

**Implikasi langsung dari batasan ini:**

1. **Regex menemukan *kandidat*, bukan *vonis*.** Sebuah "High finding" berarti "ada string yang match pola tertentu", bukan "ini pasti bug". Riwayat project ini sudah membuktikan berulang kali (kasus Partytown 8o, Preact vDOM diffing, `Function` keyword generik, `setAttribute`) — regex tidak bisa memahami konteks: siapa yang memanggil kode itu, apakah itu vendor library atau business logic custom.

2. **Regex tidak bisa trace data-flow.** `jxs` bisa menemukan `innerHTML = ...`, tapi tidak bisa otomatis menjawab apakah variabel yang di-assign berasal dari `location.search` (attacker-controlled) atau dari config internal (aman). Ini bukan keterbatasan implementasi yang "akan diperbaiki nanti" — ini batas fundamental dari pendekatan regex. Karena itu, langkah pertama di Validation Checklist (8u) — cek source data attacker-controlled atau bukan — **harus** dilakukan manual, selamanya.

3. **Vendor classifier tidak akan pernah 100% akurat.** Pattern nama file (`BUILD_HASH_PATTERN`) terbukti berulang kali "ketinggalan" format bundler baru (base62, base64url, query-string hash — lihat 8o) karena regex mencocokkan pola string, bukan memahami secara semantik bahwa sebuah file adalah vendor bundle. Future improvement apapun (signature-based detection, densitas variable single-letter) tetap berupa heuristic berbasis pola — bukan pemahaman kode yang sesungguhnya.

**Posisi `jxs` yang akurat: narrowing tool, bukan auto-detector.** Sesuai Problem Statement di atas — `jxs` mereduksi ribuan baris kode jadi puluhan titik yang layak dicek manual, mempersempit apa yang perlu dibawa ke LLM atau ditinjau langsung. Keputusan akhir "ini valid bug" atau "ini bukan" selalu ada di tangan manusia — itu sebabnya Validation Checklist (8u) dan `review_status` tracking (8p-1) adalah bagian inti dari alur kerja `jxs`, bukan fitur pelengkap.

**Konsekuensi ke desain fitur baru:** setiap usulan fitur deteksi baru harus dievaluasi dengan pertanyaan ini — "apakah ini masih dalam batas regex/pattern-matching, atau sudah butuh pemahaman semantik/eksekusi yang di luar kemampuan `jxs`?" Kalau jawabannya yang kedua, itu di luar scope `jxs` (lihat Non-Goals, section 3), dan mungkin lebih cocok jadi bagian dari proses manual atau tool terpisah. Contoh kandidat yang masih dalam batas regex: 8w — Insecure Storage Detection (lihat section 8w). Contoh yang jelas di luar scope: analisis taint-flow otomatis, AST-based dead code detection.

## 2. Goals

1. Otomasi discovery JS dari target dengan 2 mode pengumpulan data (on-demand crawl + passive capture), hasil digabung ke satu storage.
2. Ekstraksi otomatis endpoint, DOM sink, secret pattern, sourcemap leak dari tiap JS file.
3. Visualisasi graph (React Flow / mindmap-style) yang menunjukkan relasi page → JS file → endpoint/sink, dengan flag warna merah untuk node yang punya "issue".
4. Integrasi read-only dengan Burp Suite — request/response tetap sepenuhnya di Burp; `jxs` hanya konsumsi traffic untuk keperluan JS/JQ logic mapping.
5. Scope management per target (host-based filter), supaya bisa dipakai bergantian untuk banyak program (Infomaniak, LinkedIn, TikTok, dst di YWH/H1) tanpa data campur aduk.

## 3. Non-Goals (Out of Scope)

- Tidak menggantikan fungsi Burp Suite (repeater, intruder, manual request manipulation) — itu tetap dilakukan di Burp.
- Tidak melakukan exploitation otomatis (tidak mengirim payload, tidak brute force). `jxs` murni discovery & flagging, eksekusi tetap manual oleh Bangkit.
- Tidak menganalisa non-JS assets (CSS, gambar) di fase awal.

## 4. Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Browser/Burp   │───▶│  Capture Layer   │───▶│ Storage (SQLite│
│  (manual browse │     │  (mitmproxy addon│     │  / JSON)       │
│   OR Playwright │     │   passthrough)   │     │                │
│ on-demand crawl)│     └──────────────────┘     └───────┬────────┘
└─────────────────┘                                      │
                                                         ▼
                                              ┌───────────────────────┐
                                              │  Extraction Engine    │
                                              │  (LinkFinder/JSFinder │
                                              │   logic + js-beautify)│
                                              └───────────┬───────────┘
                                                          │
                                                          ▼
                                              ┌───────────────────────┐
                                              │  Tagging/Severity     │
                                              │  Engine (rule-based)  │
                                              └───────────┬───────────┘
                                                          │
                                                          ▼
                                              ┌──────────────────────┐
                                              │  React Flow Graph UI │
                                              │  (localhost webapp)  │
                                              └──────────────────────┘
```

### 4.1 Data Collection — Dual Mode

**Mode A: On-demand crawl (`jxs -u target.com --scope infomaniak`)**
- Playwright headless browser, auto-navigate + auto-click reachable elements
- Capture semua `.js` response via `page.on("response")`
- Tujuan: broad coverage, nemu JS yang gak sengaja terlewat manual browsing
- Limitasi: tidak paham multi-step flow yang butuh state (reset password perlu email valid dulu)

**Mode B: Passive capture (mitmproxy addon, jalan bareng Burp)**
- mitmproxy addon sebagai passthrough — traffic tetap ke Burp seperti biasa, addon cuma "nguping" (mirror), tidak inject atau modifikasi apapun ke request/response Burp
- Filter: hanya capture response dengan `Content-Type: application/javascript` atau `.js` extension
- Tujuan: capture JS yang butuh context/state (auth flow spesifik yang lagi digarap manual)

Kedua mode nulis ke storage yang sama, deduplikasi berdasarkan hash file content (bukan cuma URL — cegah re-parse file yang sama walau URL beda karena cache-busting param).

### 4.2 Scope Management

- Setiap target/program didefinisikan sebagai `scope` (host whitelist)
- Struktur storage: `scope_name` → `{pages: [], js_files: [], graph_nodes: []}`
- Switch scope = switch context sepenuhnya, tidak ada data campur antar program (penting karena masing-masing punya BAC ketat di YWH/H1 — data campur = risiko out-of-scope testing)

**Scope config schema** (termasuk field buat JSFinder-style crawling dengan auth state):

```python
scope_config = {
    "scope_name": str,
    "host_whitelist": [str],       # domain root — subdomain otomatis ke-cover.
                                   # Tulis "target.com", semua *.target.com ikut.
                                   # Matching: host == entry OR host.endswith(f".{entry}")
    "test_only_hosts": [str],      # opsional, default []. Host boleh di-capture TAPI
                                   # findings-nya auto-tagged verify_scope=1 — perlu
                                   # konfirmasi in-scope program sebelum report.
                                   # Suffix match sama seperti host_whitelist.
    "auth_cookie": str | None,     # opsional, dipakai untuk crawl authenticated state
    "host_list_file": str | None,  # opsional, path ke file host list ala JSFinder -c mode
}
```

Field `auth_cookie` dan `host_list_file` opsional — default `None` buat unauthenticated crawl biasa. Field `test_only_hosts` default `[]` — backward compat dengan `scope_config.json` lama yang tidak punya key ini.

**Use case `test_only_hosts`:** host yang ada di perimeter program tapi baru mau di-confirm apakah in-scope (misal subdomain baru ditemukan saat crawl, belum ada di rules program). Capture dulu, triage findings-nya, lalu konfirmasi ke program sebelum submit.


### 4.3 Extraction Engine

Pipeline per JS file:
1. `js-beautify` — deobfuscate/format dulu (skip kalau ukuran file di atas threshold tertentu, prioritaskan custom code dulu)
2. Regex extraction (adaptasi logic LinkFinder/JSFinder):
   - Endpoint pattern (`/api/`, `/v1/`, `/graphql`, `fetch(`, `axios.`, `.post(`)
   - Sourcemap leak (`//# sourceMappingURL=`)
   - Sensitive keyword (`token`, `apiKey`, `secret`, `admin`, `debug`, `internal`)
   - DOM sink (`innerHTML =`, `document.write(`, `eval(`, `dangerouslySetInnerHTML`)
   - Auth-related function name (`validateToken`, `checkAuth`, `isAdmin`, `refreshSession`)
3. Klasifikasi kategori file: vendor/UI bundle vs custom logic (heuristic: filename pattern + minification ratio + size)

### 4.4 Tagging/Severity Engine

Rule-based (bukan ML dulu di MVP), tiap match dari extraction engine di-assign severity:

| Match Type | Severity | Warna Node |
|---|---|---|
| DOM sink ditemukan | High | Merah |
| Sourcemap leak | High | Merah |
| Sensitive keyword di custom logic file | Medium | Kuning |
| ~~Endpoint baru (belum ada di Burp sitemap)~~ | **DROPPED dari MVP** — lihat section 6 | — |
| Auth-related function ditemukan | Info (perlu manual review) | Biru |
| Vendor bundle standar | Low/ignore | Abu-abu |

> **Catatan:** rule "Endpoint baru belum ada di sitemap" dihapus dari deliverable MVP (bukan sekadar di-skip), karena butuh Burp Professional REST API buat baca sitemap. Bangkit pakai Burp Community Edition — endpoint sitemap API tidak tersedia. Rule ini masuk backlog Phase 2, hanya relevan kalau upgrade ke Professional atau pindah ke pendekatan Burp Extender API.


### 4.5 Visualization Layer

- React Flow, node-based graph mirip n8n
- Node types: `Page`, `JS File`, `Endpoint`, `Issue`
- Edge: `Page → JS File` (JS dimuat di halaman ini), `JS File → Endpoint` (JS memanggil endpoint ini)
- Klik node "Issue" (merah) → tampilkan detail: file asal, baris kode (snippet), match type, link balik ke request terkait di Burp (kalau ada history-nya)
- Filter by scope/target di UI

## 5. Burp Suite Integration Point

- `jxs` TIDAK menggantikan Burp Proxy. Semua request/response tetap lewat Burp seperti biasa (Burp sebagai proxy utama)
- mitmproxy addon jalan sebagai **upstream/downstream mirror**, bukan man-in-the-middle terhadap Burp — traffic flow: `Browser → Burp Proxy → mitmproxy addon (passive log JS only) → Internet`
- Alternatif lebih simpel kalau setup di atas ribet: pakai Burp extension (Python/Jython via Burp Extender API) yang subscribe ke `IHttpListener`, filter response JS, kirim ke storage `jxs` via local API call. Ini lebih native tapi butuh belajar Burp Extender API — worth dievaluasi di fase 2 kalau approach mitmproxy addon kerasa clunky.

## 6. MVP Scope (Phase 1)

> **Section 6 = original MVP definition, dibekukan sebagai historical scope decision — bukan live status tracker.** Beberapa item di bawah sudah live (lihat evidence eksplisit di section 10: capture mitmproxy ✅, DOM_SINK_PATTERN ✅, CLI/extraction engine ✅). Checkbox di bawah **sengaja tidak diupdate** supaya scope keputusan asli (apa yang di-skip di Phase 1, kenapa) tetap utuh sebagai histori — cek section 10 untuk status implementasi terkini per komponen, jangan andalkan checkbox di bawah ini.

- [ ] Mode B saja dulu (passive capture via mitmproxy addon) — lebih simpel drpd Playwright automation
- [ ] Extraction engine: endpoint + sourcemap + DOM sink saja (skip secret detection dulu, false positive tinggi)
- [ ] Storage: SQLite lokal, single scope dulu (belum multi-scope switching)
- [ ] Visualization: React Flow basic, tanpa klik-detail-ke-Burp dulu (link manual copy-paste dulu)
- [ ] **Burp Suite yang dipakai: Community Edition (dikonfirmasi).** Konsekuensi eksplisit: severity rule "Endpoint baru belum ada di sitemap" (4.4) **dihapus permanen dari MVP scope**, bukan sekadar di-skip sementara — Community Edition tidak expose REST API buat baca sitemap. Rule ini baru relevan lagi kalau Bangkit upgrade ke Professional, dicatat di Phase 2 backlog (section 7), bukan di-assume "nanti otomatis nyala".

## 7. Phase 2

- [ ] Mode A (Playwright on-demand crawl) ditambahkan, merge ke storage yang sama
- [ ] Multi-scope switching di UI
- [ ] Burp Extender API integration (ganti mitmproxy addon kalau worth)
- [ ] Klik node issue → auto-link ke request Burp terkait

## 8. Open Questions

- Threshold ukuran file buat skip `js-beautify` (biar gak lambat di vendor bundle raksasa) — perlu testing empiris di beberapa target dulu
- Dedup strategy kalau JS file sama tapi versi beda (cache-busting hash berubah tapi logic sama) — perlu keputusan: treat as new atau diff-check dulu?
- False positive rate di secret keyword matching — perlu whitelist/blacklist pattern dari testing real target (Infomaniak dulu sebagai test case)

## 8b. Final Consolidated Tool Stack (decided)

| Layer | Tool | Fungsi | Catatan |
|---|---|---|---|
| Passive capture | mitmproxy | Mirror traffic JS-only, chained upstream ke Burp | Listen di port berbeda dari Burp (misal 8082), forward upstream ke Burp (8080). **Jangan** samakan port listen dengan port upstream target. |
| On-demand crawl | Playwright | Headless browse + auto-click + capture response | Puppeteer di-drop, redundant fungsi |
| Deobfuscate | js-beautify | Format minified JS sebelum regex extraction | |
| Endpoint extraction | LinkFinder | Regex based endpoint/path discovery dari JS | |
| Secret/API key scan | mantra | Go-based, scan JS + HTML buat API key pattern | Named entity match, bukan generic keyword — lebih rendah false positive drpd regex manual |
| Tech stack fingerprint | Wappalyzer (nomnom fork) | Validasi & cross-reference tech stack dari JS global variable/comment signature | Dipakai sebagai reference logic (rule set), bukan dependency langsung karena based browser extension |
| Visualization | React Flow + dagre/elkjs | Node graph mindmap-style, auto-layout | Custom node component buat severity coloring |
| Storage | SQLite | Per-scope data, dedup by content hash | |

### mitmproxy Proxy Chain Config (fix dari testing lu)

```bash
# mitmproxy listen di 8082, forward semua ke Burp yang listen di 8080
mitmdump -s jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080
```

Browser proxy setting diarahkan ke `127.0.0.1:8082`, BUKAN membuka `localhost:8080` sebagai URL. Flow: `Browser (proxy 8082) → mitmproxy (addon jxs, passive log JS) → Burp (8080) → Internet`.

Addon skeleton (final):
```python
# jxs_mitm_addon.py
from mitmproxy import http
import hashlib, sqlite3

DB_PATH = "jxs_storage.db"

class JXSCapture:
    def response(self, flow: http.HTTPFlow):
        content_type = flow.response.headers.get("content-type", "")
        is_js = "javascript" in content_type or flow.request.pretty_url.endswith(".js")
        if not is_js:
            return
        content = flow.response.content
        content_hash = hashlib.sha256(content).hexdigest()
        # TODO: cek dedup by content_hash sebelum insert
        # TODO: insert ke SQLite (url, host, content, content_hash, timestamp)
        save_js_file(flow.request.pretty_url, content, content_hash)

def save_js_file(url, content, content_hash):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS js_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, content_hash TEXT UNIQUE,
            content BLOB, scope TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        INSERT OR IGNORE INTO js_files (url, content_hash, content)
        VALUES (?, ?, ?)
    """, (url, content_hash, content))
    conn.commit()
    conn.close()

addons = [JXSCapture()]
```

## 8c. Module Breakdown (untuk Antigravity build order)

Build order disaranin sequential, tiap module independently testable:

1. **Module: Capture** — mitmproxy addon (di atas) + Playwright crawler script terpisah, keduanya nulis ke `jxs_storage.db` yang sama
2. **Module: Extraction** — baca dari `js_files` table, jalanin js-beautify → LinkFinder logic → mantra → simpan hasil ke table baru `findings` (kolom: `js_file_id`, `type`, `match_value`, `severity`)
3. **Module: Tech Stack** — rule set terpisah (bisa reuse tabel `findings` dengan `type = 'tech_stack'`), cross-check ke Wappalyzer fingerprint pattern
4. **Module: XSS Advisor** — baca `findings` dengan `type = 'dom_sink'`, generate rekomendasi teks (bukan payload otomatis-fire), simpan ke `advisories` table
5. **Module: UI** — React Flow, baca semua tabel di atas via local API (FastAPI simple endpoint), render graph + detail panel per node
6. **Module: CLI (8m)** — entry point `jxs scan`, reuse Extraction Engine yang sama, output JSON. **Wajib selesai sebelum module 7.**
7. **Module: katana Integration (8q)** — depends on module 6 (CLI mode). Subprocess call ke katana, scope enforcement 2 lapis, feed hasil ke Capture module yang sama seperti module 1.

Tiap module bisa dikerjakan dan ditest terpisah karena kontrak data-nya cuma SQLite schema di atas — gak saling depend langsung kodenya, **kecuali module 7 yang secara eksplisit depends on module 6**.

## 8d. Concrete Regex Patterns (validated against real test data)

Test-set: `js.txt` (38 JS URL dari nasa.gov/globe.gov). Ditemukan 1 real case yang jadi contoh false-positive handling: Google Maps API key exposed via query param — ini **public-by-design key** (dibatasi via HTTP referrer restriction), harus di-whitelist, bukan di-flag High.

```python
import re

# Endpoint/path extraction (adaptasi LinkFinder, dipersempit ke pattern umum)
ENDPOINT_PATTERN = re.compile(
    r"""["'](/(?:api|v[0-9]+|graphql|rest)/[a-zA-Z0-9_\-/{}.]+)["']"""
)

# Sourcemap leak
SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")

# DOM sink (dijalankan di JS content, bukan URL)
DOM_SINK_PATTERN = re.compile(
    r"\b(innerHTML|outerHTML|document\.write|eval|dangerouslySetInnerHTML|insertAdjacentHTML)\s*[=(]"
)

# Secret/key pattern via query param
SECRET_PARAM_PATTERN = re.compile(
    r"[?&](key|token|apikey|api_key|secret|auth)=([A-Za-z0-9_\-]{16,})", re.IGNORECASE
)

# Generic high-entropy string literal (hardcoded secret di source, bukan URL)
HIGH_ENTROPY_PATTERN = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{32,})['\"]")

# Whitelist — public-by-design key, downgrade severity ke Info
SECRET_WHITELIST_CONTEXT = re.compile(
    r"(maps\.googleapis\.com|recaptcha|googletagmanager|gtag|ga4)", re.IGNORECASE
)
```

Validasi wajib sebelum full build: jalankan pattern di atas terhadap minimal 5-10 JS file **content** real (bukan cuma URL list) dari target lama Bangkit, hitung false positive/negative rate manual, baru finalize sebelum dipakai production di Extraction Engine.

## 8e. js-beautify Threshold (decided, bukan "perlu testing")

**Keputusan: file >1.5MB di-skip beautify, regex langsung jalan di minified content.**
Alasan: regex pattern di atas (endpoint, sourcemap, secret param) toleran terhadap whitespace/minification — LinkFinder sendiri proven jalan di file minified tanpa perlu beautify dulu. Beautify cuma dipakai buat file di bawah threshold, tujuannya readability pas manual review DOM sink finding di UI (snippet code yang ditampilkan ke user), bukan prasyarat regex match.

## 8f. Definisi "Done" per Module

| Module | Kriteria Selesai (testable, bukan subjektif) |
|---|---|
| Capture | Capture 100 JS file dari 1 target test, 0 duplikat by content hash, addon jalan kontinu 30 menit tanpa crash |
| Extraction | Jalan di test-set 10 file (5 obfuscated, 5 minified real), false positive rate hasil manual review < 20% |
| Tech Stack | Identifikasi benar minimal 3 tech dari 1 target yang stack-nya udah diketahui manual sebagai ground truth |
| XSS Advisor | Setiap DOM sink match menghasilkan 1 baris rekomendasi teks spesifik (bukan generic), tanpa payload auto-fire |
| UI | Graph render tanpa crash untuk 100+ node dalam 1 scope, klik node nampilin detail panel dengan data benar |

## 8g. Sample Findings Table Rows (data konkret, dari test-set real)

| id | js_file_id | type | match_value | severity |
|---|---|---|---|---|
| 1 | 12 | secret_param | `key=AIzaSyBNshGF...` (maps.googleapis.com) | Info — whitelisted public key |
| 2 | 8 | sourcemap | `nasa.gov/_static/??-eJzTLy...` | High |
| 3 | 15 | endpoint | `/o/frontend-js-loader-modules-extender/loader.js` | Medium |
| 4 | 20 | endpoint | `/wp-content/plugins/gravityforms/js/jquery.json.min.js` | Low — vendor plugin, bukan custom logic |

## 8h. Tool Integration Spec (mantra, Wappalyzer — cara panggil, bukan cuma nama)

**mantra** — Go binary, dipanggil via subprocess, parse stdout (biasanya JSON atau line-based output tergantung flag):
```python
import subprocess, json

def run_mantra(file_path: str) -> list:
    result = subprocess.run(
        ["mantra", "-f", file_path, "-o", "json"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return []  # log error, jangan crash pipeline
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
```
Wajib pakai `timeout` — kalau mantra hang di file gede, jangan sampai block seluruh pipeline extraction.

**Wappalyzer (nomnom fork)** — ini **bukan dependency langsung**, dipakai sebagai *reference rule set* saja (pattern-nya dibaca manual dari source code fork tersebut, lalu diadaptasi jadi rule Python sendiri di Tagging Engine). Alasan: Wappalyzer versi modern berbasis browser extension (butuh Chrome runtime context), overhead terlalu besar buat dipanggil sebagai subprocess per JS file. Kalau nanti butuh tech-detection library asli, evaluasi `python-Wappalyzer` (PyPI package terpisah, bukan fork nomnom) sebagai alternatif call langsung.

## 8i. Burp Integration — Keputusan Final untuk MVP

**MVP: mitmproxy addon only (opsi A), Burp Extender API di-defer ke Phase 2 secara eksplisit.**
Alasan: Extender API butuh Jython/Java bridge learning curve yang gak sepadan buat MVP personal tool. Konsekuensi: di MVP, severity rule "Endpoint baru (belum ada di Burp sitemap)" **di-skip dulu** — karena itu butuh baca Burp sitemap via REST API (`Burp REST API` — Community Edition **tidak** expose endpoint sitemap, cuma Professional yang punya extension REST API resmi via `Burp Suite Professional's built-in REST API` atau ekstensi pihak ketiga). Kalau Bangkit pakai Burp Community, rule ini **tidak bisa diimplementasi** sampai upgrade ke Professional atau pindah ke Extender API approach di Phase 2.

## 8j. Failure Handling (wajib ada sebelum build, bukan nice-to-have)

| Skenario | Handling |
|---|---|
| JS file > 10MB (vendor bundle raksasa) | ~~Skip extraction sepenuhnya, cuma simpan metadata (URL, size, hash), flag sebagai `type: oversized_skipped`~~ **~~>10MB~~ → >75MB** (dinaikkan setelah stress-test nyata, lihat section 8n — 80MB scan terbukti selesai 32.5s tanpa crash). File >75MB: skip extraction, simpan metadata (URL, size, hash), flag `type: oversized_skipped` |
| mitmproxy addon exception saat parsing response | Try-except di level `response()`, log ke file terpisah, JANGAN crash seluruh addon — 1 file gagal parse tidak boleh stop capture file lain |
| Playwright crawler timeout saat auto-click | Set `timeout=3000ms` per elemen, wrap try-except, skip elemen yang gagal, lanjut ke elemen berikutnya (jangan stop seluruh crawl) |
| mantra subprocess hang | `subprocess.run(..., timeout=30)`, kalau timeout return empty list bukan raise exception |
| SQLite locked (concurrent write dari mitmproxy + Playwright bersamaan) | Pakai `PRAGMA journal_mode=WAL;` saat init DB, biar concurrent read/write lebih toleran |

## 8k. Pending Validation (blocker — bukan catatan lepas) — ✅ RESOLVED (lihat section 10)

> **Update:** blocker di bawah ini sudah terselesaikan. `DOM_SINK_PATTERN` sudah tervalidasi terhadap JS content real (Infomaniak `init.js`, 1 legitimate High finding terkonfirmasi manual — lihat section 10 baris "DOM_SINK_PATTERN accuracy"). Module Extraction resmi "started" sejak validasi ini. Teks asli di bawah dipertahankan sebagai histori kenapa validasi ini dianggap prasyarat keras.

Ini bukan "nice to have", ini **prasyarat sebelum Module Extraction dianggap "start"**:

- **`DOM_SINK_PATTERN` belum tervalidasi terhadap JS content real.** `SECRET_PARAM_PATTERN` sudah punya bukti empiris (real case: Google Maps API key exposed di nasa.gov, section 8d/8g), tapi `DOM_SINK_PATTERN` masih regex teoritis — test yang udah dilakukan baru sebatas list URL JS (`js.txt`), belum isi/konten file JS-nya.
- **Kenapa ini blocker, bukan sekadar catatan:** DOM sink itu severity **High** di tabel 4.4. Kalau pattern-nya false-positive-heavy dan baru ketauan pas testing beneran, Module Extraction otomatis gagal kriteria Done di 8f (FP rate < 20%), dan itu artinya balik lagi ke desain regex — mundur, bukan sekadar bug fix kecil.
- **Action item konkret sebelum lanjut coding Module Extraction:** download 5-10 file JS **content** (bukan URL) dari target yang scope-nya jelas (VDP/bug bounty program aktif Bangkit), jalankan `DOM_SINK_PATTERN` manual, hitung FP/FN rate, revisi pattern kalau perlu — baru declare Module Extraction "in progress" ke Antigravity.

## 8l. CRITICAL — Self-Capture Contamination Bug (ditemukan saat real testing)

**Gejala:** scope `infomaniak` menunjukkan 14000+ node dari 149 JS file (rasio gak masuk akal — ~95 node/file). Investigasi menemukan file seperti `dagre.esm.js`, `d3-*`, `react`, `react-dom`, `zustand`, `vite/dist/client` ikut ke-capture — file-file ini adalah **dependency milik UI `jxs` sendiri** (React Flow app di `localhost:5173`), BUKAN milik target Infomaniak.

**Root cause:** browser proxy (`127.0.0.1:8082`) aktif secara global di browser. Begitu tab `localhost:5173` (UI `jxs`) dibuka di browser yang sama dengan proxy aktif, semua request vendor JS milik UI sendiri ikut lewat mitmproxy dan ter-capture ke scope yang lagi aktif (`infomaniak`) — terjadi kontaminasi data, bukan murni soal regex false positive.

**Fix wajib di addon (prioritas di atas semua module lain, blocker sebelum re-test apapun):**
```python
# jxs_mitm_addon.py — tambahkan SEBELUM filter is_javascript()
LOCAL_TOOL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}

def response(self, flow: http.HTTPFlow):
    host = flow.request.pretty_host
    if host in LOCAL_TOOL_HOSTS:
        return  # jangan pernah capture traffic ke tool sendiri, terlepas dari scope filter manapun
    if host not in ACTIVE_SCOPE_WHITELIST:
        return  # enforce whitelist secara ketat, jangan capture apapun di luar scope aktif
    ...
```

**Prosedur recovery:** DB scope `infomaniak` yang sekarang **harus di-clear dan re-capture dari nol** setelah fix di atas diterapkan, karena data existing kemungkinan besar campur sampah vendor JS milik tool sendiri:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('data/jxs_storage.db')
conn.execute(\"DELETE FROM js_files WHERE scope = 'infomaniak'\")
conn.execute(\"DELETE FROM findings WHERE js_file_id NOT IN (SELECT id FROM js_files)\")
conn.commit()
"
```

**Operational rule ke depan:** jangan pernah buka UI `jxs` (`localhost:5173`) di browser yang sama dengan proxy capture aktif. Idealnya pakai browser/profile terpisah — 1 untuk browsing target (proxy aktif), 1 untuk lihat UI `jxs` (proxy nonaktif).

## 8m. CLI Mode (standalone, tanpa UI) — gap baru ditemukan dari pengalaman pakai subjs/JSFinder

Bangkit punya pengalaman dengan tools sejenis (`subjs`, `JSFinder`) yang jalan murni CLI tanpa UI, cocok buat quick scan tanpa nunggu render graph. `jxs` butuh mode setara ini, terpisah dari UI, supaya bisa dipakai cepat di kondisi:
- Extraction cepat tanpa render graph 14000 node yang bikin browser hang
- Otomasi/scripting (misal dijalankan dari CI script pribadi atau cron recon)

```bash
# Spek command (tambahan ke Module Reference)
jxs scan --scope infomaniak --output findings.json --no-ui
jxs scan --url-list js.txt --format subjs  # kompatibel input format mirip subjs/JSFinder
```

Output default: JSON list findings (bukan render graph), supaya bisa langsung di-pipe ke `jq` atau tool lain sesuai kebiasaan Bangkit. Module `src/cli/jxs_cli.py` baru, reuse Extraction Engine yang sama dengan UI (bukan logic terpisah) — cuma beda entry point dan output format.

## 8n. Large File Handling — ✅ DIBUKTIKAN (2026-07-23, stress-test nyata)

**Status implementasi yang akurat:** Chunking per-baris (`CHUNK_SIZE_LINES = 5000`) yang didesain di atas **tidak pernah dibangun**. Implementasi aktual di `extractor.py` adalah **whole-file scan** — seluruh konten file di-decode ke string lalu `pattern.finditer(content_str)` dijalankan sekali ke seluruh konten. Tidak ada loop per-baris, tidak ada chunk buffer.

**Temuan stress-test (file nyata dari NASA dump):**

| File | Ukuran | Load | Scan (10 pattern) | RAM Δ | Matches |
|------|--------|------|-------------------|-------|---------|
| `plotly-strict.min.js` | 10.5 MB | 0.05s | **5.4s** | ~0 MB | 313 |
| `ne_10m_admin_0_countries_usa.js` | 21.6 MB | 0.03s | **8.3s** | ~0 MB | 0 |
| `global-nav.regex.js` | 79.8 MB | 0.52s | **32.5s** | ~0 MB | 14 124 |

*Semua run tanpa crash, tanpa MemoryError, tidak ada catastrophic backtracking.*

**Kesimpulan berdasarkan data:**

- Whole-file scan **terbukti cukup** untuk file sampai 80 MB — tidak perlu chunking untuk rentang ukuran yang realistis di target bug bounty.
- Scan time ~0.25s/MB (dominasi `auth_function` dan `dom_sink` pattern).
- Memory overhead dari regex kecil (<2 MB delta), bottleneck adalah RAM untuk menampung string konten file itu sendiri (~1× ukuran file).
- **Chunking tidak diperlukan untuk sekarang.** Jika di masa depan ada file >200 MB yang perlu di-scan, baru evaluasi ulang.

**Gap yang ditemukan stress-test (perlu tindak lanjut, bukan blocker):**

1. **`dom_sink` lambat di file besar**: 7.5s di file 80 MB (dominan), `auth_function` 1.7s di file 22 MB. Keduanya acceptable tapi perlu dimonitor jika ada banyak large bundle. *Prioritas: low, bukan blocker 8m.*
2. **`high_entropy` noise tinggi**: 6 353 matches di 1 file (banyak CSS class name ikut match) — false-positive filter perlu diperkuat. *Prioritas: medium, dikerjakan setelah 8m.*
3. **`line_number` tidak berguna untuk minified**: nilai selalu kembali ke baris 1 karena minified JS adalah satu baris panjang. Ini *known limitation*, bukan bug.

**MAX_FILE_SIZE_BYTES — threshold berdasarkan data, bukan tebakan:**

Berdasarkan benchmark aktual: scan 80 MB = **32.5s**. Skala ~0.4s/MB. Untuk pipeline acceptable (<30s per file), batas yang realistis adalah **~75 MB** — lebih konservatif dari 100 MB yang awalnya diasumsikan. File di atas 75 MB di-skip dengan log `WARN: file too large, skipping extraction`. Threshold ini harus dikodekan eksplisit di `extractor.py` sebelum 8m (CLI mode) dikerjakan.

```python
# Tambahkan ke extractor.py — di atas BEAUTIFY_SIZE_THRESHOLD
MAX_SCAN_SIZE_BYTES = 75 * 1024 * 1024  # 75 MB — berbasis benchmark: 80 MB = 32.5s (batas ~30s)
# File > 75 MB: simpan metadata ke js_files (captured), skip extraction, status='skipped_too_large'
```

## 8o. Vendor/Design JS vs Logic JS — ✅ RESOLVED (2026-07-13)

~~Temuan dari 8l mengonfirmasi filter vendor classifier belum benar-benar jalan~~

**Status sekarang:** Fixed sepenuhnya. Root cause adalah **tiga bug regex terpisah** di `BUILD_HASH_PATTERN`, bukan masalah urutan call atau library list yang ketinggalan.

---

### Validasi awal yang memicu investigasi (dua kasus konkret)

1. **Stencil vDOM diffing** — ditemukan di `module-ksuite/build/p-3f3f9509.entry.js`:
   ```javascript
   // virtual DOM reconciler Stencil/Preact — innerHTML = dari vDOM internal, bukan attacker input
   (u || c) && (u && (c && u.__html == c.__html || u.__html === e.innerHTML)
     || (e.innerHTML = u && u.__html || ""))
   ```
   File ini ter-classify vendor (pure hex hash, cocok dengan pattern lama `[a-f0-9]`). File saudaranya (`p-vUKPA-Wq.js`, `p-Cn0TKsE0.js`, dll) tidak — karena pakai Stencil base62.

2. **Angular webpack bundle** — ditemukan di `common.js?ver=26dd641bbae9828e`:
   Hash cache-busting ada di query string, bukan filename. Pattern lama tidak scan QS.

---

### Root Cause — Tiga Bug Regex di `BUILD_HASH_PATTERN`

| Bug | Pattern Lama | Fix | Contoh yang Miss |
|---|---|---|---|
| **B1: Stencil base62** | `p-[a-f0-9]{6,}` (hex-only) | `p-[a-zA-Z0-9_\-]{5,}` (alphanumeric) | `p-vUKPA-Wq.js`, `p-Cn0TKsE0.js` |
| **B2: Vite base64url** | `name.[a-f0-9]{8,}.js` (hex-only) | `name.[a-zA-Z0-9_\-]{8,}.js` + dash-sep | `main-hNWVrx56.js`, `useFramesStore-Ck056IKp.js` |
| **B3: QS hash** | tidak ada | `QUERY_HASH_PATTERN`: `.js?ver=HASH` | `common.js?ver=26dd641bbae9828e` |

- B1 & B2: Stencil memakai **base62** untuk hash chunk-nya, Vite memakai **base64url** — keduanya mengandung uppercase letters yang bukan hex. Hanya file yang hash-nya kebetulan pure hex (`p-3f3f9509`) yang ter-detect sebelum fix.
- B3: Angular/webpack Angular sering serve file dengan nama generik (`common.js`, `main.js`) tapi tambahkan cache-busting hash di query string `?ver=`. Ini tidak pernah dicovery oleh pattern sebelumnya.

---

### Dampak Bug

- Sebelum fix: **6,681 High findings** (16,577 total) — vendor Stencil/Vite/Angular bundle ikut ngontribusi sebagai "custom"
- Setelah semua tiga bug difix: **0 High** dari bundle files (semua ter-downgrade ke Low/Medium via vendor downgrade map)

---

### Angka Final Post-Fix

| Severity | Count | File sumber |
|---|---|---|
| **High** | **1** | `innerHTML` di `init.js?version=latest` — custom Infomaniak login component, legitimate finding |
| **Medium** | ~119 | navigation_sink, endpoint (perlu manual verify) |
| **Low** | ~586 | vendor bundle findings (downgraded) |
| **Info** | ~4,159 | high_entropy, auth_function |
| **Total** | ~4,865 | dari 175 JS files scope infomaniak |

> **Note:** `init.js?version=latest&project=login` ter-detect **custom** dengan benar — `?version=latest` tidak match `QUERY_HASH_PATTERN` karena value-nya adalah kata bukan hash (8+ alphanumeric). Pattern hanya match `?ver=HASH{8+}`. `innerHTML` di file ini adalah finding legitimate yang perlu manual review.



---

### Known Limitation yang Tersisa

**Limitation permanen:** pendekatan static list + hash-pattern ini **selalu ketinggalan** terhadap bundler format baru yang belum diketahui. Setiap kali ada format hash baru yang tidak match, false positive akan muncul lagi sampai pattern di-update.

**Future improvement (Phase 2+, bukan sekarang):** signature-based detection — cek karakteristik konten file (densitas variable single-letter, absensi domain-specific naming) yang tidak bergantung format nama file.



## 8p. `resolved_url` & `target_url` Field — Findings Schema Update (REVISI)

Gap awal (8p versi lama): `resolved_url` cuma menunjuk ke JS file **sumber** yang mengandung match — bukan ke resource yang **direferensikan** di dalam match itu sendiri. Ini menyebabkan kegagalan verifikasi manual: tip UI "search di Burp Proxy History" gagal untuk kasus seperti `sourcemap` (`match_value: frontendFixes.bundle.js.map`), karena yang perlu dicari/dibuka bukan file JS sumbernya, tapi file `.map` yang direferensikan di dalamnya — dua URL yang berbeda.

**Skema final `findings` table:**
````python
findings_row = {
    "id": int,
    "js_file_id": int,
    "type": str,              # "dom_sink" | "endpoint" | "sourcemap" | "secret_param" | ...
    "match_value": str,       # raw match apa adanya, TIDAK diubah
    "severity": str,          # hasil otomatis dari Tagging Engine (4.4)
    "resolved_url": str,      # URL JS FILE SUMBER (tempat match ditemukan) — untuk trace balik "file mana"
    "target_url": str,        # BARU — hasil urljoin(resolved_url, match_value): URL RESOURCE yang direferensikan
    "review_status": str,     # BARU — lihat definisi di bawah
    "review_note": str,       # BARU — catatan manual bebas
}
````

`target_url` dihitung pakai `urllib.parse.urljoin(resolved_url, match_value)` — resolve path relatif (sourcemap, endpoint) terhadap base URL file sumbernya, menghasilkan URL absolut yang bisa langsung dibuka/di-fetch. Berlaku untuk semua `type` yang match_value-nya berupa path/filename relatif (`sourcemap`, `endpoint`), tidak berlaku untuk match yang sudah berupa keyword/pattern murni (`dom_sink`, `secret_param` — untuk tipe ini `target_url` = `resolved_url`, sama saja).

**Revisi UI Burp tip — dari 1 saran jadi 2 skenario eksplisit** (karena Burp Community Ctrl+F cuma cari di history yang sudah tercapture, bukan universal endpoint search):

```
💡 Verifikasi manual:
1. Kalau target_url ini SUDAH pernah ter-capture di scope aktif kamu — search nama 
   file-nya di Burp Proxy History (Ctrl+F), misal "frontendFixes.bundle.js.map".
2. Kalau belum pernah muncul di history — buka target_url LANGSUNG di browser 
   (dengan session aktif jika perlu), untuk cek apakah resource itu accessible atau 
   balik 404/SPA-fallback.
```

## 8p-1. Review Status Tracking — Findings Workflow State

**Masalah yang ditangani:** dengan puluhan scope aktif (multi-program YWH/H1), severity mentah (High/Medium/Low) tidak cukup — tidak ada cara membedakan finding yang sudah dicek manual vs yang belum, tanpa harus mengingat semuanya di kepala.

**Field baru (sudah termasuk di skema 8p di atas): `review_status`, `review_note`.**

````python
REVIEW_STATUS_VALUES = [
    "unreviewed",       # DEFAULT — belum dicek sama sekali
    "checked_fp",       # sudah dicek manual, ternyata false positive
    "checked_benign",   # valid match tapi bukan bug (misal public API key, defensive code)
    "confirmed_bug",    # sudah dicek, VALID bug/misconfig — siap di-report
    "reported",         # confirmed_bug DAN sudah disubmit ke program
]
````

**UI requirement:**
- Dropdown kecil di detail panel tiap finding untuk update `review_status` + isi `review_note` bebas.
- Default filter tampilan: `review_status = unreviewed` — supaya scope dengan ratusan finding tidak membanjiri layar dengan yang sudah pernah dicek.
- Summary count per scope: tampilkan breakdown `unreviewed / checked_fp / checked_benign / confirmed_bug / reported` di header scope, bukan cuma total severity — ini yang menjawab kebutuhan "gimana cara gak kewalahan pas hunting 20 scope sekaligus".

## 8q. katana Integration — Fast URL/JS Discovery Layer (baru, gap dari riset NASA)

**Prasyarat implementasi: 8m (CLI mode) harus selesai lebih dulu.** katana tidak punya entry point sendiri di `jxs` — dia dipanggil sebagai subprocess dari dalam `jxs scan` (CLI mode), bukan komponen berdiri sendiri. Jangan kerjakan 8q dan 8m paralel; 8m adalah dependency keras, bukan nice-to-have duluan.

Ditemukan lewat riset manual NASA (2447 file JS di-dump, sebagian besar hasil grep manual dari ribuan file) — dibutuhkan **layer discovery cepat** sebelum masuk ke Capture module yang sudah ada, khususnya untuk target dengan subdomain/endpoint sangat banyak (NASA punya puluhan subdomain aktif).

**Posisi katana di pipeline — layer BARU, bukan pengganti Playwright/mitmproxy:**

| Tool | Layer | Fungsi |
|---|---|---|
| katana | **Capture — fast discovery** (baru) | Crawl cepat URL/JS link, termasuk JS-in-JS reference via flag `-jc` |
| Playwright | Capture — on-demand deep crawl | Auto-click, capture state-dependent JS (butuh render penuh) |
| mitmproxy | Capture — passive mirror | JS yang muncul dari browsing manual real |

katana **tidak menggantikan** dua mode yang sudah ada — dia layer tambahan untuk **broad initial discovery** sebelum deep-dive pakai Playwright/manual browsing.

**Scope enforcement — WAJIB, bukan opsional (gap yang diperbaiki dari draft awal):**

Default katana dengan `-d 3` (depth 3) akan mengikuti **semua link yang ditemukan**, termasuk domain eksternal kalau ada external link di kedalaman crawl itu. Tanpa filter eksplisit, ini scope leak persis yang diwanti-wanti prinsip 4.2 (data campur antar program = risiko out-of-scope testing).

**Keputusan wajib: dua lapis enforcement, bukan cuma andalkan flag katana.**

```bash
# Lapis 1 — batasi katana sendiri di level crawl pakai native flag
katana -u https://target.com -jc -d 3 \
  -cs "target.com,*.target.com" \
  -o katana_urls_raw.txt
```
`-cs` (crawl-scope) adalah flag native katana untuk membatasi crawl tetap di domain/subdomain tertentu — ini lapis pertama, tapi **tidak boleh dipercaya sendirian** karena flag CLI bisa lupa di-set atau salah ketik.

```python
# Lapis 2 — post-filter wajib di kode jxs sebelum data masuk ke Capture module,
# reuse host_whitelist yang SAMA dari scope_config (4.2), jangan re-define terpisah
def filter_katana_output(raw_urls: list[str], scope_config: dict) -> list[str]:
    whitelist = scope_config["host_whitelist"]
    filtered = []
    for url in raw_urls:
        host = urlparse(url).hostname
        if any(host == w or host.endswith(f".{w}") for w in whitelist):
            filtered.append(url)
        # else: silently drop, TIDAK dimasukkan ke log sebagai error — ini expected behavior
    return filtered
```

Lapis 2 ini **wajib** berjalan terlepas dari apakah `-cs` di lapis 1 berhasil diset dengan benar atau tidak — prinsipnya sama seperti fix 8l (self-capture contamination): jangan percaya satu titik kontrol saja, enforce ulang di titik masuk data ke storage.

**Command spec (update, dengan scope enforcement):**
```bash
katana -u https://target.com -jc -d 3 -cs "target.com,*.target.com" -o katana_urls_raw.txt
# lapis 2 filter dijalankan otomatis di dalam jxs scan, bukan langkah manual terpisah
```

**Integrasi ke Capture module (bukan pipeline terpisah):** hasil yang sudah lolos filter_katana_output() di-feed ke fungsi `save_js_file()` yang sama dipakai mitmproxy addon (4.1) — download tiap URL, hash, simpan ke `js_files` table dengan `source: "katana"` sebagai metadata tambahan (bukan tabel/skema baru).

**Kenapa flag `-jc` penting untuk kasus NASA/WordPress:** katana dengan `-jc` otomatis extract link yang di-reference **di dalam** file JS (misal endpoint `wp-json/...` yang dipanggil via `fetch()`), bukan cuma link di HTML — ini mempercepat discovery endpoint WordPress REST API yang selama ini dicari manual pakai `rg wp-json`.

**Definisi Done (update, tambah kriteria scope):**
1. katana berhasil discover minimal jumlah unique JS URL yang sama atau lebih banyak dari hasil manual crawl Playwright di 1 target test yang sama, dalam waktu <30 detik untuk target skala menengah (100-500 halaman)
2. **Scope test wajib:** jalankan katana ke target yang diketahui punya external link di beberapa halaman (misal link ke CDN pihak ketiga atau social media), verifikasi manual bahwa `filter_katana_output()` benar-benar men-drop semua URL di luar `host_whitelist` — hitung: 0 row masuk ke `js_files` table dengan host di luar whitelist, tanpa terkecuali.

## 8r. Traceability Mandate — Pelajaran dari NASA Dump (2447 files)

**Insiden:** riset manual NASA menghasilkan 2447 file grep/dump (`eventsearch/`), tapi file-file besar (`sink1.txt` 37MB, `source1.txt` 32MB, `global-nav.regex.js` 84MB) adalah **hasil concatenate/grep dari banyak file berbeda**, bukan file asli per-URL. Begitu match ditemukan di file gabungan ini, **jejak balik ke JS file/URL asal hilang** — persis masalah yang sudah diantisipasi lewat `resolved_url` (8p), tapi ini bukti nyata kenapa field itu wajib ada dari awal proses, bukan ditambah belakangan.

**Prinsip wajib untuk `jxs` (mencegah insiden ini terulang):** setiap byte JS yang masuk ke Extraction Engine **HARUS** sudah terikat ke 1 `js_file_id` yang valid **sebelum** proses grep/regex apapun dijalankan. `jxs` tidak boleh punya mode "scan file lepas tanpa metadata sumber" — bahkan CLI mode (8m) yang menerima `--url-list` harus tetap resolve tiap baris URL jadi 1 row `js_files` dulu (download individual, bukan gabungan) sebelum extraction jalan.

**Implikasi ke CLI mode (8m):** command `jxs scan --url-list js.txt` **wajib** mendownload dan menyimpan tiap URL sebagai file/row terpisah di `js_files` — tidak diperbolehkan menerima input berupa "1 file besar hasil gabungan manual" seperti pola `eventsearch/`. Kalau user (Bangkit atau siapapun) sudah kadung punya dump gabungan, itu hanya boleh dipakai sebagai **stress-test data untuk 8n (chunking)**, bukan input produksi untuk mencari finding real.

## 8s. XSS Advisor — Payload Dictionary Structure (referensi dari PayloadsAllTheThings)

Klarifikasi posisi PayloadsAllTheThings/referensi payload publik lain: ini **knowledge base untuk manusia** (narrative writeup), bukan structured data yang bisa langsung di-*ingest* otomatis oleh `jxs`. Integrasi yang benar adalah ekstraksi manual kategori payload ke dictionary kecil di kode, bukan crawl/import seluruh repo.

**Struktur dictionary (Module: XSS Advisor, 8c):**
```python
XSS_ADVISOR_PAYLOADS = {
    "innerHTML": {
        "context": "HTML injection langsung ke DOM",
        "sample_payloads": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        "source_ref": "PayloadsAllTheThings - XSS Injection",
    },
    "document.write": {
        "context": "Sama seperti innerHTML tapi dieksekusi saat parse, bisa break out dari script tag",
        "sample_payloads": ["</script><script>alert(1)</script>"],
        "source_ref": "PayloadsAllTheThings - XSS Injection",
    },
    "location.hash_to_innerHTML": {
        "context": "DOM XSS klasik — hash tidak pernah dikirim ke server, harus dicek client-side saja",
        "sample_payloads": ["#<img src=x onerror=alert(document.domain)>"],
        "source_ref": "PayloadsAllTheThings - DOM XSS",
    },
    # tambah kategori sesuai sink type yang ditemukan Extraction Engine
}
```

Advisor mencocokkan `type` dan konteks sumber (misal apakah value berasal dari `location.search`/`location.hash` — dari hasil trace source→sink) ke key dictionary yang sesuai, lalu tampilkan `sample_payloads` sebagai rekomendasi teks manual test — **tidak pernah auto-fire**, konsisten dengan Non-Goals (section 3).

## 8t. PoC Export — Findings → Snippet Writeup

**Tujuan:** begitu finding di-mark `confirmed_bug`, generate draft writeup markdown otomatis per finding — mengurangi kerja copy-paste manual dari UI ke dokumen laporan.

**Command:**
````bash
jxs export --scope infomaniak --status confirmed_bug
````

**Struktur output** — 1 file per finding, path mengikuti nama JS file sumber:
targets/<scope_name>/<target-jsfile>/snippet.md

Contoh: `targets/infomaniak/frontendFixes.bundle/snippet.md`

**Isi template (persis sesuai spek, minimal dan siap tempel ke laporan):**
````markdown
## Finding: [type] di [resolved_url]
- **Match:** `match_value`
- **Target URL:** `target_url`
- **Severity:** [severity] — *hasil otomatis jxs, dapat berubah sesuai CVSS calculator manual*
- **Snippet:**
```js
[code_snippet]
```
````

**Catatan implementasi:**
- Severity yang tercetak adalah nilai otomatis dari Tagging Engine (4.4) — TIDAK di-lock, karena penilaian final untuk laporan biasanya disesuaikan lagi pakai CVSS calculator manual sesuai kebijakan program. Template secara eksplisit menandai ini sebagai starting point, bukan nilai final.
- File `.js` mentah (raw content) TIDAK otomatis ikut ter-export — biar export tetap ringan. Kalau butuh source lengkap sebagai lampiran bukti, tambahkan flag opsional:
````bash
  jxs export --scope infomaniak --status confirmed_bug --include-source
````
  yang menyalin `js_files.content` ke `targets/<scope>/<target-jsfile>/source.js` di folder yang sama.

## 8u. Validation Checklist — Alur Wajib Sebelum Finding Jadi Laporan

Checklist ini memformalkan proses yang sudah berulang kali dipakai manual (kasus Partytown, sourcemap NASA, dll) menjadi langkah konsisten, supaya tidak perlu mikir ulang dari nol tiap kali menemukan finding baru.

```
□ 1. Cek source data: apakah variable yang masuk ke sink berasal dari attacker-controlled 
     input (location.search, URLSearchParams, postMessage, form input) ATAU dari internal 
     config/state milik library/framework?
     → Internal config/state: review_status = checked_benign. SELESAI, bukan bug.

□ 2. Kalau attacker-controlled: buka target_url langsung, konfirmasi resource itu benar-benar 
     accessible dan responnya sesuai ekspektasi (bukan SPA fallback / soft-404 yang balas 200).
     → Tidak accessible / fallback: review_status = checked_fp. SELESAI.

□ 3. Kalau accessible dan attacker-controlled: reproduce manual di browser/Burp Repeater, 
     capture request-response asli sebagai bukti.

□ 4. Reproduce berhasil: review_status = confirmed_bug. Jalankan PoC export (8t) sebelum 
     mulai menulis laporan ke program.

□ 5. Setelah submit ke YWH/H1: review_status = reported.
```

## 8v. Storage Scaling — Open Question untuk Multi-Program Hunting

**Belum diputuskan, dicatat sebagai open question sebelum scale ke puluhan program (20+ scope YWH/H1 sekaligus):**

- `js_files.content` (BLOB penuh) disimpan permanen per scope. Dengan puluhan program aktif dan beberapa program punya bundle besar (lihat 8n — file sampai 80MB), `jxs_storage.db` berpotensi membengkak signifikan.
- Pertanyaan yang perlu dijawab sebelum benar-benar scale:
  1. Apakah `content` perlu tetap disimpan penuh selamanya, atau setelah extraction selesai dan `target_url`/snippet sudah tersimpan di `findings`, `content` BLOB besar bisa di-nullify/archive dari DB aktif (karena bukti utama sudah ada di 8t export)?
  2. Apakah perlu retensi policy per scope — scope yang sudah "selesai" hunting (semua finding di-review) bisa di-export penuh lalu dikosongin dari DB aktif untuk hemat storage?
- **Tidak diputuskan sekarang** — didesain ulang setelah 8t (PoC export) berjalan, karena 8t justru jadi mekanisme yang memungkinkan `content` BLOB besar dibuang tanpa kehilangan bukti (sudah ter-export duluan).

## 8w. Insecure Storage Detection — Backlog, Unblocked

**Status: Backlog — unblocked (8m ✅, 8q ✅), belum diprioritaskan.**

Deteksi penggunaan `localStorage` / `sessionStorage` sebagai penyimpanan data sensitif (token, credential, PII) di JS client-side. Masuk dalam batas regex/pattern-matching — tidak butuh data-flow analysis.

> **IndexedDB:** disebut dalam konteks umum "insecure browser storage" tapi **tidak di-cover pattern MVP ini**. IndexedDB API berbasis transaction (`db.transaction().objectStore().put()`) — tidak ada string-literal key di titik penyimpanan yang bisa digrep secara akurat tanpa AST context. False positive rate akan terlalu tinggi. Masuk backlog terpisah jika ada kasus nyata ditemukan di field.

**Pattern target — severity DIPISAH berdasarkan confidence:**

```python
import re

# WAJIB compile dengan re.IGNORECASE — key convention bisa camelCase (authToken),
# snake_case (auth_token), atau CONSTANT_STYLE (AUTH_TOKEN)

# Severity: HIGH — JWT/token literal value tersimpan langsung
# Confidence tinggi: prefix eyJ sangat spesifik ke JWT (base64 dari '{"'), FP rate rendah
INSECURE_STORAGE_HIGH = [
    r'localStorage\.setItem\([^,]+,\s*[\'"]eyJ[A-Za-z0-9_-]{10,}\.',   # JWT literal di-store
    r'sessionStorage\.setItem\([^,]+,\s*[\'"]eyJ[A-Za-z0-9_-]{10,}\.', # JWT literal ke sessionStorage
]

# Severity: MEDIUM — keyword MENGANDUNG kata sensitif (substring, bukan exact match)
# [^\'"]* di kedua sisi keyword supaya 'authToken', 'access_token', 'AUTH_TOKEN' ikut match
# Confidence moderate: nama key sensitif tapi value bisa saja bukan credential nyata
INSECURE_STORAGE_MEDIUM = [
    r'localStorage\.setItem\([\'"][^\'"]*(?:token|auth|password|secret|credential|session|api[_-]?key)[^\'"]*[\'"]',
    r'sessionStorage\.setItem\([\'"][^\'"]*(?:token|auth|password|secret|credential|session|api[_-]?key)[^\'"]*[\'"]',
]

# Severity: LOW/INFO — getItem dengan keyword sensitif (substring, sama seperti MEDIUM)
# Evidence penggunaan credential dari storage, perlu trace ke mana value dipakai
INSECURE_STORAGE_LOW = [
    r'localStorage\.getItem\([\'"][^\'"]*(?:token|auth|password|secret|api[_-]?key)[^\'"]*[\'"]',
]

INSECURE_STORAGE_HIGH_RE = [re.compile(p, re.IGNORECASE) for p in INSECURE_STORAGE_HIGH]
INSECURE_STORAGE_MEDIUM_RE = [re.compile(p, re.IGNORECASE) for p in INSECURE_STORAGE_MEDIUM]
INSECURE_STORAGE_LOW_RE = [re.compile(p, re.IGNORECASE) for p in INSECURE_STORAGE_LOW]
```

**Severity mapping:**

| Pattern | Severity | Reasoning |
|---------|----------|-----------|
| JWT literal (`eyJ...`) di-`setItem` | **High** | Credential eksplisit tersimpan — XSS langsung dapat token asli |
| Keyword key match (`token`/`password`/dll) di `setItem` | **Medium** | Butuh konfirmasi apakah value benar-benar sensitive |
| Keyword key match di `getItem` | **Low/Info** | Evidence penggunaan, bukan storage — perlu trace ke mana value dipakai |

**Batasan fundamental (wajib didokumentasikan, gaya 8o):**

1. **String literal key only — miss jika key pakai constant/variable.** Pattern hanya match kalau key ditulis langsung sebagai string literal di titik pemanggilan. Contoh yang **tidak akan tertangkap:**
   ```js
   const AUTH_KEY = 'auth_token'                // constant
   localStorage.setItem(AUTH_KEY, tokenValue)   // MISS — regex tidak resolve AUTH_KEY
   ```
   Ini bukan bug implementasi, ini batas fundamental regex. False negative rate signifikan di codebase TypeScript/Angular yang lazim pakai enum/constant untuk storage keys. Saat manual review temukan pattern seperti ini, tambahkan ke `whitelist_note`.

2. **Value tidak diverifikasi (untuk MEDIUM pattern).** `localStorage.setItem('token', someVar)` match meski `someVar` isinya token CSRF yang aman atau ID session non-sensitive. Manual confirm wajib: DevTools → Application → Storage → lihat isi aktual saat runtime.

3. **JWT pattern (HIGH) lebih reliable tapi bisa salah.** `eyJ` adalah prefix Base64url dari `{"` yang memang khas JWT, tapi library encode lain bisa menghasilkan prefix sama. Konfirmasi bahwa yang ditemukan adalah JWT auth token, bukan state param OAuth atau CSRF token yang ikut encode Base64.

**Chainability (`getItem` → network header) — sengaja di-drop dari scope MVP 8w:**

Pattern `localStorage.getItem('token')` yang hasilnya di-set sebagai `Authorization: Bearer ...` di fetch request adalah finding bernilai lebih tinggi (storage-to-header chaijn = eksfiltrasi token via XSS lebih clean). Namun mendeteksinya butuh **2-node pattern matching** — match `getItem` di baris X, lalu trace variabel hasilnya ke baris Y sebagai request header. Ini keluar dari single-regex territory dan masuk ke data-flow tracking ringan yang di luar scope `jxs` (lihat 1a, batasan fundamental).

Keputusan: **drop dari MVP 8w, bukan kelupaan.** Reviewer yang melihat advisory `localStorage.getItem('auth_token')` sudah punya konteks untuk melanjutkan trace secara manual ke arah header injection — itu cukup sebagai narrowing output sesuai posisi `jxs`.

**Gate — dijalankan 2026-07-25, 439 JS files, 2 scope (infomaniak + nasa):**

| Pattern | Sebelum fix | Penyebab FP | Setelah fix | Catatan |
|---------|------------|-------------|-------------|---------|
| `storage_jwt` (HIGH) | 0/0 match | — | 0/0 | Tidak ada JWT literal di 2 scope aktif. Pattern logically sound tapi belum bisa diukur FP rate — butuh scope dengan auth flow yang menyimpan JWT literal |
| `storage_set` (MEDIUM) | 15 match, **FP 60%** (9/15) | `token` match `tokenExpired`; `session` match `__testSession__` | 6 match, **FP 0%** (0/6) | Fix: tambah `(?![Ee]xpir)` setelah `token`, hapus bare `session` → ganti `session_id` |
| `storage_get` (LOW) | 9 match | — | 7 match, **FP ~0%** | Semua `IKToken` — dikonfirmasi dipakai sebagai WebSocket auth header (low finding yang valid) |

**Sisa false negative yang diketahui (tidak bisa di-fix dengan regex):**
- `localStorage.setItem(KEY, val)` di mana `KEY` adalah constant/variable — MISS by design (batasan 1)
- `IKTokenExpire` masih bisa match di codebase lain yang menulis `setItem("IKTokenExpire", actualToken)` — kecil kemungkinannya tapi tidak bisa di-exclude tanpa value inspection

## 8x. Obfuscation Detection & LLM Handoff — Backlog

**Problem:** file JS dengan obfuscation tingkat lanjut (string encoding, variable 
mangling, self-decoding eval) membuat SEMUA regex pattern (4.3, 8w) gagal total — 
bukan cuma miss sebagian, tapi 0% coverage karena tidak ada string plain-text yang 
bisa dicocokkan.

**Deteksi (bukan deobfuscate — cuma flag):**
```python
def is_likely_obfuscated(content: str) -> bool:
    # heuristic sederhana, bukan definitif
    hex_var_ratio = len(re.findall(r'_0x[a-f0-9]{4,}', content)) / max(len(content), 1)
    single_char_func_density = len(re.findall(r'function [a-zA-Z]\(', content))
    has_eval_decoder = bool(re.search(r'eval\(function\(|atob\(|String\.fromCharCode', content))
    return hex_var_ratio > 0.001 or has_eval_decoder
```

**Kalau terdeteksi:** file di-tag `obfuscation_detected = True`, SEMUA regex findings 
dari file ini otomatis dapat catatan `"⚠️ Regex coverage rendah — file terdeteksi 
obfuscated, hasil scan TIDAK reliable"` — supaya user tidak salah percaya "0 findings 
= aman", padahal artinya "regex gak bisa baca".

**Handoff ke LLM (bukan built-in ke jxs, tapi bagian dari export flow 8t):**
```bash
jxs export --scope target --obfuscated-only --format llm-prompt
```
Generate file siap-paste ke LLM (Qwen/Claude/dst) berisi: isi file + instruksi standar 
("deobfuscate dan jelaskan maksud kode ini, fokus ke: API endpoint, credential, 
auth logic"). Ini BUKAN otomatisasi — user tetap manual paste ke LLM pilihan mereka 
dan baca hasilnya sendiri, `jxs` cuma nyiapin prompt-nya biar gak perlu copy-paste 
manual tiap kali.

**Cross-host correlation (untuk kasus 3-host saling terhubung):** kalau ada string 
literal / endpoint pattern yang SAMA PERSIS muncul di file dari host berbeda dalam 
1 scope (CDN + domain utama + JS API host) meski masing-masing obfuscated beda cara, 
itu indikasi arsitektur shared-secret antar service — worth cross-reference manual, 
bukan otomatis (di luar kemampuan regex).

**Status: Backlog, tidak diprioritaskan sebelum batch mode (86-host bug) selesai.**

## 8y. Source→Sink Proximity Heuristic — Narrowing Layer (Backlog, Unblocked)

Status: Backlog — unblocked (8m ✅, 8q ✅, 8w ✅), prioritas P1 setelah batch mode.

Problem yang ditangani:
Extraction Engine (4.3) menemukan source dan sink sebagai finding atomik terpisah.
Contoh nyata: `location.search` match di baris 2, `innerHTML =` match di baris 158.
Dua finding terpisah, tidak ada indikasi bahwa keduanya terhubung. Reviewer harus
manual scroll 156 baris untuk cek data-flow — ini bottleneck validasi utama.

Proximity heuristic BUKAN data-flow analysis (tetap di luar scope 1a). Ini hanya
flag: "source dan sink muncul dalam radius N baris yang sama → worth checking first."
Bukan vonis, tapi narrowing tajam sebelum manual trace.

Posisi di pipeline:
Dijalankan SETELAH beautify (kalau file <1.5MB, sesuai 8e), SEBELUM Tagging Engine
(4.4). Output: finding baru dengan `type: proximity_hit`, bukan modifikasi finding
existing. Source dan sink atomik tetap tersimpan sebagai finding terpisah — proximity
hit adalah layer tambahan, bukan pengganti.

Pattern definitions:

import re

PROXIMITY_RADIUS_LINES = 50  # post-beautify. Pre-beautify (minified): radius = 1
                             # karena minified JS = 1 baris panjang, proximity tidak
                             # bermakna. File >1.5MB (skip beautify, 8e) → proximity
                             # heuristic DISABLED untuk file tersebut.

SOURCES = [
    r"location\.(search|hash|href|pathname)",
    r"URLSearchParams",
    r"postMessage",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
    r"history\.pushState",
]

SINKS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"eval\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"dangerouslySetInnerHTML",
    r"Function\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
]

SOURCE_RE = [re.compile(p) for p in SOURCES]
SINK_RE = [re.compile(p) for p in SINKS]

def find_proximity_hits(content_lines: list[str], file_id: int) -> list[dict]:
    """
    Return list of proximity hit dicts.
    Called ONLY on beautified content (file <1.5MB).
    """
    source_matches = []
    sink_matches = []

    for i, line in enumerate(content_lines, 1):
        for src_re in SOURCE_RE:
            if src_re.search(line):
                source_matches.append((i, src_re.pattern, line.strip()))
        for sink_re in SINK_RE:
            if sink_re.search(line):
                sink_matches.append((i, sink_re.pattern, line.strip()))

    hits = []
    for src_line, src_pat, src_text in source_matches:
        for sink_line, sink_pat, sink_text in sink_matches:
            distance = abs(sink_line - src_line)
            if distance <= PROXIMITY_RADIUS_LINES:
                hits.append({
                    "js_file_id": file_id,
                    "type": "proximity_hit",
                    "source_line": src_line,
                    "sink_line": sink_line,
                    "distance": distance,
                    "source_pattern": src_pat,
                    "sink_pattern": sink_pat,
                    "source_snippet": src_text[:200],
                    "sink_snippet": sink_text[:200],
                    "severity": "HIGH" if distance <= 10 else "MEDIUM",
                    "match_value": f"src:{src_pat} → sink:{sink_pat} (Δ{distance}L)",
                })
    return hits

Severity mapping:

| Distance | Severity | Reasoning |
|----------|----------|-----------|
| ≤10 baris | HIGH | Source dan sink sangat dekat, kemungkinan besar connected |
| 11-50 baris | MEDIUM | Worth checking, tapi bisa jadi dua fungsi terpisah |
| >50 baris | Tidak di-flag | Di luar radius, noise terlalu tinggi |

Schema update — findings table:
Tidak ada kolom baru. Proximity hit disimpan sebagai row biasa di `findings` dengan
`type: "proximity_hit"`. Detail source/sink line disimpan di `match_value` (string)
dan `review_note` (JSON string, opsional). Ini konsisten dengan skema 8p — tidak
perlu migration table baru.

UI requirement:
- Node proximity_hit di React Flow: warna ORANYE (beda dari merah High biasa),
  label "PROXIMITY" di badge.
- Detail panel: tampilkan source snippet dan sink snippet side-by-side, dengan
  line number. Klik snippet → scroll ke baris di source viewer (kalau ada).
- Filter default: `type != proximity_hit` — supaya tidak membanjiri tampilan awal.
  User harus explicit enable filter "Show proximity hits" untuk melihatnya.
- Sort priority: proximity_hit HIGH muncul di atas finding High biasa saat sort
  by severity — karena ini sudah pre-narrowed, lebih actionable.

Batasan fundamental (wajib didokumentasikan, gaya 8o/1a):

1. BUKAN data-flow analysis. Source dan sink dalam 50 baris belum tentu connected.
   Bisa jadi dua fungsi terpisah yang kebetulan berdekatan. False positive rate
   akan signifikan — ini expected, bukan bug. Manual trace tetap wajib (8u step 1).

2. Minified file = proximity tidak bermakna. File >1.5MB (skip beautify, 8e) adalah
   1 baris panjang. Semua source dan sink "berjarak 0 baris" — proximity heuristic
   DISABLED untuk file ini. Flag `obfuscation_detected` (8x) juga auto-disable
   proximity untuk file tersebut.

3. Cross-file proximity tidak di-cover. Source di file A, sink di file B (via
   function call/import) tidak akan terdeteksi. Ini butuh module-level analysis
   yang di luar scope regex. Reviewer yang melihat proximity hit di file A tapi
   trace-nya leads ke file B harus manual cross-reference.

4. False negative via wrapper function. `sanitize(location.search)` lalu
   `innerHTML = sanitize()` tidak terdeteksi karena source dan sink tidak literal
   dalam radius yang sama — data-flow via function call invisible ke regex.
   Ini batas fundamental 1a, bukan implementasi yang bisa di-fix.

Gate — wajib dijalankan sebelum declare 8y "done":
- Test di scope infomaniak (175 JS files, 8o) dan nasa (2447 files, 8r).
- Hitung: berapa proximity_hit yang dihasilkan, berapa yang setelah manual trace
  (8u) ternyata connected vs false positive.
- Kriteria Done: FP rate < 60% untuk distance ≤10 (HIGH), < 80% untuk distance
  11-50 (MEDIUM). Kalau lebih tinggi, revisi radius atau pattern.
- Wajib verifikasi: 0 proximity_hit dari file >1.5MB (beautify skip) dan 0 dari
  file dengan `obfuscation_detected = True`.

Chainability dengan 8w (Insecure Storage):
Proximity hit `localStorage.getItem('token')` (source) → `innerHTML =` (sink)
dalam radius 10 baris adalah kandidat DOM XSS → token exfiltration yang sangat
kuat. Reviewer yang melihat kombinasi ini harus prioritaskan manual trace sebelum
finding lain. Ini bukan auto-chain (tetap manual), tapi proximity heuristic bikin
pola ini visible tanpa perlu scroll manual.

Cross-reference dengan 8x (Obfuscation):
File dengan `obfuscation_detected = True` (8x) auto-skip proximity heuristic.
Alasan: obfuscated code tidak punya line structure yang bermakna post-beautify
(beautify gagal atau menghasilkan output yang tidak merepresentasikan logic asli).
Proximity hit di file obfuscated = noise 100%.

## 9. Success Metric (Personal, bukan Business)

- Waktu dari "buka target baru" sampai "punya list JS + endpoint + issue ter-flag" turun dari manual (jam) jadi di bawah 10 menit
- Minimal 1 finding real (worth report) yang ketemu karena tool ini flag sesuatu yang kelewat kalau manual

## 10. Status Summary — Solid Checklist untuk "JS Finding Tool"

Ringkasan status tiap komponen inti, supaya jelas mana yang sudah teruji vs masih asumsi:

| Komponen | Status | Bukti |
|---|---|---|
| Capture (mitmproxy) | ✅ Jalan, dengan fix self-capture contamination | 8l — clear DB + host exclusion applied |
| Vendor classifier | ✅ Resolved, 3 bug regex sudah di-fix | 8o — 6681 High → 1 High valid setelah fix |
| DOM_SINK_PATTERN accuracy | ✅ Tervalidasi real case (Infomaniak `init.js`) | 8o — 1 legitimate High finding terkonfirmasi manual |
| resolved_url traceability | ✅ Masuk skema, prinsip diperkuat oleh insiden NASA | 8p, 8r |
| Large file handling (8n) | ✅ **Whole-file scan dibuktikan cukup** (bukan chunking) | Stress-test nyata: 80 MB = 32.5s, no crash, 1.9 MB RAM Δ — **chunking tidak diimplementasikan dan tidak diperlukan untuk sekarang** |
| katana integration | ✅ **Selesai** — `jxs scan --katana-url --katana-depth` + scope enforcement 2-lapis | src/capture/katana_runner.py — filter_katana_output() verified, KATANA_BINARY auto-detect |
| XSS Advisor payload dictionary | ✅ **Selesai** — 17 sink types, payload chips + testing steps di UI | 8s — XSS_ADVISOR_PAYLOADS, generate_advisory_full(), _enrich_advisories() |
| CLI mode (8m) | ✅ **Selesai dibangun** — `jxs scan / status / export / review` | src/cli/jxs_cli.py — reuse run_extraction(), verified live |

**Progress tracker:** ~~8n~~ ✅ ~~8m~~ ✅ ~~8q~~ ✅ ~~8s~~ ✅ ~~8p-1~~ ✅ ~~8t~~ ✅

**Pending / belum disentuh:**
- **8u** — ~~Validation Checklist ada di PRD sebagai teks (section 8u), tapi belum ada implementasi UI-nya.~~ ✅ **Selesai** — `ValidationChecklist` component di DetailPanel: 5 langkah kondisional, auto-sync `review_status` ke API pada step 4 (confirmed_bug) & step 5 (reported), progress bar, outcome badges.
- **8v** — Storage scaling open question. Belum ada keputusan soal retensi BLOB dan archive policy. Dapat ditinjau ulang setelah DB mulai terasa berat (>500MB).
- **8w** — ~~Insecure Storage Detection. Backlog, unblocked, belum diprioritaskan. Draft pattern sudah ada di section 8w.~~ ✅ **Selesai** — 3 pattern tiers (HIGH JWT, MEDIUM keyword-set, LOW keyword-get), integrated ke EXTRACTION_PATTERNS + Advisor.

**Untuk hunting aktif sekarang:** `jxs scan --katana-url <target> --scope <name>` untuk discovery, lalu `jxs scan --scope <name> --format table --severity high` untuk triage, lalu `jxs review <id> confirmed_bug` + `jxs export --scope <name> --status confirmed_bug` untuk writeup.