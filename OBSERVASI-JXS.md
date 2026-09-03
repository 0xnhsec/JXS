# 📋 Pendataan & Observasi Project `jxs`

> Hasil analisa menyeluruh folder `/home/ardxcryz/Projects/jxs`
> Tanggal observasi: 2026-08-26

---

## 1. Apa itu jxs?

`jxs` adalah **JavaScript Analysis & Mapping Tool untuk bug bounty recon** (author: Bangkit Eldhianpranata Pengestu / 0xnhsec, status MVP Phase 1). Alurnya:

```
Browser (proxy :8082) → mitmproxy addon → Burp (:8080) → Internet
                              ↓
                  data/jxs_storage.db (SQLite, WAL)
                              ↓
              Extraction Engine (regex patterns + mantra)
                              ↓
          FastAPI (:8888)  →  React Flow UI (Vite, :5173)
```

Enam fungsi utama:
1. **Capture** — mitmproxy addon pasif menangkap respons JS saat browsing lewat Burp.
2. **Extract** — pipeline regex mencari endpoint, DOM sink, sourcemap leak, secret.
3. **Detect** — fingerprinting tech stack (React, Next.js, WordPress, dll).
4. **Advise** — teks advisory XSS per temuan DOM sink (tanpa auto-fire payload).
5. **Visualize** — graph React Flow: JS file → findings.
6. **CLI** — `jxs scan/status/export/review` tanpa UI.

⚠️ Catatan penting dari README: jxs **tidak bisa jalan sendiri tanpa Burp Suite aktif** — urutan start wajib: Burp listener :8080 → mitmproxy addon :8082 → browser diarahkan ke proxy → baru browsing target.

---

## 2. Struktur Folder (semua direktori)

```
jxs/
├── .claude/                    # PRD & ide development
│   ├── PRD-jxs.md              # PRD utama project
│   ├── dontbuild-thisisjustsamp0lePRD.md
│   └── jxst/                   # idea.txt + PRD tambahan
├── assetmapper.js              # script mapping aset JS
├── data/
│   ├── jxs_storage.db (+ -shm/-wal)   # DB SQLite hasil capture
│   └── .gitkeep
├── dir.txt                     # catatan struktur direktori
├── logs/
│   └── jxs_capture_errors.log  # error log capture
├── requirements.txt            # deps Python (mitmproxy, jsbeautifier, fastapi, uvicorn, pytest, rich, click)
├── scope_config.json           # konfigurasi scope aktif
├── sample.json                 # contoh output
├── README-ew.md                # dokumentasi utama
├── jxss.png                    # arsitektur/screenshot
├── src/
│   ├── api/        main.py               # FastAPI server (703 baris)
│   ├── capture/    config.py             # loader scope_config.json
│   │               jxs_mitm_addon.py     # addon mitmproxy pasif (254 baris)
│   │               katana_runner.py      # integrasi katana crawler (384 baris)
│   ├── cli/        jxs_cli.py            # CLI entry point (677 baris)
│   ├── db/         schema.py             # DDL SQLite + koneksi WAL
│   │               migrations.py         # ALTER TABLE idempotent
│   ├── extraction/ extractor.py          # pipeline ekstraksi utama (362 baris)
│   │               patterns.py           # ⭐ SEMUA regex vuln JS (267 baris)
│   │               mantra_runner.py      # wrapper subprocess mantra (secret scanner)
│   │               vendor_classifier.py  # bedakan vendor bundle vs kode custom
│   ├── techstack/  detector.py           # deteksi tech stack ala Wappalyzer (432 baris)
│   ├── xss_advisor/ advisor.py           # generator advisory XSS (601 baris)
│   └── ui/                     # React Flow UI (Vite + d3/dagre) + dist build
├── tests/
│   ├── test_capture.py, test_extraction.py
│   └── fixtures/   fixture_dom_sinks.js, fixture_endpoints.js,
│                   fixture_minified.js, fixture_secrets.js, fixture_vendor.js
├── targets/                                # (direktori target)
├── vendor/                                 # tools pihak ketiga
│   ├── LinkFinder/     linkfinder.py       # ekstraktor endpoint dari JS
│   ├── JSFinder/       JSFinder.py         # pencari URL/subdomain dari JS
│   ├── js-beautify/                        # beautifier minified JS
│   ├── mantra/                             # Go secret/API key scanner
│   ├── Scrapling/                          # scraping lib
│   └── wappalyzer/                         # referensi fingerprint tech stack
├── home/ardxcryz/jxs/src/ui/   # ⚠️ SALAH TEMPAT — copy UI nyasar ke path absolut (harus dibersihkan)
└── .venv/                      # virtualenv Python 3.14 (~512 MB total folder)
```

---

## 3. ⭐ Pattern & Function untuk Grep Kandidat Vuln JS

Semua regex ada di `src/extraction/patterns.py`, dipakai oleh `src/extraction/extractor.py` melalui dict `EXTRACTION_PATTERNS`.

### A. Endpoint / API Path Discovery
| Nama | Fungsi | Severity |
|---|---|---|
| `ENDPOINT_PATTERN` | Path quoted dengan prefix sensitif: `/api\|/v1..\|/graphql\|/rest\|/gql\|/rpc\|/internal\|/admin\|/auth\|/oauth\|/login\|/logout\|/user\|/account\|/payment\|/checkout\|/order\|/webhook\|/callback\|/redirect\|/token\|/refresh\|/revoke/...` | medium |
| `FETCH_PATTERN` | `fetch('/...')`, `axios.get/post/put/patch/delete/request('/...')`, `XMLHttpRequest`, `.open('/...')` | medium |

### B. Sourcemap Leak
| `SOURCEMAP_PATTERN` | `//# sourceMappingURL=<url>` → source code asli terekspos | **high** |

### C. DOM Sinks (vektor XSS)
| Nama | Target | Severity |
|---|---|---|
| `DOM_SINK_PATTERN` | `innerHTML`, `outerHTML`, `dangerouslySetInnerHTML`, `document.write(ln)`, `eval`, `insertAdjacentHTML` (diikuti `[=(,{]`) | **high** |
| `NEW_FUNCTION_PATTERN` | `new Function(` — code execution | **high** |
| `ATTR_SINK_PATTERN` | `setAttribute(`/`setAttributeNS(` — bahaya kalau attr name/value tainted | medium |
| `NAVIGATION_SINK_PATTERN` | `location.href/assign/replace =`, `window.open(` — perlu verifikasi manual sumber tainted (URLSearchParams/postMessage/location.search) sebelum dinaikkan ke High | medium |

Eksklusi sadar FP: `textContent`, `innerText`, `createTextNode` TIDAK dianggap sink; `Function` standalone tidak match (hanya `new Function(`).

### D. Secret / Credential
| Nama | Target | Severity |
|---|---|---|
| `SECRET_PARAM_PATTERN` | Query param `?key=\|token=\|apikey=\|api_key=\|secret=\|auth=\|access_token=\|client_secret=\|password=\|passwd=\|pwd=\|bearer=` dengan value ≥16 char alfanumerik | **high** |
| `HIGH_ENTROPY_PATTERN` | String literal ≥32 char high-entropy (hardcoded secret hint) | info (FP tinggi) |

### E. Insecure Storage (PRD 8w)
| Nama | Target | Severity |
|---|---|---|
| `INSECURE_STORAGE_JWT_PATTERN` | `localStorage/sessionStorage.setItem(..., 'eyJ...')` — JWT literal | **high** |
| `INSECURE_STORAGE_SET_PATTERN` | `setItem('...token/auth/password/secret/credential/session_id/api_key...')` — sudah difix pakai lookahead `(?![Ee]xpir)` setelah FP test nyata (infomaniak, 439 files, FP 60%→~33%) | medium |
| `INSECURE_STORAGE_GET_PATTERN` | `getItem('...token/auth/password/secret/api_key...')` — trace manual ke mana dipakai | low |

Batasan terdokumentasi: hanya string-literal key (miss jika key via variabel), value tidak diverifikasi, IndexedDB tidak dicover.

### F. Info / Manual Review
| Nama | Target | Severity |
|---|---|---|
| `AUTH_FUNCTION_PATTERN` | `validateToken, checkAuth, isAdmin, isAuthorized, refreshSession, verifyJWT, decodeToken, parseJWT, checkPermission, hasRole, requireAuth, authenticate, authorize, getUser, currentUser` | info |
| `SECRET_WHITELIST_CONTEXT` | Konteks public-by-design (maps.googleapis.com, recaptcha, gtag/GA, facebook.net, cdnjs, jsdelivr, unpkg) → downgrade ke Info, bukan skip | — |

### G. Pipeline Ekstraksi (`extractor.py`)
Per JS file:
1. Ambil file ber-status `captured` → decode UTF-8 fallback.
2. `< 1.5 MB` → beautify via js-beautify; `≥ 1.5 MB` → regex langsung di minified.
3. Jalankan semua pattern di atas.
4. Whitelist context check → downgrade Info.
5. Vendor classification (`vendor_classifier.py`: filename pattern, minification ratio, signature comment, ukuran file → 'vendor'/'custom'/'unknown').
6. Mantra scan (subprocess, timeout 30s, JSON out; return `[]` aman bila mantra tak terinstall).
7. Simpan findings → update status `extracted`.

### H. XSS Advisor (`xss_advisor/advisor.py`)
Untuk setiap finding `dom_sink`, menghasilkan advisory spesifik per sink type: konteks, sample payloads (`<img src=x onerror=alert(document.domain)>`, `<svg onload=alert(1)>`, dsb), testing_steps manual, dan source_ref (PayloadsAllTheThings). **Tidak pernah auto-fire payload** (PRD Non-Goals).

---

## 4. Interface — CLI & API

### CLI (`python -m src.cli.jxs_cli`)
| Subcommand | Parameter penting |
|---|---|
| `scan` | `--scope`, `--url-list`, `--katana-url`, `--katana-all`, `--katana-depth` (default 3), `--katana-timeout` (600), `--output/-o`, `--format json\|table`, `--type`, `--severity`, `--review-status`, `--include-whitelisted`, `--limit` |
| `status` | `--scope` |
| `export` | `--scope` (wajib), `--status confirmed_bug`, `--include-source` → snippet.md |
| `review` | `finding_id`, `status`, `--note` |

Global: `--db`.

### FastAPI (`uvicorn src.api.main:app --port 8888`)
`GET /health` · `GET|POST /scopes` · `GET /scope/{s}/graph` · `GET /scope/{s}/findings` · `GET /scope/{s}/stats` · `GET /js-file/{id}` · `GET /js-file/{id}/content` · `POST /extract/{s}` · `POST /techstack/{s}` · `POST /advisor/{s}` · `GET /scope/{s}/review-summary` · `GET /db/stats`

### Capture
- `mitmdump -s src/capture/jxs_mitm_addon.py -p 8082 --mode upstream:http://127.0.0.1:8080`
- Dedup by SHA-256 content hash, scope suffix-match (`host.endswith('.entry')`), file > MAX_CONTENT_BYTES → `oversized_skipped`, error tak pernah crash addon (log ke `logs/jxs_capture_errors.log`).
- katana: dua lapis scope enforcement — flag `-cs` native + filter Python wajib sebelum masuk DB.

### Database (SQLite WAL)
`js_files` (dedup content_hash, status: captured/extracted/oversized_skipped/error), `findings`, `tech_stack`, `advisories`. Migrasi idempotent via `src/db/migrations.py`.

### Scope aktif (`scope_config.json`)
Saat ini satu scope: **encoteki** — whitelist `passport.xellar.co`, `encoteki.com`, `beta.encoteki.com`, `api-new.encoteki.com`.

---

## 5. Hasil Analisa Keseluruhan

**Kekuatan**
1. ✅ Arsitektur pipeline jelas dan terdokumentasi baik (PRD-driven, tiap modul punya docstring PRD reference).
2. ✅ Pattern engine matang: severity berjenjang sadar-FP, ada whitelist context, vendor classifier, dan fix FP berbasis test nyata (kasus infomaniak).
3. ✅ Dedup by content hash (bukan URL) — tahan cache-busting param.
4. ✅ Robustness: timeout di semua subprocess, addon mitmproxy anti-crash, migrasi DB idempotent, WAL mode untuk konkurensi.
5. ✅ Test suite + fixtures tersedia (test_capture, test_extraction, 5 fixture JS).

**Kelemahan / Risiko**
1. ⚠️ **Folder salah tempat**: `./home/ardxcryz/jxs/src/ui/` di dalam repo adalah salinan UI yang nyasar (path absolut ter-commit) — harus dihapus/di-gitignore.
2. ⚠️ **node_modules & .venv ter-commit** (~512 MB) — bengkak, sebaiknya di-gitignore.
3. ⚠️ `__pycache__/*.pyc` ikut masuk tree, termasuk orphan `vendor_classifier.cpython-314.pyc` tanpa source-nya tampak normal tapi tetap noise.
4. ⚠️ Ketergantungan hard pada Burp aktif — single point of failure sesi capture (tercatat di README sendiri: flow reset password bisa hilang).
5. ⚠️ Limitasi metodologis terdokumentasi: belum ada taint/data-flow analysis — navigation sink hanya medium + manual verify; storage detection miss key via variabel.
6. ⚠️ `HIGH_ENTROPY_PATTERN` FP sangat tinggi — hanya layak sebagai hint review.

**Rekomendasi**
- Bersihkan `home/` nyasar, gitignore `.venv/`, `node_modules/`, `__pycache__/`, `.pytest_cache/`.
- Lanjutkan Phase 2: taint analysis minimal (source URLSearchParams/postMessage → sink) untuk menaikkan confidence navigation sink.
- Pertimbangkan memakai `vendor/LinkFinder` & `JSFinder` secara programatik di extraction (saat ini baru adaptasi polanya).
- Jalankan `pytest` rutin untuk menjaga FP < 20% saat menambah pattern baru.

---

## 6. 📦 Vendor — Penjelasan Setiap Folder & Kegunaannya pada jxs

Folder `vendor/` berisi 8 tools pihak ketiga. Berikut penjelasan fungsi internal masing-masing, lalu keputusan peran utamanya di pipeline jxs.

### 6.1 `vendor/LinkFinder/` — ekstraktor endpoint dari JS
**Isi & fungsi:**
- `linkfinder.py` — tool inti. Fungsi-fungsinya:
  - `parser_input()` — normalisasi input (URL, file lokal, atau glob folder `-i`).
  - `send_request()` — fetch JS via HTTPS dengan opsi cookie (`-c`) dan timeout (`-t`).
  - `parser_file()` — inti ekstraksi: jalankan regex endpoint terhadap konten, mode 1 = hanya string dalam kutip, mode 2 = seluruh file; dukung regex custom (`-r`) dan filter tambahan.
  - `getContext()` — ambil potongan baris sekitar match untuk output berkonteks.
  - `cli_output()` / `html_save()` — output CLI atau report HTML interaktif via `template.html`.
  - Flag utama: `-d` domain, `-i` input file/dir, `-o` output, `-r` custom regex, `-b` kirim ke Burp proxy, `-c` cookies, `-t` timeout.
- `test_parser.py` — unit test parser regex.
- `setup.py`, `Dockerfile`, `requirements.txt` — packaging.

**Peran utama di jxs:** ✅ **SUDAH TERINTEGRASI — sumber pola ENDPOINT_PATTERN.** Regex LinkFinder diadaptasi langsung ke `src/extraction/patterns.py` (`ENDPOINT_PATTERN`). Tidak dipanggil sebagai subprocess; konsepnya saja yang dipakai. Potensi lanjutan: panggil sebagai verifikator sekunder saat fitur JS-diffing (feedback-claude.md #1) dibangun.

### 6.2 `vendor/JSFinder/` — pencari URL & subdomain dari JS/HTML
**Isi & fungsi (`JSFinder.py`, single-file):**
- `extract_URL(JS)` — regex ambil URL/path dari konten JS.
- `Extract_html(URL)` — fetch halaman + semua `<script src>` di dalamnya.
- `find_by_url()` / `find_by_url_deep()` — crawl satu level / rekursif untuk mengumpulkan JS lalu ekstrak URL darinya.
- `find_subdomain(urls, mainurl)` — filter hasil jadi daftar subdomain milik domain utama.
- `find_by_file()` — proses file JS lokal (batch).
- `process_url()`, `find_last()`, `giveresult()` — normalisasi relative→absolute URL dan output.

**Peran utama di jxs:** ⚠️ **CADANGAN discovery — BELUM terpanggil.** Fungsi deep-crawl-nya tumpang tindih dengan katana (`katana_runner.py`). Nilai tambah uniknya: ekstraksi **subdomain** dari isi JS — bisa jadi sumber perluasan otomatis `host_whitelist` scope. Status: referensi, belum ada wrapper di src/.

### 6.3 `vendor/js-beautify/` — formatter minified JS
**Isi & fungsi:**
- `python/jsbeautifier/` — library Python: `beautify(string, opts)` merapikan JS minified (indentasi, newline) tanpa mengubah semantik. Juga tersedia versi JS (`js/index.js`) dan CSS/HTML beautifier.
- Opsi penting: `indent_size`, `max_preserve_newlines`, `brace_style`.

**Peran utama di jxs:** ✅ **TERINTEGRASI — tahap pra-regex pipeline.** `requirements.txt` memasang paket `jsbeautifier`. `extractor.py` step 3: file < 1.5 MB dibuat cantik dulu supaya snippet finding mudah dibaca; ≥ 1.5 MB dilewati (regex jalan di minified demi performa).

### 6.4 `vendor/mantra/` — secret/API key scanner (Go)
**Isi & fungsi (`main.go`):**
- Fetch file/URL lalu cocokkan dengan ~100+ pola key bawaan (Google, AWS, Stripe, Slack, dll).
- Flag: `-f <file>`, `-o json`, `-s` silent, `-t` thread (default 50), `-ua` user-agent, `-d` detailed, `-c` cookies, `-ep` extra custom regex pattern.
- Output JSON: array `{match, type, line}`.

**Peran utama di jxs:** ✅ **TERINTEGRASI via subprocess.** Dibungkus `src/extraction/mantra_runner.py`: dipanggil `mantra -f <file> -o json` per JS file dengan timeout wajib 30s (PRD 8h), error aman → return `[]`. Ini mesin utama deteksi sensitive data exposure di jxs — tapi karena masih nama-pola-based, perlu dikawinkan validasi format secret (lihat analisa §5) biar "tepat sasaran".

### 6.5 `vendor/wappalyzer/` — referensi fingerprint tech stack
**Isi & fungsi:**
- `src/wappalyzer.js` — engine deteksi teknologi: kelas `Wappalyzer` dengan sistem `technologies` yang punya `requires`, `implies` (chain inference, misal WordPress → PHP), confidence scoring, dan pattern matching atas header/HTML/JS/cookie/DNS.
- `src/categories.json` + `src/groups.json` — taksonomi kategori teknologi.
- `bin/*.js` — build/validasi definisi teknologi.

**Peran utama di jxs:** ✅ **TERINTEGRASI SEBAGAI ATURAN — bukan dependensi.** `src/techstack/detector.py` mengadaptasi pola fingerprint Wappalyzer jadi rule Python murni (`TechRule` dataclass, dua fase: URL-based lalu content-based). Repo vendor ini hanya rujukan definisi; tidak di-import sama sekali.

### 6.6 `vendor/Scrapling/` — framework scraping/fetching adaptif (Python) 🆕
**Isi & fungsi (baru ditambahkan):**
- `scrapling/fetchers/` — tiga fetcher: `requests.py` (HTTP cepat), `chrome.py` (browser automation), `stealth_chrome.py` (anti-bot bypass, TLS fingerprint mimic).
- `scrapling/engines/` — engine di balik fetchers (`static.py` + `_browsers/`), termasuk toolbelt helper.
- `scrapling/parser.py` — kelas `Selector`: parsing HTML/element dengan pencarian cepat + fitur **adaptive** (ingat elemen yang mirip walau struktur halaman berubah, via `storage.py` + `StorageSystemMixin`).
- `scrapling/core/` — utils, custom types, AI-assisted extraction (`ai.py`), interactive shell.
- `scrapling/cli.py` — CLI lengkap: `get/post/put/delete`, `fetch`, `stealthy_fetch`, subcommand `mcp` (server MCP), `shell`, `install`.
- `agent-skill/` — skill bundle siap pakai untuk AI agent.

**Peran utama di jxs:** 🔜 **DITETAPKAN — engine VERIFIKASI AKTIF kandidat.** Ini puzzle piece yang hilang untuk membuat jxs "tepat sasaran" (masalah inti feedback-claude.md):
1. Verifikasi endpoint kandidat bertanda `never_observed_in_traffic` (usulan #3): fetch endpoint via Scrapling → bandingkan respons unauth vs auth → naikkan kandidat BAC/IDOR jadi confirmed candidate.
2. Validasi sourcemap leak: fetch `.map` file → cek benar-benar berisi source asli.
3. Stealth fetch untuk target ber-cloudflare/anti-bot yang gagal di-fetch biasa.
Status sekarang: belum ada wrapper di `src/`; langkah integrasi pertama yang disarankan: modul `src/verification/scrapling_verifier.py`.

### 6.7 `vendor/vulnerability-Checklist/` — knowledge base checklist vuln 🆕
**Isi & fungsi (baru ditambahkan, repo Az0x7):**
27 kategori checklist markdown + payload, tiap folder satu kelas vuln: RXSS, IDOR, ATO (account takeover), 2FA bypass, 403 bypass, reset password, cookie attack, mass assignment, API authentication/authorization, CSRF, SQL injection payload, RCE, file upload, rate limit bypass, JSON attack, exif, admin panel, register vulnerability, Jira, AEM misconfig, Django/Symfony hacking (+ yaml nuclei templates), business logic, dan tips dari Twitter.

**Peran utama di jxs:** 🔜 **DITETAPKAN — sumber advisory & test-plan per finding.** Melengkapi `xss_advisor/advisor.py` yang saat ini hanya cover DOM sink:
1. Mapping finding-type → checklist: `endpoint` finding → IDOR/API Authorization checklist; `secret_param`/mantra hit → API Authentication checklist; `navigation_sink` → RXSS + CSRF; dst. Advisory jadi spesifik, bukan generik.
2. Bahan generator test-plan otomatis per scope (`jxs export` → snippet.md + langkah uji dari checklist relevan).

### 6.8 `vendor/CF-Hero/` — origin discovery di balik Cloudflare (Go) 🆕
**Isi & fungsi (baru ditambahkan, repo musana):**
- `cmd/cf-hero/main.go` — entry point.
- `internal/dns/dns.go` — `GetARecords`, `GetTXTRecords`, `IsInCloudflareIPRange`: cek apakah IP target masuk range Cloudflare, ambil record DNS/TXT (SPF sering bocorkan origin).
- `internal/http/client.go` — HTTP client dengan CycleTLS (JA3 fingerprint spoof), request builder dengan Host-header manipulation untuk probe origin.
- `internal/scanner/scanner.go` — orkestrasi scan multi-sumber (ZoomEye/Shodan API + DNS + direct-IP probe) mencari IP asli di balik CDN.
- `internal/config/config.go` — parse flag & load API keys.

**Peran utama di jxs:** ⚠️ **OUT-OF-PIPELINE — tool recon terpisah.** Tidak nyambung langsung ke capture/extraction jxs (dia bekerja level infrastruktur DNS/IP, bukan isi JS). Kegunaannya pada workflow bug bounty kamu: kalau target scope terlindungi Cloudflare dan butuh akses origin langsung untuk testing (misal bypass WAF saat verifikasi manual kandidat jxs). Saran: jalankan standalone, jangan diintegrasikan ke pipeline jxs.

### 6.9 Ringkasan Peran Semua Vendor

| Vendor | Bahasa | Status di jxs | Peran utama yang dibulatkan |
|---|---|---|---|
| LinkFinder | Python | ✅ Terintegrasi (pola) | Sumber pola ENDPOINT_PATTERN di extraction |
| js-beautify | Py/JS | ✅ Terintegrasi (lib) | Beautify pra-regex (< 1.5 MB) di extractor |
| mantra | Go | ✅ Terintegrasi (subprocess) | Mesin deteksi secret/API key |
| wappalyzer | JS | ✅ Terintegrasi (aturan adaptasi) | Referensi rule techstack detector |
| JSFinder | Python | ⚠️ Cadangan | Deep-crawl alternatif + ekspansi subdomain scope |
| Scrapling 🆕 | Python | 🔜 Ditambahkan | Engine verifikasi aktif kandidat (fetch/stealth/probe) |
| vulnerability-Checklist 🆕 | MD | 🔜 Ditambahkan | Knowledge base advisory + test-plan per finding-type |
| CF-Hero 🆕 | Go | ⚠️ Out-of-pipeline | Recon origin-behind-CF, standalone di luar jxs |

**Alur besar yang terbentuk** (setelah Scrapling & Checklist terintegrasi):
```
Capture (mitmproxy/katana) → Extract (patterns + mantra + js-beautify)
        → Prioritize (diffing, proximity hint, never_observed flag)
        → VERIFY (Scrapling: fetch kandidat aktif)      ← baru
        → ADVISE (xss_advisor + vulnerability-Checklist) ← diperluas
        → Report (CLI export / UI graph)
CF-Hero: standalone, dipakai saat butuh origin bypass WAF.
```

---
*Dibuat otomatis oleh Hermes Agent — pendataan lengkap seluruh isi folder jxs.*
