# jxs — JavaScript Analysis & Mapping Tool for Bug Bounty

**Author:** Bangkit Eldhianpranata Pengestu (0xnhsec)  
**Status:** MVP Phase 1

---

## What is jxs?

`jxs` automates the JS discovery and analysis phase of bug bounty recon:

1. **Capture** — mitmproxy addon passively captures JS responses as you browse through Burp
2. **Extract** — regex pipeline finds endpoints, DOM sinks, sourcemap leaks, secrets
3. **Detect** — tech stack fingerprinting (React, Next.js, WordPress, etc.)
4. **Advise** — XSS advisory text per DOM sink finding
5. **Visualize** — React Flow graph showing JS files → findings relationships
6. **CLI mode** — `jxs scan/status/export/review` tanpa buka UI (PRD 8m)

**Penting:** `jxs` TIDAK bisa jalan sendiri tanpa Burp Suite aktif. Burp harus running dan listener proxy-nya aktif SEBELUM mitmproxy addon di-start — `jxs` cuma numpang lewat sebagai passive mirror (lihat Architecture di bawah). Kalau Burp mati di tengah sesi, seluruh chain capture ikut putus.



## Architecture

```
Browser (proxy :8082) → mitmproxy addon → Burp (:8080) → Internet
                              ↓
                         jxs_storage.db (SQLite, WAL)
                              ↓
                    Extraction Engine (regex + mantra)
                              ↓
                    FastAPI (:8888) → React Flow UI (:5173)
```

Urutan start yang benar (wajib, bukan opsional):
1. Burp Suite jalan, listener `127.0.0.1:8080` aktif
2. mitmproxy addon start, tunggu log `HTTP(S) proxy listening at *:8082` muncul lengkap
3. Browser proxy diarahkan ke `127.0.0.1:8082`
4. Baru mulai browsing target

Kalau urutan ini gak diikuti (misal browsing duluan sebelum mitmproxy fully ready, atau Burp keburu mati di tengah flow), sebagian request penting (contoh: flow reset password) bisa gak ke-capture walau addon-nya sendiri gak error.

---

## Quick Start

### 1. Install Python dependencies

```bash
cd /home/ardxcryz/jxs
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure scope

Create `scope_config.json` in project root:

```json
{
  "scopes": [
    {
      "scope_name": "infomaniak",
      "host_whitelist": ["infomaniak.com", "api.infomaniak.com"],
      "auth_cookie": null,
      "host_list_file": null
    }
  ]
}
```

### 3. Start mitmproxy capture (Mode B — passive)

**Pastikan Burp Suite sudah running dan listener 8080 aktif SEBELUM menjalankan command ini.**

```bash
SCOPE=infomaniak mitmdump -s src/capture/jxs_mitm_addon.py \
  -p 8082 --mode upstream:http://127.0.0.1:8080 \
  --set ssl_insecure=true
```

Set your browser proxy to `127.0.0.1:8082` (NOT Burp's port). Traffic still flows through Burp.

> **Kenapa `--set ssl_insecure=true` wajib ada:** Burp Suite generate cert self-signed buat proxy-nya sendiri. Tanpa flag ini, mitmproxy akan **menolak** koneksi ke Burp karena gagal verifikasi cert upstream (`Certificate verify failed: self-signed certificate in certificate chain`) — traffic mati total di tengah, tanpa error yang jelas kelihatan di browser. Ini flag paling sering kelewat dan bikin capture stuck di 0 file.

### 4. Start FastAPI server

```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8888 --reload
```

### 5. Start UI

```bash
cd src/ui
npm run dev
# Open http://localhost:5173
```

### 6. Run extraction pipeline

In the UI toolbar, select your scope then click:
- **Extract** — run regex extraction on captured JS files
- **Tech** — run tech stack detection
- **Advisor** — generate XSS advisories for DOM sinks

Or via CLI (faster, pipeable ke `jq`):
```bash
# Extraction + tampilkan findings JSON
python -m src.cli.jxs_cli scan --scope infomaniak

# Table mode untuk baca cepat
python -m src.cli.jxs_cli scan --scope infomaniak --format table --severity high

# Status ringkas semua scope
python -m src.cli.jxs_cli status
```

---

## Module Reference

| Module | Path | Purpose |
|--------|------|---------|
| Capture | `src/capture/jxs_mitm_addon.py` | mitmproxy passive addon |
| Scope Config | `src/capture/config.py` | Scope management |
| DB Schema | `src/db/schema.py` | SQLite init + connections |
| DB Migrations | `src/db/migrations.py` | Idempotent ALTER TABLE migrations |
| Extraction | `src/extraction/extractor.py` | Main regex pipeline |
| Patterns | `src/extraction/patterns.py` | All regex patterns |
| Vendor | `src/extraction/vendor_classifier.py` | Bundle classification |
| mantra | `src/extraction/mantra_runner.py` | Go-based secret scanner |
| Tech Stack | `src/techstack/detector.py` | Tech fingerprinting |
| XSS Advisor | `src/xss_advisor/advisor.py` | Advisory text generator |
| **CLI** | **`src/cli/jxs_cli.py`** | **CLI entry point (PRD 8m)** |
| API | `src/api/main.py` | FastAPI localhost server |
| UI | `src/ui/` | React Flow visualization |

---

## CLI Mode Reference (PRD 8m)

### `jxs scan --katana-url` — katana fast JS discovery (PRD 8q)

Crawl target URL untuk discover JS files secara otomatis, lalu langsung extract.

```bash
# Crawl + extract + tampilkan findings dalam satu command
python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov

# Depth lebih dalam (lebih banyak JS, lebih lama)
python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov --katana-depth 3

# Output table format
python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov --format table
```

**Scope enforcement otomatis 2 lapis:**
1. katana `-cs` flag — crawl tidak keluar domain `host_whitelist`
2. `filter_katana_output()` — Python filter sebelum data masuk DB (mandatory, tidak bisa dilewati)

Requires `scope_config.json` dengan `host_whitelist` yang sudah dikonfigurasi.

### `jxs scan` — run extraction dan output findings

```bash
# JSON ke stdout (pipeable ke jq)
python -m src.cli.jxs_cli scan --scope nasa

# Table untuk baca cepat
python -m src.cli.jxs_cli scan --scope nasa --format table

# Filter severity + type
python -m src.cli.jxs_cli scan --scope nasa --severity high --type sourcemap

# Filter review status (lihat hanya yang belum dicek)
python -m src.cli.jxs_cli scan --scope nasa --review-status unreviewed

# Scan dari URL list (download JS + extract langsung)
python -m src.cli.jxs_cli scan --url-list js.txt --scope nasa

# Simpan ke file
python -m src.cli.jxs_cli scan --scope nasa --output findings.json

# Pipe ke jq
python -m src.cli.jxs_cli scan --scope nasa | jq '[.[] | select(.severity=="high")]'
```

### `jxs status` — ringkasan DB per scope

```bash
python -m src.cli.jxs_cli status          # semua scope
python -m src.cli.jxs_cli status --scope nasa  # satu scope
```

Output mencakup: jumlah JS file, breakdown severity, **breakdown review status** (unreviewed/checked_fp/confirmed_bug/reported).

### `jxs review` — update review status finding

```bash
# Mark finding sebagai confirmed bug
python -m src.cli.jxs_cli review <finding_id> confirmed_bug --note "innerHTML sink, user-controlled via hash"

# Mark sebagai false positive
python -m src.cli.jxs_cli review <finding_id> checked_fp

# Reset ke unreviewed
python -m src.cli.jxs_cli review <finding_id> unreviewed
```

Review status values: `unreviewed` | `checked_fp` | `checked_benign` | `confirmed_bug` | `reported`

### `jxs export` — generate draft writeup (PRD 8t)

```bash
# Generate snippet.md per confirmed_bug finding
python -m src.cli.jxs_cli export --scope nasa --status confirmed_bug
# Output: targets/nasa/<jsfile>/snippet-<id>.md

# Include source.js raw content
python -m src.cli.jxs_cli export --scope nasa --status confirmed_bug --include-source
```

File output siap tempel ke laporan YWH/H1 — sudah berisi match, target_url, severity, code snippet, dan review note.

### Workflow Hunting Lengkap

```bash
# 1. Lihat scope yang tersedia
python -m src.cli.jxs_cli status

# 2a. Katana discovery (fast — broad initial crawl)
python -m src.cli.jxs_cli scan --scope nasa --katana-url https://www.nasa.gov --katana-depth 3

# 2b. Atau extraction dari DB (jika sudah capture via mitmproxy)
python -m src.cli.jxs_cli scan --scope nasa

# 3. Lihat High findings dalam tabel
python -m src.cli.jxs_cli scan --scope nasa --format table --severity high

# 4. Review manual tiap finding, mark status
python -m src.cli.jxs_cli review 51032 confirmed_bug --note "Sourcemap leak accessible"
python -m src.cli.jxs_cli review 51037 checked_fp --note "innerHTML dari vDOM internal Stencil"

# 5. Export draft writeup semua confirmed_bug
python -m src.cli.jxs_cli export --scope nasa --status confirmed_bug

# 6. Setelah submit ke program, mark reported
python -m src.cli.jxs_cli review 51032 reported
```

---

## Running Tests

```bash
cd /home/ardxcryz/jxs
python -m pytest tests/ -v
```

Key test files:
- `tests/test_extraction.py` — validates all regex patterns + PRD 8k DOM_SINK_PATTERN blocker
- `tests/test_capture.py` — scope config, DB dedup, WAL mode

---

## mitmproxy Port Config (PRD 8b, section 8b)

```
mitmproxy listens: 8082
Burp proxy:        8080
Browser setting:   127.0.0.1:8082  ← point browser here, NOT Burp's port
```

Do NOT use the same port for mitmproxy listen and Burp upstream.

---

## Tool Stack

| Layer | Tool |
|-------|------|
| Passive capture | mitmproxy |
| Secret scan | mantra (optional, subprocess) |
| Deobfuscate | js-beautify |
| Visualization | React Flow + dagre |
| Storage | SQLite (WAL mode) |
| API | FastAPI |

---

## Troubleshooting

### ❌ `502 Bad Gateway` / `[Errno 111] Connect call failed ('127.0.0.1', 8080)`

**Ini bukan bug di `jxs`. Ini artinya Burp Suite mati atau listener 8080-nya nonaktif.**

Semua request yang lewat mitmproxy di-forward ke upstream (Burp di 8080). Kalau Burp gak jalan atau listener-nya ke-disable, mitmproxy gak punya tempat forward traffic, hasilnya `Connection refused` yang muncul sebagai halaman 502 di browser.

**Fix:**
1. Cek Burp Suite masih terbuka dan gak crash
2. Proxy → Options → pastikan listener `127.0.0.1:8080` statusnya "running" (bukan stopped/disabled)
3. Kalau semua checklist di atas oke tapi masih 502, restart Burp lalu restart mitmproxy addon

**Efek samping kalau ini kejadian di tengah testing:** sebagian request penting (misal step-step dalam flow reset password) bisa gak ke-capture walau addon-nya sendiri jalan normal — karena request itu mati di tengah jalan sebelum sempat di-log ke DB. Kalau ini terjadi, ulangi flow dari awal setelah Burp jalan normal lagi, jangan asumsikan data yang udah ke-capture itu lengkap.

---

### ❌ `Failed to parse scope config: Illegal trailing comma`

**Error:**
```
Failed to parse scope config: Illegal trailing comma before end of object
```

**Cause:** `scope_config.json` punya trailing comma — JSON standar tidak mengizinkan ini.

**Fix:** Hapus koma terakhir sebelum `}` atau `]`.

```json
// ❌ SALAH
{
  "scope_name": "infomaniak",
  "host_whitelist": ["infomaniak.com"],   ← koma di sini tidak boleh
}

// ✅ BENAR
{
  "scope_name": "infomaniak",
  "host_whitelist": ["infomaniak.com"]
}
```

Validasi sebelum run:
```bash
python3 -c "import json; json.load(open('scope_config.json')); print('OK')"
```

---

### ❌ `Error logged during startup, exiting...`

mitmproxy exit langsung setelah startup. Biasanya disebabkan salah satu:

1. `scope_config.json` tidak valid JSON → lihat error di atas
2. Python import error → pastikan venv aktif: `source .venv/bin/activate`
3. DB path tidak bisa dibuat → pastikan folder `data/` ada: `mkdir -p data`

---

### ❌ `Server TLS handshake failed. Certificate verify failed: self-signed certificate in certificate chain`

**Cause:** mitmproxy menolak koneksi ke Burp karena cert self-signed Burp gak dikenal sebagai trusted CA oleh mitmproxy.

**Fix:** Tambahkan flag `--set ssl_insecure=true` ke command mitmdump (lihat Quick Start step 3 di atas). Ini aman karena upstream-nya adalah Burp lokal milik sendiri, bukan server eksternal yang tidak dikenal.

---

### ❌ `JXSCapture addon started` tapi tidak ada `[+] CAPTURED`

Mitmproxy jalan tapi tidak capture apapun. Cek urutan berikut:

**1. Burp Suite belum jalan / listener 8080 mati**

Lihat troubleshooting "502 Bad Gateway" di atas — cek ini duluan sebelum yang lain, karena ini paling sering jadi akar masalah.

**2. FoxyProxy masih pointing ke Burp (8080), bukan mitmproxy (8082)**

Di FoxyProxy, pastikan proxy aktif adalah entry yang pointing ke `127.0.0.1:8082`.
Burp tetap jalan di 8080 — tidak perlu diubah. mitmproxy forward otomatis ke Burp.

Traffic flow yang benar:
```
Browser → FoxyProxy:8082 → mitmproxy (capture JS) → Burp:8080 → Internet
```

**3. mitmproxy CA Certificate belum diinstall di browser YANG DIPAKAI BROWSING TARGET**

Tanpa ini, semua HTTPS connection ditolak browser (SSL error) → tidak ada traffic masuk.

**Penting:** cert ini per-browser, bukan sistem-wide (khususnya Firefox yang punya CA store sendiri terpisah dari OS). Kalau lu punya lebih dari satu browser terinstall (Firefox, Brave, Chrome), **pastikan cert diinstall di browser yang SAMA PERSIS dengan yang dipakai browsing target** — install di Firefox tapi browsing pakai Brave tetap akan gagal SSL handshake tanpa error yang jelas.

Install cert (Firefox):
- Pastikan mitmproxy running dan FoxyProxy aktif ke 8082
- Buka di Firefox: `http://mitm.it` → klik Firefox → install cert
- Centang **"Trust this CA to identify websites"** → OK

Atau install manual:
```
Firefox → Settings → Privacy & Security → Certificates
→ View Certificates → Authorities → Import
→ File: /home/<user>/.mitmproxy/mitmproxy-ca-cert.pem
→ Centang "Trust this CA to identify websites" → OK
```

Install cert (Chromium/Brave/Chrome — pakai OS trust store, bukan NSS Firefox):
```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "mitmproxy" -i ~/.mitmproxy/mitmproxy-ca-cert.pem
```
Kalau `certutil` belum ada: `sudo pacman -S nss` (Arch/CachyOS). Restart browser setelah import.

**4. SCOPE env var pakai full URL bukan scope name**

```bash
# ❌ SALAH
SCOPE=https://target.com/ mitmdump ...

# ✅ BENAR — pakai scope_name dari scope_config.json
SCOPE=infomaniak mitmdump ...
```

**5. `host_whitelist` di scope_config.json pakai full URL**

```json
// ❌ SALAH
"host_whitelist": ["https://target.com/"]

// ✅ BENAR — hostname only, tanpa scheme dan path
"host_whitelist": ["target.com", "www.target.com"]
```

---

### ❌ `/scope/{scope}/graph` returns 404

Normal — berarti belum ada JS file yang ter-capture untuk scope tersebut.
Capture JS dulu dengan browse target, lalu jalankan extraction pipeline.

---

### ❌ Burp error `Failed to start proxy service on *:8082`

Ini **bukan masalah** — artinya mitmproxy sudah running di port 8082 duluan.
Burp tidak perlu listen di 8082. Biarkan saja.

---

### ✅ Cara verifikasi traffic sudah masuk mitmproxy

Test koneksi lewat mitmproxy (ke server eksternal, bukan upstream Burp):
```bash
curl -x http://127.0.0.1:8082 http://example.com -v
```

Kalau berhasil (200 OK), mitmproxy berfungsi. Kalau tidak ada response, cek apakah mitmproxy running.

**Catatan:** kalau curl manual ke HTTPS lewat proxy ini nunjukin `unable to get local issuer certificate`, itu **expected dan bukan bug** — curl polos gak tau soal cert mitmproxy custom. Test ini gak merepresentasikan kondisi browser asli (yang udah punya cert ter-trust). Kalau mau test manual pakai curl dengan cert yang benar:
```bash
curl -x http://127.0.0.1:8082 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com -v
```

Cek DB langsung:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('data/jxs_storage.db')
print('JS files:', conn.execute('SELECT COUNT(*) FROM js_files').fetchone()[0])
conn.close()
"
```

---

## Phase 2 Backlog

- [x] CLI mode — `jxs scan/status/export/review` (PRD 8m, **done**)
- [x] Review status tracking per finding — workflow unreviewed → confirmed_bug → reported (PRD 8p-1, **done**)
- [x] PoC export — `jxs export --status confirmed_bug` → snippet.md (PRD 8t, **done**)
- [x] katana integration — `jxs scan --katana-url` + scope enforcement 2-lapis (PRD 8q, **done**)
- [ ] Mode A: Playwright on-demand crawl
- [ ] Multi-scope switching in UI
- [ ] Burp Extender API (replace mitmproxy if needed)
- [ ] "Endpoint not in Burp sitemap" rule (requires Burp Professional REST API)