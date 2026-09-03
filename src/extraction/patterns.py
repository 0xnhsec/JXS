"""
src/extraction/patterns.py
All validated regex patterns for jxs extraction engine.

Source: PRD section 8d — patterns validated against test-set from nasa.gov/globe.gov.

Pattern philosophy:
  - Prefer specificity over recall to keep false-positive rate < 20% (PRD 8f)
  - Whitelist context patterns downgrade severity to Info (not a skip)
  - Each pattern is documented with its severity and known FP risks

Status (per PRD 8k):
  - SECRET_PARAM_PATTERN : ✅ empirically validated (Google Maps key case)
  - ENDPOINT_PATTERN     : ✅ LinkFinder-adapted, well-tested class of pattern
  - SOURCEMAP_PATTERN    : ✅ deterministic (no ambiguity)
  - DOM_SINK_PATTERN     : ⚠️  validated against fixtures in tests/fixtures/
                               Run tests/test_extraction.py to confirm FP < 20%
  - HIGH_ENTROPY_PATTERN : ⚠️  high FP risk — flagged as Info severity only
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
# Endpoint / API Path Discovery
# Adapted from LinkFinder — matches quoted path strings with api/v1/graphql prefix.
# Severity: Medium (custom logic) or Low (vendor plugin paths)
# Known FP: WordPress plugin paths like /wp-content/plugins/... → vendor classifier
#           should downgrade these automatically.
# ─────────────────────────────────────────────────────────────────────────────
ENDPOINT_PATTERN = re.compile(
    r"""[\"'`](/(?:api|v\d+|graphql|rest|gql|rpc|internal|admin|auth|oauth|login|logout|user|account|payment|checkout|order|webhook|callback|redirect|token|refresh|revoke)/[a-zA-Z0-9_\-/{}.?=&%+#]*)[\"'`]""",
    re.IGNORECASE,
)

# Also catch relative paths like fetch('/some/path') or axios.get('/endpoint')
FETCH_PATTERN = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete|request)|XMLHttpRequest|\.open)\s*\(\s*[\"'`](/[a-zA-Z0-9_\-/{}.?=&%+#]+)[\"'`]""",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Sourcemap Leak
# High severity — exposes original source code to anyone who knows to look.
# Very low FP risk: syntax is deterministic.
# ─────────────────────────────────────────────────────────────────────────────
SOURCEMAP_PATTERN = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s\r\n]+)"
)

# ─────────────────────────────────────────────────────────────────────────────
# DOM Sinks
# High severity — direct XSS vectors if user-controlled data reaches these.
# Validated against tests/fixtures/ (PRD 8k).
#
# Split into two patterns to correctly handle both:
#   - Assignment sinks: innerHTML =, outerHTML =, location.href =
#   - Call sinks: eval(, window.open(, insertAdjacentHTML(, document.write(
#
# Intentional exclusions to reduce FP:
#   - textContent, innerText           — text-only, NOT sinks
#   - createTextNode                   — text-only, NOT a sink
#   - "innerHTMLContent", "outerHTMLElement" — word-boundary guarded by (?<!\w)
# ─────────────────────────────────────────────────────────────────────────────

# Assignment sinks — must be followed by = (assignment to taint-able property)
_DOM_ASSIGN_SINKS = re.compile(
    r"(?<!\w)(innerHTML|outerHTML|dangerouslySetInnerHTML)(?=\s*[=({,])",
    re.IGNORECASE,
)

# Call sinks — direct XSS execution vectors
_DOM_CALL_SINKS = re.compile(
    r"(?<!\w)(document\.write(?:ln)?|eval|insertAdjacentHTML|window\.open)\s*\(",
    re.IGNORECASE,
)

# Location/navigation assignment sinks
_DOM_LOCATION_SINKS = re.compile(
    r"(?<!\w)(location\.href|location\.assign|location\.replace)\s*=",
    re.IGNORECASE,
)


def _dom_sink_finditer(content: str):
    """Yield all DOM sink matches from content using all three sub-patterns."""
    for pat in (_DOM_ASSIGN_SINKS, _DOM_CALL_SINKS, _DOM_LOCATION_SINKS):
        yield from pat.finditer(content)


# Primary DOM_SINK_PATTERN — HIGH severity XSS sinks.
#
# Intentional exclusions vs previous version:
#   - 'Function' removed: standalone 'Function' is a JS built-in referenced
#     constantly in minified code. Only 'new Function(' is dangerous (see
#     NEW_FUNCTION_PATTERN below).
#   - 'setAttribute' removed from HIGH: needs both tainted attribute name AND
#     value to be exploitable — moved to ATTR_SINK_PATTERN at Medium severity.
#   - 'location.href/assign/replace' and 'window.open' removed: these are
#     redirect/navigation sinks that need data-flow context to confirm
#     attacker-controlled source — moved to NAVIGATION_SINK_PATTERN at Medium.
#     Pattern rationale: High only defensible when source is known tainted;
#     regex-only match = Medium + manual verify.
DOM_SINK_PATTERN = re.compile(
    r"(?<!\w)"
    r"(innerHTML|outerHTML|dangerouslySetInnerHTML"
    r"|document\.write(?:ln)?"
    r"|eval"
    r"|insertAdjacentHTML)"
    r"(?=\s*[=(,({])",
    re.IGNORECASE,
)


# new Function() — code execution sink, High severity.
# Separate from DOM_SINK_PATTERN to avoid matching every 'Function' keyword.
NEW_FUNCTION_PATTERN = re.compile(
    r"\bnew\s+Function\s*\(",
    re.IGNORECASE,
)

# setAttribute / setAttributeNS — Medium severity.
# Dangerous only when attribute name OR value is user-controlled (e.g. href, src,
# on* handlers), but far too common in normal framework code to be High.
ATTR_SINK_PATTERN = re.compile(
    r"(?<!\w)setAttribute(?:NS)?\s*\(",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Secret in Query Parameters
# Medium/High severity — API key/token leaked in URL (may end up in logs/referrer).
# Empirically validated: Google Maps key case (nasa.gov, PRD 8g).
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PARAM_PATTERN = re.compile(
    r"[?&](key|token|apikey|api_key|secret|auth|access_token|client_secret|password|passwd|pwd|bearer)"
    r"=([A-Za-z0-9_\-]{16,})",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# High-Entropy String Literal (hardcoded secret in source)
# Info severity only — very high FP risk (hashed IDs, asset hashes, etc.)
# Use as a hint for manual review, not automatic flagging.
# ─────────────────────────────────────────────────────────────────────────────
HIGH_ENTROPY_PATTERN = re.compile(
    r"""[\"'`]([A-Za-z0-9+/=_\-]{32,})[\"'`]"""
)

# ─────────────────────────────────────────────────────────────────────────────
# Auth-Related Function Names
# Info severity — flag for manual review, not exploitable by itself.
# ─────────────────────────────────────────────────────────────────────────────
AUTH_FUNCTION_PATTERN = re.compile(
    r"""\b(validateToken|checkAuth|isAdmin|isAuthorized|refreshSession|"""
    r"""verifyJWT|decodeToken|parseJWT|checkPermission|hasRole|"""
    r"""requireAuth|authenticate|authorize|getUser|currentUser)\s*[({]""",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Whitelist Context — downgrade severity to Info (NOT a skip)
# These are public-by-design keys that are intentionally embedded in frontend.
# Example validated case: Google Maps API key on nasa.gov (PRD 8d/8g).
# ─────────────────────────────────────────────────────────────────────────────
SECRET_WHITELIST_CONTEXT = re.compile(
    r"(maps\.googleapis\.com|recaptcha\.google\.com|googletagmanager\.com"
    r"|google-analytics\.com|gtag|ga\.js|analytics\.js|doubleclick\.net"
    r"|facebook\.net|connect\.facebook|twitter\.com/widgets|cdn\.jsdelivr\.net"
    r"|cdnjs\.cloudflare\.com|unpkg\.com)",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Compiled map for the extraction pipeline
# Maps pattern name → (compiled_regex, default_severity)
# ─────────────────────────────────────────────────────────────────────────────
# Severity rationale for navigation/redirect sinks (location.href, window.open, etc):
# These are High severity IF AND ONLY IF an attacker-controlled source (URLSearchParams,
# postMessage, untrusted input) flows into the sink. Regex-only detection cannot confirm
# this data-flow — it only confirms the sink exists. Therefore:
#   - severity = "medium" to flag for MANUAL VERIFY (not automatic High)
#   - Known limitation: no data-flow / taint analysis (Phase 2 scope)
#   - When reviewing: look for location.search, URLSearchParams, postMessage,
#     query param extraction in the same snippet before escalating to High.
NAVIGATION_SINK_PATTERN = re.compile(
    r"(?<!\w)(location\.href|location\.assign|location\.replace|window\.open)"
    r"(?=\s*[=(,])",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# PRD 8w — Insecure Storage Detection
#
# Severity split berdasarkan confidence:
#   HIGH   — JWT literal value (`eyJ...`) langsung di-setItem. Prefix `eyJ` adalah
#              Base64url dari `{"` yang sangat khas JWT. FP rate rendah (<10%).
#   MEDIUM — Keyword substring match pada NAMA KEY di setItem. Key seperti
#              `authToken`, `access_token`, `AUTH_TOKEN` ikut match karena pattern
#              pakai [^\'"]*...[^\'"]*. FP moderate (30-40%) — value bisa
#              saja non-sensitive (CSRF token, state param).
#   LOW    — getItem dengan keyword sensitif. Evidence penggunaan credential
#              dari storage, perlu trace manual ke mana value dipakai.
#
# Batasan wajib diketahui (PRD 8w — gaya dokumentasi 8o):
#   • String literal key only — MISS kalau key pakai constant/variable:
#       const KEY = 'auth_token'
#       localStorage.setItem(KEY, val)  ← TIDAK tertangkap
#   • Value tidak diverifikasi (MEDIUM/LOW): setItem('token', csrfVar) ikut match
#   • Chainability getItem → header: sengaja di-drop, butuh 2-node matching (PRD 8w)
#   • IndexedDB: tidak di-cover, API transaction-based tidak bisa digrep accurately
# ─────────────────────────────────────────────────────────────────────────────

# HIGH: JWT literal di setItem
# eyJ adalah prefix Base64url dari '{"' — sangat spesifik JWT.
INSECURE_STORAGE_JWT_PATTERN = re.compile(
    r"""(?:localStorage|sessionStorage)\.setItem\s*\([^,]+,\s*['"]eyJ[A-Za-z0-9_-]{10,}\.""",
    re.IGNORECASE,
)

# MEDIUM: keyword match pada nama key di setItem
#
# REVISI BERDASARKAN FP TEST NYATA (infomaniak, 439 files, 2026-07-25):
#   Sebelum fix: 15 matches, FP rate 60% (9/15)
#   Penyebab FP:
#     - 'token' match 'tokenExpired' (substring) → fix: tambah (?![Ee]xpir)
#     - 'session' match '__testSession__' (feature detect) → fix: hapus bare 'session',
#       pakai 'session_id' saja
#   Setelah fix (estimasi): FP rate ~33% (5/15 → IKToken×3, IKRefreshToken×2 adalah TP)
#   Sisa FP yang tidak bisa di-fix tanpa value inspection:
#     - IKTokenExpire tetap match karena ENDS with 'Token' bukan 'TokenExpire'
#     - Untuk ini reviewer wajib cek value aktual di DevTools → Application → Storage
#
# [^'"]*...[^'"]* supaya 'authToken', 'access_token', 'AUTH_TOKEN', 'X-Auth-Token' ikut match
# (?![Ee]xpir) negative lookahead setelah 'token' untuk exclude 'tokenExpired', 'TokenExpire'
INSECURE_STORAGE_SET_PATTERN = re.compile(
    r"""(?:localStorage|sessionStorage)\.setItem\s*\(['"][^'"]*(?:token(?![Ee]xpir)|auth(?!or)|password|passwd|secret|credential|session_id|api[_-]?key)[^'"]*['"]""",
    re.IGNORECASE,
)

# LOW/INFO: getItem dengan keyword sensitif
# Fix sama: (?![Ee]xpir) setelah 'token'
INSECURE_STORAGE_GET_PATTERN = re.compile(
    r"""(?:localStorage|sessionStorage)\.getItem\s*\(['"][^'"]*(?:token(?![Ee]xpir)|auth(?!or)|password|secret|api[_-]?key)[^'"]*['"]""",
    re.IGNORECASE,
)

EXTRACTION_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "endpoint":               (ENDPOINT_PATTERN,             "medium"),
    "endpoint_fetch":         (FETCH_PATTERN,                "medium"),
    "sourcemap":              (SOURCEMAP_PATTERN,            "high"),
    # DOM sinks — HIGH: direct code/HTML injection (innerHTML, eval, document.write etc)
    # navigation_sink removed from DOM_SINK_PATTERN — see NAVIGATION_SINK_PATTERN below
    "dom_sink":               (DOM_SINK_PATTERN,             "high"),
    "new_function":           (NEW_FUNCTION_PATTERN,         "high"),    # new Function() only
    "attr_sink":              (ATTR_SINK_PATTERN,            "medium"),  # setAttribute → medium
    # Navigation sinks — MEDIUM: regex match only, no data-flow analysis.
    # Manual verify required: look for attacker-controlled source before escalating.
    "navigation_sink":        (NAVIGATION_SINK_PATTERN,     "medium"),
    "secret_param":           (SECRET_PARAM_PATTERN,         "high"),
    "high_entropy":           (HIGH_ENTROPY_PATTERN,         "info"),
    "auth_function":          (AUTH_FUNCTION_PATTERN,        "info"),
    # PRD 8w — Insecure Storage Detection
    # Three tiers based on confidence (see comments above).
    "storage_jwt":            (INSECURE_STORAGE_JWT_PATTERN, "high"),    # JWT literal in setItem
    "storage_set":            (INSECURE_STORAGE_SET_PATTERN, "medium"),  # keyword key in setItem
    "storage_get":            (INSECURE_STORAGE_GET_PATTERN, "low"),     # keyword key in getItem
}
