"""
filter_prober.py — Atomic filter detection for XSS context.

Logic giữ nguyên hoàn toàn so với bản gốc (2-phase brute-force):
  Phase 1: Probe các tags → tìm tag nào không bị block
  Phase 2: Probe events trên từng allowed tag → tìm combo (tag, event) hoạt động
  Result:  FilterMap.allowed_combos = [(tag, event), ...]

Thay đổi duy nhất so với bản gốc:
  - ALL_TAGS  : trim xuống còn tags cần thiết để bypass 5 lab PortSwigger
  - ALL_EVENTS: trim xuống còn events cần thiết để bypass 5 lab PortSwigger

Mapping 5 test case → tags/events cần thiết:
  Test 1 (html, body+onresize)     → tags: body | events: onresize, onpageshow
  Test 2 (html, custom xss+onfocus)→ tags: xss, x, custom | events: onfocus, onmouseover
  Test 3 (attribute, onmouseover)  → probe events trên img (attr context logic)
  Test 4 (script, tag breakout)    → probe script tag + angles
  Test 5 (script, backslash)       → probe backslash + quote chars
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

log = logging.getLogger("xss_scanner.filter_prober")

REQUEST_TIMEOUT = 8
MAX_TAG_WORKERS = 10
MAX_EVT_WORKERS = 10

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; XSSReflectionScanner/1.0)",
    "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
})


# ---------------------------------------------------------------------------
# Behavior enum — giữ nguyên
# ---------------------------------------------------------------------------

class Behavior(str, Enum):
    ALLOWED  = "allowed"
    ENCODED  = "encoded"
    ESCAPED  = "escaped"
    DOUBLED  = "doubled"
    STRIPPED = "stripped"
    PARTIAL  = "partial"
    UNKNOWN  = "unknown"


# ---------------------------------------------------------------------------
# Tags & Events — TRIMMED cho 5 lab PortSwigger
# ---------------------------------------------------------------------------

# Giải thích lựa chọn:
#   body    → Test 1: body onresize / onpageshow
#   xss, x  → Test 2: custom tag + onfocus (WAF thường quên block custom tags)
#   img     → Test 3 (attribute context) + general fallback
#   svg     → general fallback HTML context
#   input   → fallback với onfocus/autofocus
#   details → ontoggle fallback
ALL_TAGS: list[str] = [
    "body",     # Test 1: body onresize / onpageshow
    "xss",      # Test 2: custom tag (WAF thường không block custom tag)
    "img",      # fallback: img onerror
    "svg",      # fallback: svg onload
    "input",    # fallback: input onfocus autofocus
]

# Giải thích lựa chọn:
#   onresize    → Test 1: body onresize (trigger bằng iframe resize)
#   onpageshow  → Test 1 variant: fires on page load
#   onfocus     → Test 2: xss tag + tabindex + fragment #x
#   onmouseover → Test 3: attribute context breakout; cũng dùng ở HTML
#   onerror     → img onerror — classic fallback
#   onload      → svg/body onload
#   ontoggle    → details open ontoggle
#   onclick     → interaction-required fallback
ALL_EVENTS: list[str] = [
    # Auto-trigger (không cần user interaction) — ưu tiên cao
    "onresize",     # Test 1
    "onpageshow",   # Test 1 variant
    "onfocus",      # Test 2
    "onerror",      # img fallback
    "onload",       # svg/body
    "ontoggle",     # details
    # Require interaction
    "onmouseover",  # Test 3 + HTML fallback
    "onclick",      # interaction fallback
]

# Events auto-trigger (không cần user click/hover)
AUTO_TRIGGER_EVENTS: set[str] = {
    "onresize", "onpageshow", "onfocus", "onerror",
    "onload", "ontoggle",
}


# ---------------------------------------------------------------------------
# FilterMap — giữ nguyên hoàn toàn
# ---------------------------------------------------------------------------

@dataclass
class FilterMap:
    # Character filters
    angle_open:   Behavior = Behavior.UNKNOWN
    angle_close:  Behavior = Behavior.UNKNOWN
    double_quote: Behavior = Behavior.UNKNOWN
    single_quote: Behavior = Behavior.UNKNOWN
    backtick:     Behavior = Behavior.UNKNOWN
    backslash:    Behavior = Behavior.UNKNOWN

    # Tag-level filters
    script_tag:     Behavior = Behavior.UNKNOWN
    event_handlers: Behavior = Behavior.UNKNOWN

    # Brute-force results
    allowed_combos: list[tuple[str, str]] = field(default_factory=list)
    allowed_tags:   list[str]             = field(default_factory=list)

    # Per-tag-category shortcuts (derived)
    custom_tag_events: Behavior = Behavior.UNKNOWN
    body_events:       Behavior = Behavior.UNKNOWN
    input_events:      Behavior = Behavior.UNKNOWN

    raw: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived properties — giữ nguyên
    # ------------------------------------------------------------------

    @property
    def tags_usable(self) -> bool:
        bad = (Behavior.ENCODED, Behavior.STRIPPED)
        return self.angle_open not in bad and self.angle_close not in bad

    @property
    def script_usable(self) -> bool:
        return self.tags_usable and self.script_tag == Behavior.ALLOWED

    @property
    def events_usable(self) -> bool:
        return self.tags_usable and self.event_handlers == Behavior.ALLOWED

    @property
    def custom_tag_ok(self) -> bool:
        return self.custom_tag_events == Behavior.ALLOWED

    @property
    def body_events_ok(self) -> bool:
        return self.body_events == Behavior.ALLOWED

    @property
    def input_events_ok(self) -> bool:
        return self.input_events == Behavior.ALLOWED

    @property
    def has_any_combo(self) -> bool:
        return len(self.allowed_combos) > 0

    @property
    def double_quote_free(self) -> bool:
        return self.double_quote == Behavior.ALLOWED

    @property
    def single_quote_free(self) -> bool:
        return self.single_quote == Behavior.ALLOWED

    @property
    def backtick_free(self) -> bool:
        return self.backtick == Behavior.ALLOWED

    @property
    def backslash_doubles(self) -> bool:
        return self.backslash == Behavior.DOUBLED


# ---------------------------------------------------------------------------
# Known encoding forms — giữ nguyên
# ---------------------------------------------------------------------------

_ENTITY_FORMS: dict[str, list[str]] = {
    "<":  ["&lt;", "&#60;", "&#x3c;", "&#X3C;", "%3c", "%3C"],
    ">":  ["&gt;", "&#62;", "&#x3e;", "&#X3E;", "%3e", "%3E"],
    '"':  ["&quot;", "&#34;", "&#x22;", "&#X22;", "%22"],
    "'":  ["&#39;", "&apos;", "&#x27;", "&#X27;", "%27"],
    "`":  ["&#96;", "&#x60;", "&#X60;", "%60"],
}

_BACKSLASH_ESCAPE = {"'": ["\\'"], '"': ['\\"']}


# ---------------------------------------------------------------------------
# HTTP helpers — giữ nguyên
# ---------------------------------------------------------------------------

def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _fetch(base_url: str, param: str, value: str) -> tuple[str | None, int]:
    url = _build_url(base_url, param, value)
    try:
        r = _SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        ct = r.headers.get("Content-Type", "")
        if "html" not in ct:
            return None, r.status_code
        return r.text, r.status_code
    except requests.RequestException:
        return None, 0


def _fetch_text(base_url: str, param: str, value: str) -> str | None:
    html, _ = _fetch(base_url, param, value)
    return html


# ---------------------------------------------------------------------------
# Character analyser — giữ nguyên
# ---------------------------------------------------------------------------

def _analyse_char(html: str, sentinel: str, char: str) -> Behavior:
    if html is None:
        return Behavior.UNKNOWN
    if f"{sentinel}{char}{sentinel}" in html:
        return Behavior.ALLOWED
    m = re.search(re.escape(sentinel) + r"(.*?)" + re.escape(sentinel),
                  html, re.DOTALL)
    if m:
        between = m.group(1)
        if not between:
            return Behavior.STRIPPED
        # ESCAPED phải check TRƯỚC ENCODED:
        # Trong HTML, &#39; là entity cho ' — nhưng \' là JS escape.
        # Nếu check ENCODED trước, &#39; sẽ match trước \' → false ENCODED.
        # Thứ tự đúng: ESCAPED → ENCODED → PARTIAL/ALLOWED
        for form in _BACKSLASH_ESCAPE.get(char, []):
            if form in between:
                return Behavior.ESCAPED
        for form in _ENTITY_FORMS.get(char, []):
            if form.lower() in between.lower():
                return Behavior.ENCODED
        if char not in between:
            return Behavior.PARTIAL
        return Behavior.ALLOWED
    if sentinel[:4] in html:
        return Behavior.PARTIAL
    return Behavior.STRIPPED


def _probe_char(base_url: str, param: str, marker: str, char: str) -> Behavior:
    sentinel = f"{marker}F"
    html = _fetch_text(base_url, param, f"{sentinel}{char}{sentinel}")
    return _analyse_char(html, sentinel, char)


def _probe_char_in_js_string(
    base_url:   str,
    param:      str,
    marker:     str,
    char:       str,
    quote_char: str,
) -> Behavior:
    """
    Probe behavior của một char khi nằm TRONG JS string literal.

    Tại sao _probe_char thông thường không đủ:
    ============================================
    Server PortSwigger lab này có 2 lớp xử lý ĐỘCLẬP:

      Layer 1 — HTML context encode (áp dụng cho toàn bộ output HTML):
        '  → &#39;    (HTML entity)
        <  → &lt;
        "  → &quot;

      Layer 2 — JS string escape (chỉ áp dụng bên trong JS string literal):
        '  → \'       (backslash-escape)

    _probe_char gửi  SENTINELF'SENTINELF  dưới dạng raw param.
    Server thấy reflection nằm trong HTML body (text node / attribute),
    không phải JS string → chỉ áp dụng Layer 1 → trả về &#39; → ENCODED.

    _analyse_char check ENCODED trước ESCAPED → luôn trả về ENCODED,
    không bao giờ tới ESCAPED → sq_escaped = False → bs_pay không sinh.

    Approach đúng — đọc raw JS source:
    =====================================
    Gửi probe bình thường (sentinel + char + sentinel).
    Nhưng thay vì dùng _analyse_char trên toàn HTML, ta:
      1. Extract <script>...</script> block từ HTML response.
      2. Tìm sentinel pair TRONG JS source (không qua HTML parser).
      3. Đọc trực tiếp chars giữa 2 sentinel trong raw JS source.
         Trong JS source, server KHÔNG HTML-encode nữa (đã ở trong <script>),
         nhưng CÓ JS-escape → \\' xuất hiện thay vì &#39;.
      4. Phân tích riêng: nếu thấy \\' → ESCAPED; nếu thấy raw ' → ALLOWED.

    Ví dụ với lab này (quote_char = "'"):
      Probe value:  MARKERJS'MARKERJS
      HTML response chứa:  var searchTerms = 'MARKERJS\\'MARKERJS';
      → Trong <script> block ta thấy:  MARKERJS\\'MARKERJS
      → giữa 2 sentinel là: \\'
      → đó là backslash + quote → ESCAPED  ✓
    """
    sentinel = f"{marker}JS"
    probe    = f"{sentinel}{char}{sentinel}"
    html     = _fetch_text(base_url, param, probe)
    if html is None:
        return Behavior.UNKNOWN

    # Extract tất cả <script> blocks
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        js_src = m.group(1)
        if sentinel not in js_src:
            continue

        # Tìm vị trí của 2 sentinel trong raw JS source
        idx1 = js_src.find(sentinel)
        idx2 = js_src.find(sentinel, idx1 + len(sentinel))
        if idx1 == -1 or idx2 == -1:
            continue

        between = js_src[idx1 + len(sentinel): idx2]
        log.debug("  js_string probe char=%r between=%r", char, between)

        if not between:
            return Behavior.STRIPPED

        # Trong raw JS source (không qua HTML decode):
        #   ESCAPED:  server thêm backslash trước char  →  \' hoặc \"
        #   DOUBLED:  server double backslash            →  \\
        #   ALLOWED:  char xuất hiện nguyên vẹn
        #   STRIPPED: char biến mất hoàn toàn

        escaped_form = f"\\{char}"   # 2 chars: backslash + char
        if escaped_form in between and char in between:
            # \' present → ESCAPED (backslash là escape prefix, không phải literal)
            return Behavior.ESCAPED
        if char in between:
            return Behavior.ALLOWED
        # char không còn trong between — có thể bị encode theo cách khác
        # Fallback: thử HTML entity forms (ít gặp trong <script> block)
        for form in _ENTITY_FORMS.get(char, []):
            if form.lower() in between.lower():
                return Behavior.ENCODED
        if between:
            return Behavior.PARTIAL
        return Behavior.STRIPPED

    # sentinel không tìm thấy trong bất kỳ <script> block nào
    # Fallback về _analyse_char trên toàn HTML (ít chính xác hơn)
    log.debug("  js_string probe: sentinel not found in script blocks, fallback to html")
    return _analyse_char(html, sentinel, char)


def _probe_backslash(base_url: str, param: str, marker: str) -> Behavior:
    sentinel = f"{marker}BS"
    html = _fetch_text(base_url, param, f"{sentinel}\\{sentinel}")
    if html is None:
        return Behavior.UNKNOWN
    if f"{sentinel}\\\\{sentinel}" in html:
        return Behavior.DOUBLED
    if f"{sentinel}\\{sentinel}" in html:
        return Behavior.ALLOWED
    return Behavior.STRIPPED


def _probe_script(base_url: str, param: str, marker: str) -> Behavior:
    probe = f"<script>{marker}</script>"
    html = _fetch_text(base_url, param, probe)
    if html is None:
        return Behavior.UNKNOWN
    if probe in html:
        return Behavior.ALLOWED
    if marker in html:
        return Behavior.PARTIAL
    return Behavior.STRIPPED


# ---------------------------------------------------------------------------
# Phase 1: Tag brute-force — giữ nguyên logic, dùng ALL_TAGS đã trim
# ---------------------------------------------------------------------------

def _probe_tag(base_url: str, param: str, marker: str, tag: str) -> bool:
    attr_token = f"{marker}attr"
    probe      = f"<{tag} {attr_token}=1>"
    html       = _fetch_text(base_url, param, probe)
    if html is None:
        return False
    return attr_token in html


def _probe_all_tags(
    base_url: str,
    param:    str,
    marker:   str,
    tags:     list[str],
) -> list[str]:
    allowed: list[str] = []

    def check(tag: str) -> tuple[str, bool]:
        return tag, _probe_tag(base_url, param, marker, tag)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_TAG_WORKERS) as ex:
        futures = {ex.submit(check, t): t for t in tags}
        for fut in concurrent.futures.as_completed(futures):
            try:
                tag, ok = fut.result()
                if ok:
                    allowed.append(tag)
                    log.debug("  Tag allowed: <%s>", tag)
            except Exception as e:
                log.debug("  Tag probe error: %s", e)

    return allowed


# ---------------------------------------------------------------------------
# Phase 2: Event brute-force — giữ nguyên logic, dùng ALL_EVENTS đã trim
# ---------------------------------------------------------------------------

def _probe_event_on_tag(
    base_url: str,
    param:    str,
    marker:   str,
    tag:      str,
    event:    str,
) -> bool:
    token = f"{marker}_{event}"
    probe = f"<{tag} {event}={token}>"
    html  = _fetch_text(base_url, param, probe)
    if html is None:
        return False
    return token in html


def _probe_all_events_on_tag(
    base_url: str,
    param:    str,
    marker:   str,
    tag:      str,
    events:   list[str],
) -> list[str]:
    allowed: list[str] = []

    def check(ev: str) -> tuple[str, bool]:
        return ev, _probe_event_on_tag(base_url, param, marker, tag, ev)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_EVT_WORKERS) as ex:
        futures = {ex.submit(check, ev): ev for ev in events}
        for fut in concurrent.futures.as_completed(futures):
            try:
                ev, ok = fut.result()
                if ok:
                    allowed.append(ev)
                    log.debug("  Event allowed on <%s>: %s", tag, ev)
            except Exception as e:
                log.debug("  Event probe error: %s", e)

    return allowed


# ---------------------------------------------------------------------------
# Public API — giữ nguyên hoàn toàn
# ---------------------------------------------------------------------------

def probe_filters(
    base_url:      str,
    param:         str,
    marker:        str,
    context:       str,
    js_quote_char: str = "",
) -> FilterMap:
    """
    Chạy filter detection và trả về FilterMap.

    HTML context: 2-phase brute-force
      Phase 1: Thử ALL_TAGS → tìm tags được phép
      Phase 2: Thử ALL_EVENTS trên từng allowed tag → tìm combos

    JS context: Probe quote chars + backslash.
    Attribute context: Probe quote chars + event handlers.

    Số lượng request ước tính với list đã trim:
      HTML:      8 tags × 1 + 8 events × n_allowed_tags
                 (thay vì 225 request bản gốc → ~30-50 request)
      Attribute: 5 char probes + ~6 event probes = ~11 request
      Script:    4 char probes = ~4 request
    """
    if context == "script":
        context = "js"

    fm  = FilterMap()
    raw: dict = {}

    def pc(char: str, label: str) -> Behavior:
        b = _probe_char(base_url, param, marker, char)
        raw[label] = b.value
        log.debug("  char probe %-16s → %s", label, b.value)
        return b

    # ── HTML context ──────────────────────────────────────────────────────
    if context == "html":
        fm.angle_open   = pc("<", "angle_open")
        fm.angle_close  = pc(">", "angle_close")
        fm.double_quote = pc('"', "double_quote")

        if not fm.tags_usable:
            fm.script_tag     = Behavior.STRIPPED
            fm.event_handlers = Behavior.STRIPPED
        else:
            fm.script_tag = _probe_script(base_url, param, marker)
            raw["script_tag"] = fm.script_tag.value

            # ── Phase 1: Brute-force tags ─────────────────────────────────
            log.info("  [Phase 1] Probing %d tags: %s", len(ALL_TAGS), ALL_TAGS)
            fm.allowed_tags = _probe_all_tags(base_url, param, marker, ALL_TAGS)
            raw["allowed_tags"] = fm.allowed_tags
            log.info("  [Phase 1] Allowed: %s", fm.allowed_tags)

            if not fm.allowed_tags:
                fm.event_handlers = Behavior.STRIPPED
            else:
                # ── Phase 2: Brute-force events ───────────────────────────
                log.info(
                    "  [Phase 2] Probing %d events × %d tags...",
                    len(ALL_EVENTS), len(fm.allowed_tags)
                )

                combos: list[tuple[str, str]] = []

                def probe_tag_events(tag: str) -> list[tuple[str, str]]:
                    evs = _probe_all_events_on_tag(
                        base_url, param, marker, tag, ALL_EVENTS
                    )
                    return [(tag, ev) for ev in evs]

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(len(fm.allowed_tags), 4)
                ) as ex:
                    results = list(ex.map(probe_tag_events, fm.allowed_tags))

                for tag_combos in results:
                    combos.extend(tag_combos)

                fm.allowed_combos = combos
                raw["allowed_combos"] = [(t, e) for t, e in combos]
                log.info("  [Phase 2] %d combos found: %s", len(combos), combos)

                # Derive legacy fields
                tags_with_events = {t for t, _ in combos}

                if any(t in ("img", "svg", "video", "audio", "iframe")
                       for t in tags_with_events):
                    fm.event_handlers = Behavior.ALLOWED
                else:
                    fm.event_handlers = Behavior.STRIPPED

                if any(t in ("xss", "x", "custom") for t in tags_with_events):
                    fm.custom_tag_events = Behavior.ALLOWED

                if "body" in tags_with_events:
                    fm.body_events = Behavior.ALLOWED

                if "input" in tags_with_events:
                    fm.input_events = Behavior.ALLOWED

    # ── Attribute context ──────────────────────────────────────────────────
    elif context == "attribute":
        fm.angle_open   = pc("<",  "angle_open")
        fm.angle_close  = pc(">",  "angle_close")
        fm.double_quote = pc('"',  "double_quote")
        fm.single_quote = pc("'",  "single_quote")
        fm.backtick     = pc("`",  "backtick")

        if fm.tags_usable or fm.double_quote_free or fm.single_quote_free:
            # Probe events chỉ trên img (đủ cho Test 3)
            allowed_evs = _probe_all_events_on_tag(
                base_url, param, marker, "img",
                ["onerror", "onload", "onmouseover", "onfocus", "ontoggle"]
            )
            fm.event_handlers = (
                Behavior.ALLOWED if allowed_evs else Behavior.STRIPPED
            )
        else:
            fm.event_handlers = Behavior.UNKNOWN

        raw["event_handlers"] = fm.event_handlers.value

    # ── JS context ─────────────────────────────────────────────────────────
    elif context == "js":
        # Quan trọng: phải dùng _probe_char_in_js_string cho quote char đang
        # wrap JS string, KHÔNG dùng _probe_char thông thường.
        #
        # Lý do: server thường có 2 lớp xử lý độc lập:
        #   1. HTML encode: < > " → entity (áp dụng cho toàn bộ output)
        #   2. JS string escape: ' → \' (chỉ áp dụng cho chars trong JS string)
        #
        # _probe_char gửi SENTINEL'SENTINEL dưới dạng raw param, server thấy
        # ' không nằm trong JS string → HTML-encode → trả về ENCODED.
        # Nhưng thực tế khi user inject vào JS string, server sẽ ESCAPE.
        # → sq_escaped = False → bs_pay không sinh → miss lab này.
        #
        # Fix: dùng _probe_char_in_js_string để probe quote char trong đúng
        # JS string context, đọc kết quả từ <script> block của response.
        def pjs(char: str, label: str) -> Behavior:
            b = _probe_char_in_js_string(base_url, param, marker, char, js_quote_char)
            raw[label] = b.value
            log.debug("  js_string char probe %-16s → %s", label, b.value)
            return b

        if js_quote_char == "'":
            fm.single_quote = pjs("'", "single_quote")
            fm.double_quote = Behavior.ALLOWED
            fm.backtick     = pc("`", "backtick")
        elif js_quote_char == '"':
            fm.double_quote = pjs('"', "double_quote")
            fm.single_quote = Behavior.ALLOWED
            fm.backtick     = pc("`", "backtick")
        elif js_quote_char == "`":
            fm.backtick     = pjs("`", "backtick")
            fm.single_quote = Behavior.ALLOWED
            fm.double_quote = Behavior.ALLOWED
        else:
            fm.single_quote = Behavior.ALLOWED
            fm.double_quote = Behavior.ALLOWED
            fm.backtick     = Behavior.ALLOWED

        fm.backslash  = _probe_backslash(base_url, param, marker)
        raw["backslash"] = fm.backslash.value

        fm.angle_open  = pc("<", "angle_open")
        fm.angle_close = pc(">", "angle_close")

        if fm.tags_usable:
            fm.script_tag = _probe_script(base_url, param, marker)
            raw["script_tag"] = fm.script_tag.value

    fm.raw = raw
    log.info(
        "FilterMap [ctx=%s param=%s]: allowed_tags=%s combos=%d",
        context, param,
        getattr(fm, "allowed_tags", []),
        len(getattr(fm, "allowed_combos", [])),
    )
    return fm
