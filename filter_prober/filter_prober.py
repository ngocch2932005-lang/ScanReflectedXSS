"""
filter_prober.py — Atomic filter detection for XSS context.

2-phase brute-force:
  Phase 1: Probe các tags → tìm tag nào không bị block
  Phase 2: Probe events trên từng allowed tag → tìm combo (tag, event) hoạt động
  Result:  FilterMap.allowed_combos = [(tag, event), ...]

Mapping 5 lab PortSwigger → tags/events cần thiết:
  Lab 1 (html, body+onresize)      → tags: body | events: onresize, onpageshow
  Lab 2 (html, custom xss+onfocus) → tags: xss  | events: onfocus, onmouseover
  Lab 3 (attribute, onmouseover)   → probe events trên img (attr context)
  Lab 4 (js, angle brackets)       → probe script tag + angles
  Lab 5 (js, single quote escaped) → probe backslash + quote chars
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
# Behavior enum
# ---------------------------------------------------------------------------

class Behavior(str, Enum):
    ALLOWED  = "allowed" #cho phép
    ENCODED  = "encoded" #ký tự bị mã hóa
    ESCAPED  = "escaped" #ký tự bị escape \
    DOUBLED  = "doubled" #ký tự \ -> \\
    STRIPPED = "stripped" #ký tự bị cắt đi hoàn toàn
    UNKNOWN  = "unknown" #không xác định


# ---------------------------------------------------------------------------
# Tags & Events
# ---------------------------------------------------------------------------

ALL_TAGS: list[str] = [
    "body",
    "xss",
    "img",
    "svg",
    "input",
]

ALL_EVENTS: list[str] = [
    "onresize",
    "onpageshow",
    "onfocus",
    "onerror",
    "onload",
    "ontoggle",
    "onmouseover",
    "onclick",
]


# ---------------------------------------------------------------------------
# FilterMap
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

    raw: dict = field(default_factory=dict)

    @property
    def tags_usable(self) -> bool:
        bad = (Behavior.ENCODED, Behavior.STRIPPED)
        return self.angle_open not in bad and self.angle_close not in bad

    @property
    def script_usable(self) -> bool:
        return self.tags_usable and self.script_tag == Behavior.ALLOWED

    @property
    def backslash_doubles(self) -> bool:
        return self.backslash == Behavior.DOUBLED


# ---------------------------------------------------------------------------
# Known encoding forms
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
# HTTP helpers
# ---------------------------------------------------------------------------

def _build_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _fetch_text(base_url: str, param: str, value: str) -> str | None:
    url = _build_url(base_url, param, value)
    try:
        r = _SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if "html" not in r.headers.get("Content-Type", ""):
            return None
        return r.text
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Character analyser
# ---------------------------------------------------------------------------

def _analyse_char(html: str, sentinel: str, char: str) -> Behavior:
    if html is None:
        return Behavior.UNKNOWN

    if f"{sentinel}{char}{sentinel}" in html:
        return Behavior.ALLOWED

    m = re.search(re.escape(sentinel) + r"(.*?)" + re.escape(sentinel),
                  html, re.DOTALL)
    if not m:
        return Behavior.STRIPPED

    between = m.group(1)

    if not between:
        return Behavior.STRIPPED

    for form in _BACKSLASH_ESCAPE.get(char, []):
        if form in between:
            return Behavior.ESCAPED

    for form in _ENTITY_FORMS.get(char, []):
        if form.lower() in between.lower():
            return Behavior.ENCODED

    return Behavior.UNKNOWN


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
    sentinel = f"{marker}JS"
    html     = _fetch_text(base_url, param, f"{sentinel}{char}{sentinel}")
    if html is None:
        return Behavior.UNKNOWN

    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE):
        js_src = m.group(1)
        if sentinel not in js_src:
            continue

        idx1 = js_src.find(sentinel)
        idx2 = js_src.find(sentinel, idx1 + len(sentinel))
        if idx1 == -1 or idx2 == -1:
            continue

        between = js_src[idx1 + len(sentinel): idx2]
        log.debug("  js_string probe char=%r between=%r", char, between)

        if not between:
            return Behavior.STRIPPED
        if f"\\{char}" in between:
            return Behavior.ESCAPED
        if char in between:
            return Behavior.ALLOWED
        for form in _ENTITY_FORMS.get(char, []):
            if form.lower() in between.lower():
                return Behavior.ENCODED
        return Behavior.UNKNOWN

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
    html  = _fetch_text(base_url, param, probe)
    if html is None:
        return Behavior.UNKNOWN
    if probe in html:
        return Behavior.ALLOWED
    if marker in html:
        return Behavior.UNKNOWN
    return Behavior.STRIPPED


# ---------------------------------------------------------------------------
# Phase 1: Tag brute-force
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
# Phase 2: Event brute-force
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
# Public API
# ---------------------------------------------------------------------------

def probe_filters(
    base_url:      str,
    param:         str,
    marker:        str,
    context:       str,
    js_quote_char: str = "",
) -> FilterMap:

    if context == "script":
        context = "js"

    fm  = FilterMap()
    raw: dict = {}

    # ── HTML context ──────────────────────────────────────────────────────
    if context == "html":
        fm.angle_open   = _probe_char(base_url, param, marker, "<")
        fm.angle_close  = _probe_char(base_url, param, marker, ">")
        fm.double_quote = _probe_char(base_url, param, marker, '"')

        if not fm.tags_usable:
            fm.script_tag     = Behavior.STRIPPED
            fm.event_handlers = Behavior.STRIPPED
        else:
            fm.script_tag = _probe_script(base_url, param, marker)

            fm.allowed_tags = _probe_all_tags(base_url, param, marker, ALL_TAGS)

            if not fm.allowed_tags:
                fm.event_handlers = Behavior.STRIPPED
            else:
                def probe_tag_events(tag: str) -> list[tuple[str, str]]:
                    evs = _probe_all_events_on_tag(
                        base_url, param, marker, tag, ALL_EVENTS
                    )
                    return [(tag, ev) for ev in evs]

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(len(fm.allowed_tags), 4)
                ) as ex:
                    results = list(ex.map(probe_tag_events, fm.allowed_tags))

                fm.allowed_combos = [
                    combo for tag_combos in results for combo in tag_combos
                ]

                fm.event_handlers = (
                    Behavior.ALLOWED if fm.allowed_combos else Behavior.STRIPPED
                )

    # ── Attribute context ──────────────────────────────────────────────────
    elif context == "attribute":
        fm.angle_open   = _probe_char(base_url, param, marker, "<")
        fm.angle_close  = _probe_char(base_url, param, marker, ">")
        fm.double_quote = _probe_char(base_url, param, marker, '"')
        fm.single_quote = _probe_char(base_url, param, marker, "'")
        fm.backtick     = _probe_char(base_url, param, marker, "`")

        if (
            fm.double_quote == Behavior.ALLOWED
            or fm.single_quote == Behavior.ALLOWED
        ):
            allowed_evs = _probe_all_events_on_tag(
                base_url, param, marker, "img",
                ["onerror", "onload", "onmouseover", "onfocus", "ontoggle"]
            )
            fm.event_handlers = (
                Behavior.ALLOWED if allowed_evs else Behavior.STRIPPED
            )
        else:
            fm.event_handlers = Behavior.UNKNOWN

    # ── JS context ─────────────────────────────────────────────────────────
    elif context == "js":

        if js_quote_char == "'":
            fm.single_quote = _probe_char_in_js_string(base_url, param, marker, "'", js_quote_char)
            fm.double_quote = Behavior.ALLOWED
            fm.backtick     = _probe_char(base_url, param, marker, "`")

        elif js_quote_char == '"':
            fm.double_quote = _probe_char_in_js_string(base_url, param, marker, '"', js_quote_char)
            fm.single_quote = Behavior.ALLOWED
            fm.backtick     = _probe_char(base_url, param, marker, "`")

        elif js_quote_char == "`":
            fm.backtick     = _probe_char_in_js_string(base_url, param, marker, "`", js_quote_char)
            fm.single_quote = Behavior.ALLOWED
            fm.double_quote = Behavior.ALLOWED

        else:
            fm.single_quote = Behavior.ALLOWED
            fm.double_quote = Behavior.ALLOWED
            fm.backtick     = Behavior.ALLOWED

        fm.backslash = _probe_backslash(base_url, param, marker)

        fm.angle_open  = _probe_char(base_url, param, marker, "<")
        fm.angle_close = _probe_char(base_url, param, marker, ">")

        if fm.tags_usable:
            fm.script_tag = _probe_script(base_url, param, marker)

    fm.raw = raw

    log.info(
        "FilterMap [ctx=%s param=%s]: allowed_tags=%s combos=%d",
        context, param, fm.allowed_tags, len(fm.allowed_combos),
    )

    return fm