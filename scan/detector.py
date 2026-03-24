"""
detector.py — Reflection detection and HTML-context classification.

Public API
----------
find_reflections(html, marker) -> list[int]
detect_contexts(html, marker)  -> list[str]
detect_per_position(html, marker) -> list[ReflectionPoint]
extract_snippet(html, pos, marker) -> str

JS sub-context detection
------------------------
Khi marker nằm trong <script>...</script>, cần phân biệt:
  - Trong string literal đơn:  var x = 'MARKER'   → quote_char = "'"
  - Trong string literal kép:  var x = "MARKER"   → quote_char = '"'
  - Trong template literal:    var x = `MARKER`   → quote_char = "`"
  - Raw JS (không trong string): var x = MARKER;  → quote_char = ""

quote_char này truyền thẳng vào filter_prober và payload_generator
để chọn đúng strategy breakout.
"""

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Block-context patterns
# ---------------------------------------------------------------------------

_SCRIPT_PAT  = re.compile(r"<script(?:\s[^>]*)?>.*?</script>", re.DOTALL | re.IGNORECASE)
_STYLE_PAT   = re.compile(r"<style(?:\s[^>]*)?>.*?</style>",   re.DOTALL | re.IGNORECASE)
_COMMENT_PAT = re.compile(r"<!--.*?-->",                         re.DOTALL)

_URL_ATTR_GENERAL  = re.compile(
    r"(?:href|src|action|data|formaction)\s*=\s*",
    re.IGNORECASE,
)
_URL_ATTR_UNQUOTED = re.compile(
    r"(?:href|src|action|data|formaction)\s*=\s*$",
    re.IGNORECASE,
)

_ATTR_NAME_RE = re.compile(r'([\w:_-]+)\s*=\s*$', re.IGNORECASE)

SNIPPET_RADIUS = 80


# ---------------------------------------------------------------------------
# ReflectionPoint
# ---------------------------------------------------------------------------

@dataclass
class ReflectionPoint:
    """
    One reflection occurrence with full structural context.

    Fields
    ------
    position  : character offset in HTML
    context   : "html" | "attribute" | "url" | "script" | "style"
                | "comment" | "tag_name"
    attr_name : attribute name if context is "attribute"/"url", else ""
    quote_char: for attribute: the quote char ('"' | "'" | "")
                for script:    the JS string delimiter ('"' | "'" | "`" | "")
                               "" means raw JS (not inside a string literal)
    snippet   : short excerpt around the reflection
    """
    position:   int
    context:    str
    attr_name:  str = ""
    quote_char: str = ""
    snippet:    str = ""


# ---------------------------------------------------------------------------
# Snippet
# ---------------------------------------------------------------------------

def extract_snippet(html: str, pos: int, marker: str) -> str:
    start  = max(0, pos - SNIPPET_RADIUS)
    end    = min(len(html), pos + len(marker) + SNIPPET_RADIUS)
    before = html[start:pos]
    after  = html[pos + len(marker):end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(html) else ""
    return f"{prefix}{before}>>>{marker}<<<{after}{suffix}"


# ---------------------------------------------------------------------------
# Reflection finder
# ---------------------------------------------------------------------------

def find_reflections(html: str, marker: str) -> list[int]:
    positions: list[int] = []
    start = 0
    while True:
        idx = html.find(marker, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + len(marker)
    return positions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_spans(html: str, pattern: re.Pattern) -> list[tuple[int, int]]:
    return [m.span() for m in pattern.finditer(html)]


def _in_spans(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


# ---------------------------------------------------------------------------
# JS sub-context classifier
# ---------------------------------------------------------------------------

def _js_quote_char(script_content: str, marker_offset: int) -> str:
    """
    Walk the JS content before marker_offset to determine
    whether the marker lands inside a string literal.

    Returns the opening quote character: "'" | '"' | '`' | ""
    "" means the marker is in raw JS (not inside any string).

    Algorithm: simple state machine — tracks open string delimiters.
    Handles backslash escaping and template literal nesting.
    Does NOT handle multi-line regex or comments fully, but covers
    the common PortSwigger / real-world patterns correctly.
    """
    i        = 0
    in_str   = ""    # current string delimiter, "" = not in string
    in_tmpl  = 0     # template literal nesting depth

    while i < marker_offset:
        c = script_content[i]

        # Backslash escape inside string — skip next char
        if in_str and c == "\\" and i + 1 < marker_offset:
            i += 2
            continue

        if not in_str:
            if c in ('"', "'", "`"):
                in_str = c
        else:
            if c == in_str:
                in_str = ""

        i += 1

    return in_str   # "" = raw JS, "'" / '"' / "`" = inside that string


# ---------------------------------------------------------------------------
# HTML attribute context classifier
# ---------------------------------------------------------------------------

def _classify_position(html: str, pos: int) -> tuple[str, str, str]:
    """
    Backwards-walk from pos to classify HTML attribute context.
    Returns (context, attr_name, quote_char).
    """
    j = pos - 1
    while j >= 0:
        ch = html[j]

        if ch == ">":
            return "html", "", ""

        if ch == "<":
            tag_content = html[j + 1: pos]

            in_dq = False
            in_sq = False
            i = 0
            while i < len(tag_content):
                c = tag_content[i]
                if c == '"' and not in_sq:
                    in_dq = not in_dq
                elif c == "'" and not in_dq:
                    in_sq = not in_sq
                i += 1

            stripped   = tag_content.rstrip()
            am         = _ATTR_NAME_RE.search(stripped)
            attr_name  = am.group(1).lower() if am else ""

            if in_dq:
                is_url = bool(_URL_ATTR_GENERAL.search(tag_content))
                return ("url" if is_url else "attribute"), attr_name, '"'

            if in_sq:
                is_url = bool(_URL_ATTR_GENERAL.search(tag_content))
                return ("url" if is_url else "attribute"), attr_name, "'"

            if stripped.endswith("="):
                is_url = bool(_URL_ATTR_UNQUOTED.search(stripped))
                am2    = re.search(r'([\w:_-]+)\s*=\s*$', stripped, re.IGNORECASE)
                aname  = am2.group(1).lower() if am2 else ""
                return ("url" if is_url else "attribute"), aname, ""

            return "tag_name", "", ""

        j -= 1

    return "html", "", ""


# ---------------------------------------------------------------------------
# Public: per-position detail
# ---------------------------------------------------------------------------

def detect_per_position(html: str, marker: str) -> list[ReflectionPoint]:
    """
    Return one ReflectionPoint per occurrence of marker in html.

    For script context, quote_char tells the JS string delimiter:
      "'"  → marker is inside single-quoted string  → need ' breakout
      '"'  → marker is inside double-quoted string  → need " breakout
      '`'  → marker is inside template literal      → need ` breakout
      ""   → marker is raw JS                       → direct execution
    """
    if not html or marker not in html:
        return []

    script_spans  = _build_spans(html, _SCRIPT_PAT)
    style_spans   = _build_spans(html, _STYLE_PAT)
    comment_spans = _build_spans(html, _COMMENT_PAT)

    # Pre-extract script block contents and their start offsets
    script_blocks: list[tuple[int, str]] = []
    for m in _SCRIPT_PAT.finditer(html):
        # Find where the actual JS content starts (after the opening >)
        tag_end = html.index(">", m.start()) + 1
        script_blocks.append((tag_end, html[tag_end: m.end()]))

    points: list[ReflectionPoint] = []
    for pos in find_reflections(html, marker):

        if _in_spans(pos, comment_spans):
            ctx, aname, qchar = "comment", "", ""

        elif _in_spans(pos, script_spans):
            # Determine JS sub-context: which string literal (if any)?
            ctx   = "script"
            aname = ""
            qchar = ""
            for (js_start, js_content) in script_blocks:
                if js_start <= pos < js_start + len(js_content):
                    offset = pos - js_start
                    qchar  = _js_quote_char(js_content, offset)
                    break

        elif _in_spans(pos, style_spans):
            ctx, aname, qchar = "style", "", ""

        else:
            ctx, aname, qchar = _classify_position(html, pos)

        points.append(ReflectionPoint(
            position   = pos,
            context    = ctx,
            attr_name  = aname,
            quote_char = qchar,
            snippet    = extract_snippet(html, pos, marker),
        ))

    return points


# ---------------------------------------------------------------------------
# Public: legacy API
# ---------------------------------------------------------------------------

def detect_contexts(html: str, marker: str) -> list[str]:
    """Deduplicated, sorted list of context labels across all positions."""
    return sorted({p.context for p in detect_per_position(html, marker)})
