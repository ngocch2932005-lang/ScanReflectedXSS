"""
detector.py — Reflection detection and HTML-context classification.

Public API
----------
find_reflections(html, marker)        -> list[int]
detect_per_position(html, marker)     -> list[ReflectionPoint]
extract_snippet(html, pos, marker)    -> str

Supported contexts
------------------
  html       — marker nằm trong text node hoặc ngoài tag
  attribute  — marker nằm trong giá trị thuộc tính HTML
               quote_char: '"' | "'" | "" (unquoted)
               attr_name:  tên thuộc tính
  script     — marker nằm trong <script>...</script>
               quote_char: "'" | '"' | "`" | "" (raw JS)

Các context style, comment, url, tag_name bị loại bỏ:
  - style / comment: không xử lý, bỏ qua hoàn toàn (skip reflection).
  - url: gộp vào attribute — attr_name đủ để phân biệt nếu cần.
  - tag_name: gộp vào html.
"""

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Block-context patterns
# ---------------------------------------------------------------------------

_SCRIPT_PAT  = re.compile(r"<script(?:\s[^>]*)?>.*?</script>", re.DOTALL | re.IGNORECASE)
_STYLE_PAT   = re.compile(r"<style(?:\s[^>]*)?>.*?</style>",   re.DOTALL | re.IGNORECASE)
_COMMENT_PAT = re.compile(r"<!--.*?-->",                         re.DOTALL)

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
    context   : "html" | "attribute" | "script"
    attr_name : attribute name if context is "attribute", else ""
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
    """
    i      = 0
    in_str = ""  # current string delimiter, "" = not in string

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

    return in_str  # "" = raw JS, "'" / '"' / "`" = inside that string


# ---------------------------------------------------------------------------
# HTML attribute context classifier
# ---------------------------------------------------------------------------

def _classify_position(html: str, pos: int) -> tuple[str, str, str]:
    """
    Backwards-walk from pos to classify context.
    Returns (context, attr_name, quote_char).

    context is one of: "html" | "attribute"
    tag_name positions are folded into "html".
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
            for c in tag_content:
                if c == '"' and not in_sq:
                    in_dq = not in_dq
                elif c == "'" and not in_dq:
                    in_sq = not in_sq

            stripped  = tag_content.rstrip()
            am        = _ATTR_NAME_RE.search(stripped)
            attr_name = am.group(1).lower() if am else ""

            if in_dq:
                return "attribute", attr_name, '"'

            if in_sq:
                return "attribute", attr_name, "'"

            if stripped.endswith("="):
                am2   = re.search(r'([\w:_-]+)\s*=\s*$', stripped, re.IGNORECASE)
                aname = am2.group(1).lower() if am2 else ""
                return "attribute", aname, ""

            # tag_name or bare inside tag → treat as html
            return "html", "", ""

        j -= 1

    return "html", "", ""


# ---------------------------------------------------------------------------
# Public: per-position detail
# ---------------------------------------------------------------------------

def detect_per_position(html: str, marker: str) -> list[ReflectionPoint]:
    """
    Return one ReflectionPoint per occurrence of marker in html.

    Positions inside <style> or HTML comments are silently skipped —
    payloads cannot execute in those contexts.

    For script context, quote_char tells the JS string delimiter:
      "'"  → inside single-quoted string  → need ' breakout
      '"'  → inside double-quoted string  → need " breakout
      '`'  → inside template literal      → need ` breakout
      ""   → raw JS                       → direct execution
    """
    if not html or marker not in html:
        return []

    script_spans = _build_spans(html, _SCRIPT_PAT)
    ignore_spans = (
        _build_spans(html, _STYLE_PAT) +
        _build_spans(html, _COMMENT_PAT)
    )

    # Pre-extract script block contents and their start offsets
    script_blocks: list[tuple[int, str]] = []
    for m in _SCRIPT_PAT.finditer(html):
        tag_end = html.index(">", m.start()) + 1
        script_blocks.append((tag_end, html[tag_end: m.end()]))

    points: list[ReflectionPoint] = []
    for pos in find_reflections(html, marker):

        # Skip style blocks and HTML comments entirely
        if _in_spans(pos, ignore_spans):
            continue

        if _in_spans(pos, script_spans):
            ctx, aname, qchar = "script", "", ""
            for (js_start, js_content) in script_blocks:
                if js_start <= pos < js_start + len(js_content):
                    qchar = _js_quote_char(js_content, pos - js_start)
                    break

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
