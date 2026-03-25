import re
from dataclasses import dataclass

_SCRIPT_PAT   = re.compile(r"<script(?:\s[^>]*)?>.*?</script>", re.DOTALL | re.IGNORECASE)
_ATTR_NAME_RE = re.compile(r'([\w:_-]+)\s*=\s*$', re.IGNORECASE)

SNIPPET_RADIUS = 80


@dataclass
class ReflectionPoint:
    position:   int
    context:    str
    attr_name:  str = ""
    quote_char: str = ""
    snippet:    str = ""


def extract_snippet(html: str, pos: int, marker: str) -> str:
    start  = max(0, pos - SNIPPET_RADIUS)
    end    = min(len(html), pos + len(marker) + SNIPPET_RADIUS)
    before = html[start:pos]
    after  = html[pos + len(marker):end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(html) else ""
    return f"{prefix}{before}>>>{marker}<<<{after}{suffix}"


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


def _build_script_spans(html: str) -> list[tuple[int, int, int]]:
    return [
        (m.start(), m.end(), html.index(">", m.start()) + 1)
        for m in _SCRIPT_PAT.finditer(html)
    ]


def _js_quote_char(html: str, js_start: int, pos: int) -> str:
    i      = js_start
    in_str = ""

    while i < pos:
        c = html[i]
        if in_str and c == "\\" and i + 1 < pos:
            i += 2
            continue
        if not in_str:
            if c in ('"', "'", "`"):
                in_str = c
        else:
            if c == in_str:
                in_str = ""
        i += 1

    return in_str


def _classify_position(html: str, pos: int) -> tuple[str, str, str]:
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

            return "html", "", ""

        j -= 1

    return "html", "", ""


def detect_per_position(html: str, marker: str) -> list[ReflectionPoint]:
    """
    Return one ReflectionPoint per occurrence of marker in html.

    For script context, quote_char tells the JS string delimiter:
      "'"  → inside single-quoted string  → need ' breakout
      '"'  → inside double-quoted string  → need " breakout
      '`'  → inside template literal      → need ` breakout
      ""   → raw JS                       → direct execution
    """
    if not html or marker not in html:
        return []

    script_spans = _build_script_spans(html)

    points: list[ReflectionPoint] = []
    for pos in find_reflections(html, marker):
        script_span = next((span for span in script_spans if span[0] < pos < span[1]), None)

        if script_span:
            _, _, js_start = script_span
            qchar = _js_quote_char(html, js_start, pos)
            ctx, aname = "script", ""
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

