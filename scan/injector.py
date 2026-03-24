"""
injector.py — Build probe URLs by injecting a marker into one parameter at a time.

Chỉ truyền giá trị đặc biệt vào duy nhất một param, nếu có các param khác trong cùng url thì truyền = test
-----------------------
Three probe kinds:

  value  — conventional:   ?search=MARKER  (marker as param value)
  key    — key-only param: ?MARKER         (marker as param key, no '=')
           Used when raw_url contains a valueless param like ?heh.
           Also generates a companion value probe: ?heh=MARKER.
  bare   — no known params at all: ?MARKER (URL base + marker as bare query)
           Used when crawler found params=[] but the server might still
           reflect an arbitrary query string (e.g. in canonical <link> tags).

Param dicts come directly from the crawler (single source of truth).
The injector never re-parses URLs; it trusts endpoint["params"] completely.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass

DUMMY_VALUE = "test"

# Sentinel name used for bare-query probes (no real param name exists)
BARE_PARAM_NAME = "__bare__"


@dataclass(frozen=True)
class Param:
    """
    Represents a single URL query parameter.

    Attributes:
        name:      Parameter name as it appears in the URL.
        has_value: False for key-only params (?heh → name='heh', has_value=False).
                   True for ordinary params (?q=1 → name='q', has_value=True).
    """
    name:      str
    has_value: bool = True


@dataclass(frozen=True)
class ProbeTarget:
    """
    One HTTP probe: one endpoint × one parameter × one marker.

    Attributes:
        original_url:  Base URL without query string or fragment.
        param:         The Param being probed.
        marker:        The unique marker injected for this probe.
        injected_url:  The full URL ready to be fetched.
        probe_kind:    'value' — marker is the param value   (?name=MARKER)
                       'key'   — marker is the param key     (?MARKER)
                       'bare'  — no known params, marker as bare query (?MARKER)
    """
    original_url: str
    param:        Param
    marker:       str
    injected_url: str
    probe_kind:   str  # 'value' | 'key' | 'bare'



def parse_params(url: str) -> list[Param]:
    """
    Parse query string of *url* into Param objects.

    Preserves all param types:
      - key-only  (?heh)  -> Param(name='heh', has_value=False)
      - empty val (?q=)   -> Param(name='q',   has_value=True)
      - normal    (?q=1)  -> Param(name='q',   has_value=True)

    Duplicate names are dropped (first occurrence wins).
    """
    query = urlparse(url).query
    if not query:
        return []
    seen: set[str] = set()
    params: list[Param] = []
    for part in query.split("&"):
        if not part:
            continue
        has_value = "=" in part
        name = part.split("=", 1)[0]
        if name and name not in seen:
            seen.add(name)
            params.append(Param(name=name, has_value=has_value))
    return params


def build_probe_urls(endpoint: dict, markers: dict[str, str]) -> list[ProbeTarget]:
    """
    For every parameter in *endpoint*, build probe URL(s) with the marker injected.

    For value params  → one probe:  ?name=MARKER
    For key params    → two probes: ?MARKER  and  ?name=MARKER
    For bare probe    → one probe:  ?MARKER  (when markers has BARE_PARAM_NAME key)

    The markers dict is keyed by param name (or BARE_PARAM_NAME for bare probes).

    Args:
        endpoint: Crawler output dict with 'url', 'params', 'raw_url', etc.
        markers:  {param_name: marker_string}.  May include BARE_PARAM_NAME.

    Returns:
        List of ProbeTarget objects, one (or two for key params) per param.
    """
    base_url = _strip_query(endpoint.get("url", ""))

    # Crawler is the single source of truth: consume params directly, no re-parsing.
    # Each entry is already {"name": str, "has_value": bool} from the crawler.
    params: list[Param] = [
        Param(p["name"], p["has_value"])
        for p in endpoint.get("params", [])
    ]

    targets: list[ProbeTarget] = []

    # --- Bare query probe (params=[]) ---
    if BARE_PARAM_NAME in markers:
        bare_marker = markers[BARE_PARAM_NAME]
        targets.append(ProbeTarget(
            original_url = base_url,
            param        = Param(name=BARE_PARAM_NAME, has_value=False),
            marker       = bare_marker,
            injected_url = f"{base_url}?{bare_marker}",
            probe_kind   = "bare",
        ))

    # --- Per-param probes ---
    for active in params:
        if active.name not in markers:
            continue
        marker = markers[active.name]

        if active.has_value:
            # Standard: ?active=MARKER & others=dummy
            query = _build_value_query(params, active, marker)
            targets.append(ProbeTarget(
                original_url = base_url,
                param        = active,
                marker       = marker,
                injected_url = f"{base_url}?{query}",
                probe_kind   = "value",
            ))
        else:
            # Key-only probe 1: ?MARKER
            query_key = _build_key_query(params, active, marker)
            targets.append(ProbeTarget(
                original_url = base_url,
                param        = active,
                marker       = marker,
                injected_url = f"{base_url}?{query_key}",
                probe_kind   = "key",
            ))
            # Key-only probe 2: ?name=MARKER (companion value probe)
            query_val = _build_value_query(
                params, Param(active.name, has_value=True), marker
            )
            targets.append(ProbeTarget(
                original_url = base_url,
                param        = Param(active.name, has_value=True),
                marker       = marker,
                injected_url = f"{base_url}?{query_val}",
                probe_kind   = "value",
            ))

    return targets


# ---------------------------------------------------------------------------
# Internal query-string builders
# ---------------------------------------------------------------------------

def _build_value_query(params: list[Param], active: Param, marker: str) -> str:
    """?active=MARKER & every other param gets a dummy value."""
    parts: list[str] = []
    for p in params:
        if p.name == active.name:
            parts.append(f"{p.name}={marker}")
        elif p.has_value:
            parts.append(f"{p.name}={DUMMY_VALUE}")
        else:
            parts.append(p.name)          # keep other key-only params intact
    return "&".join(parts)


def _build_key_query(params: list[Param], active: Param, marker: str) -> str:
    """?MARKER & every other param gets a dummy value."""
    parts: list[str] = []
    for p in params:
        if p.name == active.name:
            parts.append(marker)          # key-only: no '='
        elif p.has_value:
            parts.append(f"{p.name}={DUMMY_VALUE}")
        else:
            parts.append(p.name)
    return "&".join(parts)


def _strip_query(url: str) -> str:
    """Return *url* with the query string and fragment removed."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))