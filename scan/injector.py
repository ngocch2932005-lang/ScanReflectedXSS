"""
injector.py — Build probe URLs by injecting a marker into one parameter at a time.

Chỉ truyền giá trị đặc biệt vào duy nhất một param, nếu có các param khác trong cùng url thì truyền = test
-----------------------
Two probe kinds:

  value  — conventional:   ?search=MARKER  (marker as param value)
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
        name: Parameter name as it appears in the URL.
    """
    name: str


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
                       'bare'  — no known params, marker as bare query (?MARKER)
    """
    original_url: str
    param:        Param
    marker:       str
    injected_url: str
    probe_kind:   str  # 'value' | 'bare'


def build_probe_urls(endpoint: dict, markers: dict[str, str]) -> list[ProbeTarget]:
    """
    For every parameter in *endpoint*, build one probe URL with the marker injected.

    For value params → one probe: ?name=MARKER
    For bare probe   → one probe: ?MARKER  (when markers has BARE_PARAM_NAME key)

    The markers dict is keyed by param name (or BARE_PARAM_NAME for bare probes).

    Args:
        endpoint: Crawler output dict with 'url', 'params', etc.
        markers:  {param_name: marker_string}.  May include BARE_PARAM_NAME.

    Returns:
        List of ProbeTarget objects, one per param.
    """
    base_url = _strip_query(endpoint.get("url", ""))

    # Crawler is the single source of truth: consume param names directly.
    # has_value is intentionally ignored — all params are treated as value params.
    params: list[Param] = [
        Param(p["name"])
        for p in endpoint.get("params", [])
    ]

    targets: list[ProbeTarget] = []

    # --- Bare query probe (params=[]) ---
    if BARE_PARAM_NAME in markers:
        bare_marker = markers[BARE_PARAM_NAME]
        targets.append(ProbeTarget(
            original_url = base_url,
            param        = Param(name=BARE_PARAM_NAME),
            marker       = bare_marker,
            injected_url = f"{base_url}?{bare_marker}",
            probe_kind   = "bare",
        ))

    # --- Per-param probes ---
    for active in params:
        if active.name not in markers:
            continue
        marker = markers[active.name]

        query = _build_value_query(params, active, marker)
        targets.append(ProbeTarget(
            original_url = base_url,
            param        = active,
            marker       = marker,
            injected_url = f"{base_url}?{query}",
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
        else:
            parts.append(f"{p.name}={DUMMY_VALUE}")
    return "&".join(parts)


def _strip_query(url: str) -> str:
    """Return *url* with the query string and fragment removed."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))