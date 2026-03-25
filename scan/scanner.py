"""
scanner.py — HTTP probing + reflection scanning pipeline.

Public API
----------
probe_endpoint(endpoint)    -> list[dict]
run_marker_scan(endpoints)  -> list[dict]
enable_debug(dir)           -> None
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

import requests
from requests import Response

from scan.marker import generate_marker
from scan.injector import (
    build_probe_urls,
    ProbeTarget, Param, BARE_PARAM_NAME,
)
from scan.detector import (
    detect_per_position,
    ReflectionPoint,
)

log = logging.getLogger("xss_scanner.scanner")

REQUEST_TIMEOUT   = 10
MAX_RESPONSE_SIZE = 5_000_000

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (compatible; XSSReflectionScanner/1.0; "
        "+https://github.com/your-org/xss-scanner)"
    ),
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
})


def _fetch(url: str) -> Optional[Response]:
    try:
        resp = SESSION.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        log.warning("Request failed %s: %s", url, exc)
        return None

    if "html" not in resp.headers.get("Content-Type", ""):
        return None
    if len(resp.content) > MAX_RESPONSE_SIZE:
        log.warning("Response too large for %s", url)
        return None
    return resp


def probe_endpoint(endpoint: dict) -> list[dict]:
    """
    Probe every parameter in endpoint for reflection.

    Returns a list of reflection records. Each record represents one
    (param, position, context) triple — a single parameter that reflects
    in multiple contexts produces MULTIPLE records, one per context/position.

    Record schema:
        {
            "url":        str,   # clean base URL
            "param":      str,   # parameter name
            "probe_kind": str,   # "value" | "key" | "bare"
            "probe_url":  str,   # exact URL fetched
            "context":    str,   # ONE context label for this position
            "attr_name":  str,   # attribute name if context=attribute/url
            "quote_char": str,   # quote char used: '"' | "'" | ""
            "position":   int,   # character offset in HTML
            "snippet":    str,   # excerpt around the reflection
        }
    """
    method = endpoint.get("method", "GET").upper()
    if method != "GET":
        return []

    raw_params = endpoint.get("params", [])

    # Normalise to list[Param] — params may be list[dict] (crawler/JSON)
    # or list[str] (legacy format). Crawler is the single source of truth;
    # no re-parsing of raw_url needed.
    all_params: list[Param] = []
    for p in raw_params:
        if isinstance(p, dict):
            all_params.append(Param(name=p["name"], has_value=p.get("has_value", True)))
        elif isinstance(p, str):
            all_params.append(Param(name=p, has_value=True))

    markers: dict[str, str] = {p.name: generate_marker() for p in all_params}
    # Bare probe only makes sense when there are no known params.
    if not all_params:
        markers[BARE_PARAM_NAME] = generate_marker()

    probe_targets: list[ProbeTarget] = build_probe_urls(endpoint, markers)
    results: list[dict] = []

    for target in probe_targets:
        log.info("Probing %s [param=%s]", target.injected_url, target.param.name)

        resp = _fetch(target.injected_url)
        if resp is None:
            continue

        html = resp.text
        raw_count = html.count(target.marker)

        if raw_count == 0:
            continue

        # Get per-position detail — one ReflectionPoint per occurrence
        points: list[ReflectionPoint] = detect_per_position(html, target.marker)

        if not points:
            continue

        param_label = (
            "(bare query)" if target.probe_kind == "bare"
            else target.param.name
        )

        # Deduplicate by context within this parameter (same context at
        # multiple positions → keep only the first occurrence)
        seen_ctx: set[str] = set()
        for pt in points:
            if pt.context in seen_ctx:
                continue
            seen_ctx.add(pt.context)

            log.info(
                "  ✓ Reflected! param=%r context=%s attr=%r quote=%r pos=%d",
                param_label, pt.context, pt.attr_name, pt.quote_char, pt.position,
            )

            results.append({
                "url":        target.original_url,
                "param":      param_label,
                "probe_kind": target.probe_kind,
                "probe_url":  target.injected_url,
                "context":    pt.context,
                "attr_name":  pt.attr_name,
                "quote_char": pt.quote_char,
                "position":   pt.position,
                "snippet":    pt.snippet,
            })

    return results


def run_marker_scan(endpoints: list[dict]) -> list[dict]:
    """
    Scan all GET endpoints for reflected parameters.
    Deduplicates on (url, param, context).
    """
    all_results: list[dict] = []
    seen: set[tuple] = set()

    get_eps = [e for e in endpoints if e.get("method", "GET").upper() == "GET"]
    log.info("Marker scan: %d GET endpoint(s)", len(get_eps))

    for idx, ep in enumerate(get_eps, 1):
        url = ep.get("url", "<unknown>")
        log.info("[%d/%d] %s", idx, len(get_eps), url)

        for r in probe_endpoint(ep):
            key = (r["url"], r["param"], r["context"])
            if key in seen:
                continue
            seen.add(key)
            all_results.append(r)

    log.info("Scan complete. %d reflected point(s) found.", len(all_results))
    return all_results