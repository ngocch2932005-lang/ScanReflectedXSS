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
    build_probe_urls, parse_params,
    ProbeTarget, Param, BARE_PARAM_NAME,
)
from scan.detector import (
    find_reflections, detect_per_position,
    extract_snippet, ReflectionPoint,
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

_DEBUG_MODE = False
_DEBUG_DIR  = "debug_responses"


def enable_debug(output_dir: str = "debug_responses") -> None:
    global _DEBUG_MODE, _DEBUG_DIR
    _DEBUG_MODE = True
    _DEBUG_DIR  = output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    log.info("Debug mode ON → ./%s/", output_dir)


def _debug_save(param: str, url: str, html: str, marker: str) -> None:
    if not _DEBUG_MODE:
        return
    slug = hashlib.md5(url.encode()).hexdigest()[:8]
    path = Path(_DEBUG_DIR) / f"{param}_{slug}.html"
    count = html.count(marker)
    header = (
        f"<!-- DEBUG\n"
        f"     URL   : {url}\n"
        f"     Param : {param}\n"
        f"     Marker: {marker}\n"
        f"     Count : {count}x\n"
        f"     Len   : {len(html)}\n"
        f"-->\n"
    )
    path.write_text(header + html, encoding="utf-8", errors="replace")


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
    raw_url: str = endpoint.get("raw_url", "") or endpoint.get("url", "")

    # endpoint["params"] may be list[dict] (from crawler) or list[str] (from _url_to_endpoint)
    # Normalise to list[Param]
    crawler_params: list[Param] = []
    for p in raw_params:
        if isinstance(p, dict):
            crawler_params.append(Param(name=p["name"], has_value=p.get("has_value", True)))
        elif isinstance(p, str):
            crawler_params.append(Param(name=p, has_value=True))

    detected = {p.name: p for p in parse_params(raw_url)}
    known    = {p.name for p in crawler_params}

    all_params: list[Param] = []
    for cp in crawler_params:
        # prefer has_value info from raw_url parse if available, else trust crawler
        all_params.append(detected.get(cp.name, cp))
    for p in detected.values():
        if p.name not in known:
            all_params.append(p)

    markers: dict[str, str] = {p.name: generate_marker() for p in all_params}
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
        log.debug("  marker appears %dx  len=%d", raw_count, len(html))

        if raw_count == 0:
            log.debug("  No reflection for param '%s'", target.param.name)
            _debug_save(target.param.name, target.injected_url, html, target.marker)
            continue

        _debug_save(target.param.name, target.injected_url, html, target.marker)

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