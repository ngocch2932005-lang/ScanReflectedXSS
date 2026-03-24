"""
crawler_v2.py — Discovery-only web crawler for security testing (Phase 1, v2).

Improvements over v1:
  - Extracts query parameters from link URLs (not just from forms)
  - Stores raw_url (original full URL with query string)
  - Adds "type" field: "link" or "form"
  - Saves results to JSON file (output.json by default)
  - Deduplicates by (url, method, sorted params)

Usage:
    python crawler_v2.py https://example.com
    python crawler_v2.py https://example.com --max-depth 3 --max-urls 200 --skip-static --output results.json

Non-goals: NO scanning, NO payload injection, NO form submission, NO JS execution.
"""

import argparse
import json
import sys
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_URLS  = 150
DEFAULT_OUTPUT    = "output.json"
TIMEOUT           = 10

STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
}

IGNORED_SCHEMES = {"javascript", "mailto", "tel", "data", "ftp"}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SecurityCrawler/2.0; +discovery-only)"}


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
#Chuẩn hóa URL, loại bỏ fragment,lọc schema http, https
def normalize_url(url: str, base: str) -> str | None:
    """Resolve relative URL, strip fragment, reject non-HTTP schemes."""
    url = url.strip()
    if not url:
        return None
    if urlparse(url).scheme.lower() in IGNORED_SCHEMES:
        return None
    absolute, _ = urldefrag(urljoin(base, url))
    return absolute if urlparse(absolute).scheme in ("http", "https") else None

#kiểm tra domain
def same_domain(url: str, seed: str) -> bool:
    return urlparse(url).netloc == urlparse(seed).netloc

#kiểm tra url thuộc loại tĩnh
def is_static(url: str) -> bool:
    return any(urlparse(url).path.lower().endswith(ext) for ext in STATIC_EXTENSIONS)

#Lấy ra URL sạch và tách riêng phần params + sắp xếp params
def _parse_params_from_query(query: str) -> list[dict]:
    """
    Parse a query string into structured param dicts, preserving all param types.

    Unlike parse_qs(), this keeps:
      - key-only params (?heh)       -> {"name": "heh", "has_value": False}
      - empty-value params (?q=)     -> {"name": "q",   "has_value": True}
      - normal params (?q=123)       -> {"name": "q",   "has_value": True}

    This is the single source of truth for param parsing. The injector must
    consume these dicts directly and never re-parse the raw URL.
    """
    if not query:
        return []
    seen: set[str] = set()
    params: list[dict] = []
    for part in query.split("&"):
        if not part:
            continue
        has_value = "=" in part
        name = part.split("=", 1)[0]
        if name and name not in seen:
            seen.add(name)
            params.append({"name": name, "has_value": has_value})
    return params


def split_url(url: str) -> tuple[str, list[dict]]:
    """
    Split a URL into (clean_url_without_query, parsed_params).

    Returns params as structured dicts (not plain strings) so that
    has_value information is never lost downstream.

    Example:
        "https://example.com/search?q=test&heh"
        -> ("https://example.com/search", [
               {"name": "q",   "has_value": True},
               {"name": "heh", "has_value": False},
           ])
    """
    parsed = urlparse(url)
    # Strip query string from URL for the canonical endpoint path
    clean = parsed._replace(query="", fragment="").geturl()
    params = _parse_params_from_query(parsed.query)
    return clean, params


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
#Thực hiện thao tác GET URL
def fetch_page(url: str) -> str | None:
    """GET a URL and return HTML text, or None on any error."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        if "html" not in r.headers.get("Content-Type", ""):
            return None
        return r.text
    except requests.exceptions.Timeout:
        print(f"  [TIMEOUT] {url}", file=sys.stderr)
    except requests.exceptions.HTTPError as e:
        print(f"  [HTTP {e.response.status_code}] {url}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] {url} — {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
#Beautifulsoup biến html trả về thành DOM tree

#
def extract_links(html: str, base: str, skip_static: bool) -> list[str]:
    """Return all valid same-page-or-child absolute URLs from <a href> tags."""
    soup = BeautifulSoup(html, "html.parser")
    seen = set()
    for tag in soup.find_all("a", href=True):
        url = normalize_url(tag["href"], base)
        if url and not (skip_static and is_static(url)):
            seen.add(url)
    return list(seen)


def extract_forms(html: str, base: str) -> list[dict]:
    """
    Read <form> elements and return endpoint dicts.
    Never submits — discovery only.
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []
    for form in soup.find_all("form"):
        raw_action = form.get("action", "")
        action_url = normalize_url(raw_action, base) or base
        method = form.get("method", "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        # Form fields always have values (submitted as key=value pairs)
        form_params = [
            {"name": name, "has_value": True}
            for name in sorted({
                f.get("name")
                for f in form.find_all(["input", "select", "textarea"])
                if f.get("name")
            })
        ]
        clean_url, url_params = split_url(action_url)
        # Merge URL params (if action has query string) with form field names,
        # deduplicating by name; url_params take precedence (preserve has_value)
        url_param_names = {p["name"] for p in url_params}
        all_params = url_params + [p for p in form_params if p["name"] not in url_param_names]
        results.append({
            "url":     clean_url,
            "method":  method,
            "params":  all_params,
            "raw_url": action_url,
            "type":    "form",
        })
    return results


def make_link_endpoint(raw_url: str) -> dict:
    """Build a structured endpoint dict from a raw link URL."""
    clean_url, params = split_url(raw_url)
    return {
        "url":     clean_url,
        "method":  "GET",
        "params":  params,
        "raw_url": raw_url,
        "type":    "link",
    }


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl(
    seed_url: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_urls: int  = DEFAULT_MAX_URLS,
    skip_static: bool = False,
) -> list[dict]:
    """
    BFS crawl within seed_url's domain.
    Returns a deduplicated list of endpoint dicts.
    """
    queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
    visited:        set[str]   = set()
    endpoint_keys:  set[tuple] = set()
    endpoints:      list[dict] = []

    def add(ep: dict) -> None:
        # Params are now dicts; hash by (name, has_value) tuples for dedup
        key = (ep["url"], ep["method"], tuple((p["name"], p["has_value"]) for p in ep["params"]))
        if key not in endpoint_keys:
            endpoint_keys.add(key)
            endpoints.append(ep)

    add(make_link_endpoint(seed_url))

    print(f"\n[*] Crawling: {seed_url}  (depth={max_depth}, max_urls={max_urls})\n")

    while queue:
        url, depth = queue.popleft()

        if url in visited or len(visited) >= max_urls or depth > max_depth:
            continue

        visited.add(url)
        print(f"  [d{depth}] ({len(visited)}/{max_urls}) {url}")

        html = fetch_page(url)
        if not html:
            continue

        # Forms → endpoints (no requests sent)
        for ep in extract_forms(html, url):
            if same_domain(ep["url"], seed_url):
                add(ep)

        # Links → enqueue + record as endpoints
        if depth < max_depth:
            for link in extract_links(html, url, skip_static):
                if same_domain(link, seed_url) and link not in visited:
                    queue.append((link, depth + 1))
                    add(make_link_endpoint(link))

    print(f"\n[+] Done. Visited {len(visited)} pages, found {len(endpoints)} endpoints.\n")
    return endpoints


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_json(endpoints: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(endpoints, f, indent=2)
    print(f"[+] Saved {len(endpoints)} endpoints → {path}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discovery-only web crawler v2 — for security testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url",                                     help="Seed URL")
    parser.add_argument("--max-depth",  type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-urls",   type=int, default=DEFAULT_MAX_URLS)
    parser.add_argument("--output",     default=DEFAULT_OUTPUT,    help="JSON output file")
    parser.add_argument("--skip-static", action="store_true",      help="Skip static assets")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"[!] Invalid URL: {args.url!r}", file=sys.stderr)
        sys.exit(1)

    endpoints = crawl(args.url, args.max_depth, args.max_urls, args.skip_static)
    save_json(endpoints, args.output)


if __name__ == "__main__":
    main()