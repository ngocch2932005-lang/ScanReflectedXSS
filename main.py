"""
main.py — XSS Scanner entry point.

Pipeline giữ nguyên hoàn toàn so với bản gốc:
  crawl → marker scan → filter probe → payload gen → Playwright verify → report

Thay đổi:
  - filter_prober.py dùng list tags/events đã trim (đủ bypass 5 lab PortSwigger)
  - Code được dọn sạch, bỏ các option ít dùng

5 Test Case được hỗ trợ:
  Test 1: HTML context, most tags/attrs blocked
          → <body onresize=print()>

  Test 2: HTML context, all tags blocked except custom
          → <xss id=x onfocus=alert(document.cookie) tabindex=1>
          → Trigger qua URL fragment #x

  Test 3: Reflected XSS into attribute, angle brackets HTML-encoded
          → "onmouseover="alert(1)

  Test 4: Reflected XSS into JS string, single quote + backslash escaped
          → </script><script>alert(1)</script>

  Test 5: Reflected XSS into JS string, angles + double quotes encoded,
          single quotes escaped
          → \\'-alert(1)//

Modes:
  Crawl (default): python main.py https://LAB-ID.web-security-academy.net
  Single URL:      python main.py --url "https://LAB-ID.../?search=test"
  From file:       python main.py --input output.json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

from scan.marker         import generate_marker
from scan.scanner        import run_marker_scan, enable_debug
from filter_prober.filter_prober  import probe_filters
from verify.payload_generator import generate_payloads, AttributeMeta
from verify.verifier       import verify_finding, close_browser, Finding
from report.reporter       import write_report
from crawler.crawler     import crawl, save_json

log = logging.getLogger("xss_scanner.main")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Context mapping — giữ nguyên
# detector labels: "html" | "attribute" | "url" | "script" | "style" | "comment"
# ---------------------------------------------------------------------------

_CTX_MAP = {
    "html":      "html",
    "attribute": "attribute",
    "url":       "attribute",
    "script":    "js",
    "tag_name":  "attribute",
    "style":     None,    # skip
    "comment":   None,    # skip
}


# ---------------------------------------------------------------------------
# Single-URL helper — giữ nguyên
# ---------------------------------------------------------------------------

def _url_to_endpoint(raw_url: str) -> dict:
    parsed = urlparse(raw_url)
    param_names = []
    for part in parsed.query.split("&"):
        if part:
            name = part.split("=")[0]
            if name:
                param_names.append(name)
    clean = parsed._replace(query="", fragment="").geturl()
    return {
        "url":     clean,
        "method":  "GET",
        "params":  param_names,
        "raw_url": raw_url,
        "type":    "link",
    }


# ---------------------------------------------------------------------------
# Core scan pipeline — giữ nguyên hoàn toàn
# ---------------------------------------------------------------------------

def run_scan(
    endpoints:  list[dict],
    delay:      float = 0.0,
    target_url: str   = "",
) -> list[Finding]:
    """
    Pipeline đầy đủ:
      Phase 1: Inject unique markers → tìm reflected parameters + contexts
      Phase 2: probe_filters() → generate_payloads() → verify_finding()
    """
    # ── Phase 1: Reflection scan ─────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Phase 1 — Reflection scan ({len(endpoints)} endpoints)")
    print(f"{'='*60}\n")

    reflections = run_marker_scan(endpoints)

    if not reflections:
        log.info("No reflections found.")
        return []

    print(f"\n[+] {len(reflections)} reflected parameter/context(s) found.\n")

    # ── Phase 2: Filter → Payload → Verify ───────────────────────────────
    print(f"{'='*60}")
    print( "  Phase 2 — Filter probe → Payload → Playwright verify")
    print(f"{'='*60}\n")

    findings: list[Finding] = []
    seen:     set[tuple]    = set()

    for r in reflections:
        url        = r["url"]
        param      = r["param"]
        raw_ctx    = r.get("context",    "")
        attr_name  = r.get("attr_name",  "")
        quote_char = r.get("quote_char", '"')
        snippet    = r.get("snippet",    "")

        if param == "(bare query)":
            continue

        # Map detector context → pipeline context
        context = _CTX_MAP.get(raw_ctx)
        if context is None:
            log.debug("Skip non-exploitable context %r for %s[%s]",
                      raw_ctx, url, param)
            continue

        if raw_ctx == "url" and not attr_name:
            attr_name = "href"

        dedup_key = (url, param, context, attr_name)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Print target info
        print(f"  ┌─ {url}")
        print(f"  │  param={param!r}  ctx={raw_ctx}→{context}"
              f"  attr={attr_name!r}  quote={quote_char!r}")
        if snippet:
            print(f"  │  snippet: {snippet[:110]}")

        # ── 2a: Probe filters ────────────────────────────────────────────
        marker = generate_marker()
        js_qc  = quote_char if context == "js" else ""

        fm = probe_filters(
            base_url      = url,
            param         = param,
            marker        = marker,
            context       = context,
            js_quote_char = js_qc,
        )

        if context == "js":
            desc = "raw JS" if not js_qc else f"inside {js_qc!r}-quoted string"
            print(f"  │  js position: {desc}")

        # ── 2b: Generate payloads ─────────────────────────────────────────
        attr_meta = None
        if context == "attribute":
            attr_meta = AttributeMeta(
                attr_name  = attr_name,
                is_quoted  = bool(quote_char),
                quote_char = quote_char or '"',
            )

        payloads = generate_payloads(
            context       = context,
            filter_map    = fm,
            attr_meta     = attr_meta,
            js_quote_char = js_qc,
        )

        if not payloads:
            print(f"  └─ [SKIP] no viable payloads for this filter state\n")
            continue

        log.info("  Generated %d payload(s) — launching Playwright verify",
                 len(payloads))

        # ── 2c: Verify with Playwright ────────────────────────────────────
        finding = verify_finding(
            base_url  = url,
            param     = param,
            context   = context,
            payloads  = payloads,
            attr_name = attr_name,
            delay     = delay,
        )

        if finding:
            print(f"  └─ [✓ CONFIRMED]  strategy={finding.payload.strategy}")
            print(f"                   payload={finding.payload.value!r}\n")
            findings.append(finding)
        else:
            print(f"  └─ [✗ NOT CONFIRMED]  {len(payloads)} payload(s) tried\n")

    print(f"{'='*60}")
    print(f"  Scan complete — {len(findings)} confirmed finding(s).")
    print(f"{'='*60}\n")
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "xss-scanner",
        description = (
            "Reflected XSS scanner — "
            "crawl → reflect → filter probe → verify (Playwright) → report\n\n"
            "Tags probed  : body, xss, x, img, svg, input, details, script\n"
            "Events probed: onresize, onpageshow, onfocus, onerror, onload,\n"
            "               ontoggle, onmouseover, onclick"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("seed_url", nargs="?", default=None,
                     help="Seed URL — crawl rồi scan.")
    src.add_argument("--url",   metavar="URL",
                     help="Scan single URL, bỏ qua crawl.")
    src.add_argument("--input", metavar="FILE",
                     help="Load crawler JSON đã có sẵn.")
    p.add_argument("--depth",       type=int,   default=2,
                   help="Crawl depth (default: 2)")
    p.add_argument("--max-urls",    type=int,   default=50,
                   help="Max URLs to crawl (default: 50)")
    p.add_argument("--skip-static", action="store_true",
                   help="Bỏ qua static assets khi crawl")
    p.add_argument("--output",      default="output.json",
                   help="Crawler JSON output (default: output.json)")
    p.add_argument("--delay",       type=float, default=0.0,
                   help="Giây chờ giữa verify requests (default: 0)")
    p.add_argument("--report-dir",  default="reports",
                   help="Thư mục xuất báo cáo (default: reports)")
    p.add_argument("--debug",       action="store_true",
                   help="Dump probe HTML responses vào debug_responses/")
    p.add_argument("--verbose",     action="store_true",
                   help="Bật DEBUG logging")
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose)

    if args.debug:
        enable_debug()

    target_url = args.seed_url or args.url or ""

    # ── Load endpoints ────────────────────────────────────────────────────
    if args.url:
        parsed = urlparse(args.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            print(f"[!] Invalid URL: {args.url!r}", file=sys.stderr)
            sys.exit(1)
        endpoints = [_url_to_endpoint(args.url)]

    elif args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"[!] File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        try:
            endpoints = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[!] Invalid JSON: {exc}", file=sys.stderr)
            sys.exit(1)
        log.info("Loaded %d endpoints from %s", len(endpoints), args.input)

    elif args.seed_url:
        parsed = urlparse(args.seed_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            print(f"[!] Invalid seed URL: {args.seed_url!r}", file=sys.stderr)
            sys.exit(1)
        endpoints = crawl(
            seed_url    = args.seed_url,
            max_depth   = args.depth,
            max_urls    = args.max_urls,
            skip_static = args.skip_static,
        )
        save_json(endpoints, args.output)

    else:
        parser.print_help()
        sys.exit(0)

    if not endpoints:
        print("[-] No endpoints to scan.")
        sys.exit(0)

    # ── Scan ──────────────────────────────────────────────────────────────
    try:
        findings = run_scan(endpoints, delay=args.delay, target_url=target_url)
    finally:
        close_browser()

    # ── Console summary ───────────────────────────────────────────────────
    if findings:
        print(f"[+] {len(findings)} confirmed XSS finding(s):\n")
        print("=" * 70)
        for i, f in enumerate(findings, 1):
            print(f"  #{i}  {f.url}  [{f.param}]  {f.context}")
            print(f"      Strategy : {f.payload.strategy}")
            print(f"      Payload  : {f.payload.value}")
            if f.payload.note:
                print(f"      Note     : {f.payload.note}")
            print(f"      Evidence : {f.evidence}")
            print(f"      Probe URL: {f.probe_url}")
            print("=" * 70)
    else:
        print("[-] No confirmed XSS findings.")

    # ── Reports ───────────────────────────────────────────────────────────
    paths = write_report(
        findings   = findings,
        output_dir = args.report_dir,
        target_url = target_url,
    )
    print(f"\n[+] Reports written:")
    print(f"    JSON → {paths['json']}")
    print(f"    HTML → {paths['html']}\n")


if __name__ == "__main__":
    main()
