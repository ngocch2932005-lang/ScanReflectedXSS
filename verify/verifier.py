"""
verifier.py — XSS payload verification using    .

Architecture
============
- Dùng một browser instance duy nhất cho cả session (khởi động 1 lần)
- Mỗi payload: tạo new BrowserContext (isolated cookies/storage)
- Timeout 4s mỗi page, dismiss dialog ngay khi xuất hiện
  với cảnh báo rõ ràng (không im lặng degrade)

Supported contexts: "html" | "attribute" | "script"

Public API
----------
verify_finding(base_url, param, context, payloads, attr_name, delay) -> Finding | None
close_browser() -> None
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from playwright.sync_api import sync_playwright

from verify.payload_generator import Payload


log = logging.getLogger("xss_scanner.verifier")

REQUEST_TIMEOUT = 10
PAGE_TIMEOUT_MS = 6_000
DIALOG_WAIT_MS  = 1_500

_HTTP_SESSION = requests.Session()
_HTTP_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; XSSScanner/3.0)",
    "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
})


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
# object đại diện cho một lỗ hổng đã được xác nhận
@dataclass
class Finding:
    url:       str
    param:     str
    context:   str
    attr_name: str
    payload:   Payload
    probe_url: str
    evidence:  str # bằng chứng xác minh diglog đã bật
    snippet:   str = "" # đoạn HTML xung quang để tiện report, debug.


# ---------------------------------------------------------------------------
# Playwright browser — singleton, lazy init
# ---------------------------------------------------------------------------

_pw      = None # instance playwright runtime
_browser = None
# chỉ khởi tạo browser 1 lần, sau đó dùng lại cho nhiều lần verify
def _get_browser():
    global _pw, _browser
    if _browser is not None: # nếu có rồi thì trả về luôn
        return _browser
    try: # nếu chưa có gọi sync_playwright để launch chromium headless (k có giao diện).
        _pw      = sync_playwright().start()
        _browser = _pw.chromium.launch(
            headless = True,
            args     = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
            ],
        )
        log.info("Playwright Chromium launched")
        return _browser
    except Exception as exc:
        log.warning("Playwright not available: %s — falling back to HTTP mode", exc)
        return None

# đóng trình duyệt, stop instance playwright
def close_browser() -> None:
    global _pw, _browser
    if _browser:
        try:
            _browser.close()
        except Exception:
            pass
        _browser = None
    if _pw:
        try:
            _pw.stop()
        except Exception:
            pass
        _pw = None


# ---------------------------------------------------------------------------
# URL injection helper
# ---------------------------------------------------------------------------
# thay giá trị gốc, build lại url hoàn chỉnh
def _inject_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ---------------------------------------------------------------------------
# Playwright verification
# ---------------------------------------------------------------------------

# sinh javascript để kích hoạt event
def _get_trigger_js(strategy: str) -> str | None:
    s = strategy.lower()

    if "onresize" in s:
        return "window.dispatchEvent(new Event('resize'));"

    if "onfocus" in s:
        return """
(function() {
    var el = document.getElementById('x');
    if (el) { el.focus(); return; }
    var els = document.querySelectorAll('[tabindex]');
    for (var i = 0; i < els.length; i++) { els[i].focus(); }
})();
"""

    if "ontoggle" in s:
        return """
(function() {
    var d = document.querySelector('details');
    if (d) { d.open = !d.open; d.open = !d.open; }
})();
"""

    return None


def _verify_playwright(probe_url: str, payload: Payload) -> tuple[bool, str]:
    browser = _get_browser()
    if browser is None:
        return False, ""

    ctx  = None
    page = None
    try:
        ctx = browser.new_context(
            ignore_https_errors = True,
            extra_http_headers  = {"User-Agent": "Mozilla/5.0 (compatible; XSSScanner/3.0)"},
        )
        page = ctx.new_page()

        dialogs: list[dict] = []

        # bắt dialog, khi có được xss payload chạy kiểu alert(1) sẽ bắt được event dialog
        # sau đó lưu lại type, và message, và dismiss ngay để k bị treo.
        def _on_dialog(dialog):
            dialogs.append({"type": dialog.type, "message": dialog.message})
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", _on_dialog)
        
        try:
            page.goto(probe_url, timeout=PAGE_TIMEOUT_MS, wait_until="domcontentloaded")
        except Exception as nav_err:
            log.debug("Navigation exception (may be OK): %s", nav_err)

        try:
            page.wait_for_timeout(500)
        except Exception:
            pass

        trigger_js = _get_trigger_js(payload.strategy)
        if trigger_js and not dialogs:
            try:
                page.evaluate(trigger_js)
                log.debug("  Trigger JS dispatched for strategy=%s", payload.strategy)
            except Exception as e:
                log.debug("  Trigger JS error: %s", e)

        try:
            page.wait_for_timeout(DIALOG_WAIT_MS)
        except Exception:
            pass

        if dialogs:
            d = dialogs[0]
            evidence = (
                f"Playwright: {d['type']} dialog fired"
                f"{' — msg: ' + d['message'][:40] if d['message'] else ''}"
                f" | strategy={payload.strategy}"
            )
            log.info("  [PLAYWRIGHT CONFIRMED] %s", evidence)
            return True, evidence

        return False, ""

    except Exception as exc:
        log.debug("Playwright error for %s: %s", probe_url, exc)
        return False, ""
    finally:
        if page:
            try:
                page.close()
            except Exception:
                pass
        if ctx:
            try:
                ctx.close()
            except Exception:
                pass



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_finding(
    base_url:   str,
    param:      str,
    context:    str,
    payloads:   list[Payload],
    attr_name:  str   = "",
    delay:      float = 0.0,
) -> Optional[Finding]:
    """
    Thử từng payload theo thứ tự, trả về Finding đầu tiên được xác nhận.

    Args:
        base_url:  Clean endpoint URL.
        param:     Tên parameter để inject.
        context:   "html" | "attribute" | "script"
        payloads:  Danh sách Payload từ generate_payloads().
        attr_name: Tên attribute nếu context=attribute.
        delay:     Giây chờ giữa các requests.
    """
    pw_available = _get_browser() is not None
    if not pw_available:
        log.warning(
            "Playwright unavailable — using HTTP fallback. "
            "Results may have false positives/negatives. "
            "Install: pip install playwright && playwright install chromium"
        )

    for i, payload in enumerate(payloads, 1):
        if delay and i > 1:
            time.sleep(delay)

        probe_url = _inject_url(base_url, param, payload.value)

        log.info(
            "  [%d/%d] %-32s %s",
            i, len(payloads),
            payload.strategy,
            probe_url[:80] + ("..." if len(probe_url) > 80 else ""),
        )

        if pw_available:
            confirmed, evidence = _verify_playwright(probe_url, payload)
        # else:
        #     confirmed, evidence = _verify_http_fallback(base_url, param, payload)

        if confirmed:
            snippet = ""
            try:
                resp = _HTTP_SESSION.get(
                    probe_url, timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
                idx = resp.text.find(payload.value[:20])
                if idx != -1:
                    lo = max(0, idx - 80)
                    hi = min(len(resp.text), idx + len(payload.value) + 80)
                    snippet = resp.text[lo:hi]
            except Exception:
                pass

            return Finding(
                url       = base_url,
                param     = param,
                context   = context,
                attr_name = attr_name,
                payload   = payload,
                probe_url = probe_url,
                evidence  = evidence,
                snippet   = snippet,
            )

    return None
