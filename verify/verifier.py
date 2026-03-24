"""
verifier.py — XSS payload verification using Playwright.

Tại sao Playwright thay vì đọc chuỗi HTML?
==========================================
Regex/string matching trên HTML response có 2 vấn đề căn bản:

1. FALSE POSITIVE: Tìm "onerror=" trong HTML không có nghĩa payload XSS
   thực sự CHẠY được. Server có thể reflect payload vào attribute bị quote
   đúng cách, hoặc vào text node bị HTML-encode. Nhìn HTML thôi không đủ.

2. FALSE NEGATIVE: Payload có thể bị server transform (URL-encode, entity-encode,
   reorder attributes) khiến string matching fail dù payload thực sự work.

Playwright load URL đích bằng Chromium thật. Nếu alert()/confirm()/print()
thực sự được execute, dialog event sẽ fire. Đây là ground truth duy nhất.

Architecture
============
- Dùng một browser instance duy nhất cho cả session (khởi động 1 lần)
- Mỗi payload: tạo new BrowserContext (isolated cookies/storage)
- Timeout 4s mỗi page, dismiss dialog ngay khi xuất hiện
- Nếu Playwright không available: fallback về HTTP string matching
  với cảnh báo rõ ràng (không im lặng degrade)

Public API
----------
verify_finding(base_url, param, context, payloads, attr_name, delay) -> Finding | None
close_browser() -> None  # gọi khi scan xong để cleanup
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from verify.payload_generator import Payload

log = logging.getLogger("xss_scanner.verifier")

REQUEST_TIMEOUT  = 10
PAGE_TIMEOUT_MS  = 6_000   # giảm xuống để không chờ quá lâu mỗi payload
DIALOG_WAIT_MS   = 1_500   # 1.5s đủ để catch alert/confirm/print

_HTTP_SESSION = requests.Session()
_HTTP_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; XSSScanner/3.0)",
    "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
})


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    url:       str
    param:     str
    context:   str
    attr_name: str
    payload:   Payload
    probe_url: str
    evidence:  str
    snippet:   str = ""


# ---------------------------------------------------------------------------
# Playwright browser — singleton, khởi động lazy
# ---------------------------------------------------------------------------

_pw       = None   # playwright instance
_browser  = None   # Browser instance

def _get_browser():
    """Lazy-init Playwright + Chromium. Gọi lần đầu thì khởi động."""
    global _pw, _browser
    if _browser is not None:
        return _browser
    try:
        from playwright.sync_api import sync_playwright
        _pw      = sync_playwright().start()
        _browser = _pw.chromium.launch(
            headless = True,
            args     = [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",   # để test same-origin bypass labs
            ],
        )
        log.info("Playwright Chromium launched (PID managed by playwright)")
        return _browser
    except Exception as exc:
        log.warning("Playwright not available: %s — falling back to HTTP mode", exc)
        return None


def close_browser() -> None:
    """Gọi ở cuối scan để cleanup resources."""
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

def _inject_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ---------------------------------------------------------------------------
# Playwright verification — ground truth
# ---------------------------------------------------------------------------

def _get_trigger_js(strategy: str) -> str | None:
    """
    Trả về JS snippet cần chạy sau khi page load để trigger event.

    Một số event không tự fire mà cần được dispatch thủ công:

      onresize   : window không resize khi Playwright load headless.
                   Cần dispatchEvent(new Event('resize')) để trigger.
                   Lab 1 dùng cách này — payload <body onresize=print()>
                   được deliver qua iframe, nhưng ở đây ta dispatch trực tiếp.

      onfocus    : Custom tag có id=x cần được focus.
                   Tab fragment (#x) trigger focus khi navigate,
                   nhưng Playwright cần evaluate focus() trực tiếp.

      ontoggle   : <details open ontoggle=...> thường tự fire, nhưng
                   nếu không: toggle details element.

      onerror    : Tự fire khi src=x (invalid) — không cần trigger thêm.
      onload     : Tự fire — không cần trigger thêm.
      onpageshow : Tự fire khi page load — không cần trigger thêm.
      onmouseover: Cần user hover — không thể auto-trigger headless.
    """
    s = strategy.lower()

    if "onresize" in s:
        # Dispatch resize event lên window — trigger <body onresize=...>
        # và bất kỳ element nào có onresize handler
        return "window.dispatchEvent(new Event('resize'));"

    if "onfocus" in s:
        # Tìm element có id=x (pattern Test 2) và focus nó
        # Cũng thử focus tất cả element có tabindex
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

    # Các event khác (onerror, onload, onpageshow, onmouseover, onclick)
    # không cần trigger thêm hoặc không thể auto-trigger headless
    return None


def _verify_playwright(probe_url: str, payload: Payload) -> tuple[bool, str]:
    """
    Load probe_url trong Chromium. Trả về (triggered, evidence).

    Logic:
    1. Navigate đến probe_url (wait domcontentloaded)
    2. Chờ ngắn để page settle
    3. Dispatch event trigger nếu cần (onresize, onfocus, ontoggle)
    4. Chờ thêm DIALOG_WAIT_MS để catch deferred JS
    5. Nếu dialog fire → XSS confirmed

    Mỗi payload dùng BrowserContext riêng (isolated state).
    """
    browser = _get_browser()
    if browser is None:
        return False, ""

    ctx  = None
    page = None
    try:
        ctx = browser.new_context(
            ignore_https_errors = True,
            extra_http_headers  = {
                "User-Agent": "Mozilla/5.0 (compatible; XSSScanner/3.0)",
            },
        )
        page = ctx.new_page()

        dialogs: list[dict] = []

        def _on_dialog(dialog):
            dialogs.append({"type": dialog.type, "message": dialog.message})
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", _on_dialog)

        # Navigate
        try:
            page.goto(
                probe_url,
                timeout    = PAGE_TIMEOUT_MS,
                wait_until = "domcontentloaded",
            )
        except Exception as nav_err:
            log.debug("Navigation exception (may be OK): %s", nav_err)

        # Chờ DOM render xong trước khi trigger
        try:
            page.wait_for_timeout(500)
        except Exception:
            pass

        # Dispatch event trigger nếu cần
        trigger_js = _get_trigger_js(payload.strategy)
        if trigger_js and not dialogs:
            try:
                page.evaluate(trigger_js)
                log.debug("  Trigger JS dispatched for strategy=%s", payload.strategy)
            except Exception as e:
                log.debug("  Trigger JS error: %s", e)

        # Chờ thêm để catch deferred JS
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
# HTTP fallback verification — dùng khi Playwright không có
# ---------------------------------------------------------------------------

def _normalize_html(text: str) -> str:
    """Decode common HTML entities để so sánh chính xác hơn."""
    import html as _h
    text = _h.unescape(text)
    text = text.replace("%3C", "<").replace("%3c", "<")
    text = text.replace("%3E", ">").replace("%3e", ">")
    text = text.replace("%22", '"').replace("%27", "'")
    return text


_EXEC_PAIRS = [
    ("alert(1)",     "alert(1)"),
    ("confirm(1)",   "confirm(1)"),
    ("(alert)(1)",   "(alert)(1)"),
    ("alert`1`",     "alert`1`"),
    ("confirm?.(1)", "confirm?.(1)"),
    ("print()",      "print()"),
]

_STRUCTURAL: dict[str, list[str]] = {
    "html":      ["<script>", "onerror=", "onload=", "onfocus=", "ontoggle=",
                  "onmouseover=", "onpointerover=", "srcdoc=", "javascript:", "onbegin="],
    "attribute": ["onerror=", "onmouseover=", "onfocus=", "ontoggle=",
                  "onpointerover=", "javascript:", "<script>", "<img ", "<svg"],
    "js":        ["alert(1)", "confirm(1)", "(alert)(1)", "alert`1`",
                  "-alert(", "||alert(", "`;", "</script>"],
    "script":    [],
    "url":       [],
}
_STRUCTURAL["script"] = _STRUCTURAL["js"]
_STRUCTURAL["url"]    = _STRUCTURAL["attribute"]


def _verify_http_fallback(
    base_url: str,
    param:    str,
    payload:  Payload,
) -> tuple[bool, str]:
    """
    HTTP fallback khi Playwright không có.

    Inject payload trực tiếp (không dùng fence marker) vì fence bị vỡ
    khi payload chứa ký tự như ' mà server sẽ escape trong cả fence lẫn payload.

    Với JS context: tìm exec signal (alert, confirm, print) nằm trong
    <script> block trong response → đủ để confirm.
    """
    import re, html as _h

    probe_url = _inject_url(base_url, param, payload.value)
    try:
        resp = _HTTP_SESSION.get(probe_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        log.warning("HTTP fallback request failed: %s", exc)
        return False, ""

    if "html" not in resp.headers.get("Content-Type", ""):
        return False, ""

    raw  = resp.text
    norm = _normalize_html(raw)

    # ── JS / script context ───────────────────────────────────────────────
    # Tìm exec signal nằm trong <script> block
    if payload.context in ("js", "script"):
        script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", norm,
                                   re.DOTALL | re.IGNORECASE)
        for block in script_blocks:
            for src_frag, _ in _EXEC_PAIRS:
                if src_frag in payload.value and src_frag in block:
                    ev = (f"HTTP fallback: '{src_frag}' found in <script> block"
                          f" | strategy={payload.strategy}")
                    return True, ev
        return False, ""

    # ── HTML context ──────────────────────────────────────────────────────
    structural = _STRUCTURAL.get(payload.context, [])
    for src_frag, html_frag in _EXEC_PAIRS:
        if src_frag in payload.value and html_frag in norm:
            for sig in structural:
                if sig in norm:
                    ev = f"HTTP fallback: '{html_frag}' + '{sig}' in response"
                    return True, ev

    return False, ""


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

    Flow cho mỗi payload:
    1. Inject payload vào param → tạo probe_url
    2. Playwright load probe_url
    3. Nếu dialog (alert/confirm/prompt) fire → XSS confirmed, return Finding
    4. Nếu không fire → thử payload tiếp theo
    5. Sau khi hết payloads → return None

    Nếu Playwright không available: fallback HTTP với cảnh báo.

    Args:
        base_url:  Clean endpoint URL (không có injected values).
        param:     Tên parameter để inject.
        context:   "html" | "attribute" | "js" | "script"
        payloads:  Danh sách Payload từ generate_payloads(), ưu tiên cao nhất trước.
        attr_name: Tên attribute nếu context=attribute.
        delay:     Giây chờ giữa các requests (rate limiting).
    """
    # Kiểm tra Playwright availability sớm để log 1 lần
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
        else:
            confirmed, evidence = _verify_http_fallback(base_url, param, payload)

        if confirmed:
            # Lấy snippet từ HTTP response để hiển thị trong report
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
