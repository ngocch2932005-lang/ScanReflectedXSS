"""
reporter.py — Write scan reports from confirmed Finding objects.

Public API
----------
write_report(findings, output_dir, target_url, stem) -> {"json": Path, "html": Path}
"""

from __future__ import annotations

import json
import html as _esc
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from verify.verifier import Finding


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def _severity(f: Finding) -> str:
    s = f.payload.strategy
    if any(x in s for x in ("script_tag", "direct_js", "img_onerror",
                              "svg_onload", "srcdoc", "script_img",
                              "script_svg", "raw_js")):
        return "high"
    if any(x in s for x in ("js_uri", "backtick", "template",
                              "quoted_breakout", "bs_double")):
        return "medium"
    return "medium"


_SEV_COLOR = {"high": "#c0392b", "medium": "#e67e22", "low": "#27ae60"}


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _to_dict(f: Finding) -> dict:
    return {
        "url":       f.url,
        "param":     f.param,
        "context":   f.context,
        "attr_name": f.attr_name,
        "severity":  _severity(f),
        "payload": {
            "value":    f.payload.value,
            "strategy": f.payload.strategy,
            "note":     f.payload.note,
        },
        "probe_url": f.probe_url,
        "evidence":  f.evidence,
    }


def write_json(findings: list[Finding], path: Union[str, Path]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "total":     len(findings),
        "findings":  [_to_dict(f) for f in findings],
    }
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#f4f6f8;color:#1a1a2e;font-size:14px;line-height:1.6}
header{background:#1a1a2e;color:#fff;padding:24px 40px}
header h1{font-size:22px;font-weight:600}
header p{font-size:13px;color:#a0aec0;margin-top:4px}
.summary{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}
.stat{background:#fff;border-radius:8px;padding:16px 24px;
      min-width:130px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.stat .n{font-size:28px;font-weight:700}
.stat .l{font-size:12px;color:#718096;margin-top:2px}
.findings{padding:0 40px 40px;display:flex;flex-direction:column;gap:16px}
.card{background:#fff;border-radius:8px;overflow:hidden;
      box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card-head{display:flex;align-items:center;gap:10px;padding:12px 20px;
           border-bottom:1px solid #edf2f7}
.badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:4px;
       color:#fff;text-transform:uppercase}
.ctx{font-size:11px;background:#edf2f7;color:#4a5568;
     padding:3px 9px;border-radius:4px}
.card-head .u{font-weight:600;font-size:13px;word-break:break-all}
.card-body{padding:16px 20px;display:grid;
           grid-template-columns:130px 1fr;row-gap:10px}
.lb{font-size:12px;color:#718096;padding-top:2px}
.vl{font-size:13px;word-break:break-all}
.mono{font-family:'SFMono-Regular',Consolas,monospace;font-size:12px;
      background:#f7fafc;border:1px solid #e2e8f0;
      padding:8px 12px;border-radius:4px;white-space:pre-wrap;word-break:break-all}
.note{font-size:12px;color:#718096;font-style:italic;margin-top:4px}
.empty{padding:60px 40px;text-align:center;color:#718096;font-size:15px}
"""


def _card(f: Finding, idx: int) -> str:
    sev   = _severity(f)
    color = _SEV_COLOR.get(sev, "#888")
    e     = _esc.escape

    note_html = (
        f'<div class="note">{e(f.payload.note)}</div>'
        if f.payload.note else ""
    )
    attr_row = (
        f'<div class="lb">Attribute</div><div class="vl">{e(f.attr_name)}</div>'
        if f.attr_name else ""
    )

    return f"""
<div class="card">
  <div class="card-head">
    <span class="badge" style="background:{color}">{sev}</span>
    <span class="ctx">{e(f.context)}</span>
    <span class="u">#{idx} &nbsp;{e(f.url)}</span>
  </div>
  <div class="card-body">
    <div class="lb">Parameter</div>
    <div class="vl"><code>{e(f.param)}</code></div>
    {attr_row}
    <div class="lb">Strategy</div>
    <div class="vl">{e(f.payload.strategy)}</div>
    <div class="lb">Payload</div>
    <div class="vl">
      <div class="mono">{e(f.payload.value)}</div>
      {note_html}
    </div>
    <div class="lb">Evidence</div>
    <div class="vl">{e(f.evidence)}</div>
    <div class="lb">Probe URL</div>
    <div class="vl">
      <a href="{e(f.probe_url)}" target="_blank"
         style="color:#3182ce;word-break:break-all">{e(f.probe_url)}</a>
    </div>
  </div>
</div>"""


def write_html(
    findings:   list[Finding],
    path:       Union[str, Path],
    target_url: str = "",
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)
    high  = sum(1 for f in findings if _severity(f) == "high")
    med   = sum(1 for f in findings if _severity(f) == "medium")
    low   = sum(1 for f in findings if _severity(f) == "low")

    cards = "\n".join(_card(f, i + 1) for i, f in enumerate(findings))
    body  = cards or '<div class="empty">No confirmed XSS findings.</div>'
    tline = (
        f'<p>Target: {_esc.escape(target_url)}</p>' if target_url else ""
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Scan Report</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>XSS Scan Report</h1>
  {tline}
  <p>Generated {now}</p>
</header>
<div class="summary">
  <div class="stat"><div class="n">{total}</div><div class="l">Total</div></div>
  <div class="stat"><div class="n" style="color:#c0392b">{high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n" style="color:#e67e22">{med}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n" style="color:#27ae60">{low}</div><div class="l">Low</div></div>
</div>
<div class="findings">{body}</div>
</body>
</html>"""

    path.write_text(doc, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_report(
    findings:   list[Finding],
    output_dir: Union[str, Path] = "reports",
    target_url: str = "",
    stem:       str = "xss_report",
) -> dict[str, Path]:
    """
    Write JSON + HTML reports.

    Returns:
        {"json": Path, "html": Path}
    """
    d = Path(output_dir)
    return {
        "json": write_json(findings, d / f"{stem}.json"),
        "html": write_html(findings, d / f"{stem}.html", target_url=target_url),
    }
