"""Standalone HTML report renderer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sentinel.core import ScanResult, Severity

_SEVERITY_CSS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>sentinel scan report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
    header {{ background: #1e293b; padding: 24px 40px; border-bottom: 1px solid #334155; }}
    header h1 {{ font-size: 1.5rem; font-weight: 700; color: #f8fafc; }}
    header p {{ color: #94a3b8; font-size: 0.875rem; margin-top: 4px; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 40px; }}
    .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px; }}
    .badge {{ padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }}
    .module-section {{ margin-bottom: 40px; }}
    .module-title {{ font-size: 1.125rem; font-weight: 600; color: #f1f5f9;
                     margin-bottom: 16px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
    .no-findings {{ color: #4ade80; font-size: 0.875rem; padding: 12px 0; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    th {{ text-align: left; padding: 10px 12px; background: #1e293b; color: #94a3b8;
          font-weight: 600; text-transform: uppercase; font-size: 0.75rem;
          letter-spacing: 0.05em; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
    tr:hover td {{ background: #1e293b; }}
    .sev {{ font-weight: 700; font-size: 0.75rem; padding: 2px 8px; border-radius: 4px;
            color: #fff; display: inline-block; }}
    .detail {{ color: #94a3b8; font-size: 0.8rem; }}
    .remediation {{ color: #64748b; font-size: 0.8rem; margin-top: 4px; }}
    footer {{ background: #1e293b; border-top: 1px solid #334155; padding: 20px 40px;
              text-align: center; color: #64748b; font-size: 0.8rem; }}
    footer a {{ color: #38bdf8; text-decoration: none; }}
  </style>
</head>
<body>
<header>
  <h1>sentinel &mdash; MCP Security Scan Report</h1>
  <p>Generated {timestamp} &bull; {total_findings} finding(s) across {module_count} module(s)</p>
</header>
<div class="container">
  <div class="summary">
    {summary_badges}
  </div>
  {module_sections}
</div>
<footer>
  <p>sentinel by <a href="https://helixar.ai" target="_blank">Helixar</a>
  &bull; Runtime protection: <a href="https://helixar.ai" target="_blank">helixar.ai</a></p>
</footer>
</body>
</html>
"""


def render(results: List[ScanResult]) -> str:
    """Return a complete HTML report as a string."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_findings = sum(len(r.findings) for r in results)

    counts: dict = {s: 0 for s in Severity}
    for result in results:
        for f in result.findings:
            counts[f.severity] += 1

    # Summary badges
    badges = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev] > 0:
            color = _SEVERITY_CSS[sev]
            badges.append(
                f'<span class="badge" style="background:{color}">{sev.value}: {counts[sev]}</span>'
            )
    if not badges:
        badges.append('<span class="badge" style="background:#16a34a">Clean</span>')

    # Module sections
    sections = []
    for result in results:
        rows = ""
        if not result.findings:
            rows = '<p class="no-findings">&#10003; No findings</p>'
        else:
            table_rows = ""
            for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
                color = _SEVERITY_CSS.get(f.severity, "#6b7280")
                ref_link = (
                    f'<a href="{f.reference}" style="color:#38bdf8" target="_blank">{f.rule_id}</a>'
                    if f.reference
                    else f.rule_id
                )
                remediation_html = (
                    f'<div class="remediation">Fix: {_html_escape(f.remediation[:200])}</div>'
                    if f.remediation
                    else ""
                )
                table_rows += f"""
<tr>
  <td><span class="sev" style="background:{color}">{f.severity.value}</span></td>
  <td>{ref_link}</td>
  <td>
    {_html_escape(f.title)}<br>
    <span class="detail">{_html_escape(f.detail)}</span>
    {remediation_html}
  </td>
  <td class="detail">{_html_escape(f.location[:80])}</td>
</tr>"""
            rows = f"""
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th>
    </tr>
  </thead>
  <tbody>{table_rows}</tbody>
</table>"""

        sections.append(f"""
<div class="module-section">
  <div class="module-title">{_html_escape(result.module)} &rarr; {_html_escape(result.target)}</div>
  {rows}
</div>""")

    return _HTML_TEMPLATE.format(
        timestamp=timestamp,
        total_findings=total_findings,
        module_count=len(results),
        summary_badges="\n    ".join(badges),
        module_sections="\n".join(sections),
    )


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
