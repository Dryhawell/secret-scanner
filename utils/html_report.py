"""Self-contained HTML scan reports.

All dynamic strings are HTML-escaped. The page never includes plaintext
secrets or original source lines (those would leak in a browser, email,
or screenshot).
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from scanner.models import ScanResult, SecretFinding, Severity
from scanner.severity import count_by_severity
from scanner.version import __version__
from utils.reporter import DEFAULT_REPORTS_DIR, default_report_path

_SEVERITY_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}


def _e(value: object) -> str:
    return escape(str(value), quote=True)


PAGE_CSS = """:root { color-scheme: dark; }
body { font: 15px/1.45 system-ui, sans-serif; margin: 0; background: #0f1419;
  color: #e7ecf1; }
main { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
h1 { font-size: 1.4rem; margin: 0 0 0.25rem; }
.meta { color: #8b9bb0; margin-bottom: 1.5rem; }
.cards { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 0 0 1.5rem; }
.card { background: #1a2330; border-radius: 8px; padding: 0.7rem 0.9rem; min-width: 7rem; }
.card strong { display: block; font-size: 1.15rem; }
.card span { color: #8b9bb0; font-size: 0.8rem; }
table { width: 100%; border-collapse: collapse; background: #1a2330;
  border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 0.65rem 0.75rem; vertical-align: top; }
th { color: #8b9bb0; font-weight: 600; font-size: 0.8rem; }
tr + tr td { border-top: 1px solid #243044; }
code { font-family: ui-monospace, monospace; font-size: 0.9em; }
.pill { display: inline-block; padding: 0.12rem 0.45rem; border-radius: 999px;
  font-size: 0.75rem; font-weight: 700; letter-spacing: 0.03em; }
.critical { background: #5c1520; color: #ff8b96; }
.high { background: #5a3b12; color: #ffc56e; }
.medium { background: #143a45; color: #7ee0f2; }
.low { background: #2a3340; color: #c5d0dc; }
.empty { color: #8b9bb0; }
.note { margin-top: 1.25rem; color: #8b9bb0; font-size: 0.85rem; }
form { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: end;
  margin: 0 0 1.5rem; }
label { display: block; color: #8b9bb0; font-size: 0.8rem; margin-bottom: 0.25rem; }
input[type=text] { background: #1a2330; color: #e7ecf1; border: 1px solid #243044;
  border-radius: 8px; padding: 0.55rem 0.7rem; min-width: 22rem; }
button { background: #2a6f97; color: #fff; border: 0; border-radius: 8px;
  padding: 0.55rem 0.9rem; font-weight: 600; cursor: pointer; }
.error { color: #ff8b96; margin: 0 0 1rem; }
"""


def render_findings_block(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> str:
    """Cards plus findings table. Never includes plaintext secrets."""
    counts = count_by_severity(findings)
    rows = [_finding_row(item, target) for item in findings]
    body = (
        "\n".join(rows)
        if rows
        else '<tr><td colspan="5" class="empty">No potential secrets found.</td></tr>'
    )
    return f"""<div class="cards">
  <div class="card"><strong>{result.files_scanned}</strong><span>Files</span></div>
  <div class="card"><strong>{result.lines_scanned}</strong><span>Lines</span></div>
  <div class="card"><strong>{len(findings)}</strong><span>Findings</span></div>
  <div class="card"><strong>{result.placeholders_ignored}</strong><span>Placeholders</span></div>
  <div class="card"><strong>{result.allowlist_ignored}</strong><span>Allowlist</span></div>
  <div class="card"><strong>{result.baseline_ignored}</strong><span>Baseline</span></div>
  <div class="card"><strong>{counts[Severity.CRITICAL]}</strong><span>Critical</span></div>
  <div class="card"><strong>{counts[Severity.HIGH]}</strong><span>High</span></div>
</div>
<table>
<thead>
<tr><th>Severity</th><th>Location</th><th>Type</th><th>Confidence</th><th>Masked value</th></tr>
</thead>
<tbody>
{body}
</tbody>
</table>"""


def render_html(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
) -> str:
    """Return a full HTML document. Never includes plaintext secrets."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secret Scanner report</title>
<style>
{PAGE_CSS}
</style>
</head>
<body>
<main>
<h1>Secret Scanner {_e(__version__)}</h1>
<p class="meta">Target: {_e(target)} · Scan time: {_e(result.scan_time.isoformat())}</p>
{render_findings_block(result, findings, target)}
<p class="note">Values are masked. This report does not include source snippets
or plaintext secrets. Finding a real credential still requires revoke and rotate.</p>
</main>
</body>
</html>
"""


def _finding_row(finding: SecretFinding, target: Path) -> str:
    css = _SEVERITY_CLASS[finding.severity]
    location = finding.location(root=target)
    return (
        "<tr>"
        f'<td><span class="pill {css}">{_e(finding.severity.value)}</span></td>'
        f"<td><code>{_e(location)}</code></td>"
        f"<td>{_e(finding.pattern_name)}</td>"
        f"<td>{finding.confidence}%</td>"
        f"<td><code>{_e(finding.masked_value)}</code></td>"
        "</tr>"
    )


def write_html_report(
    result: ScanResult,
    findings: list[SecretFinding],
    target: Path,
    output: Path | None = None,
    reports_dir: Path | None = None,
) -> Path:
    """Write an HTML report and return the path that was written."""
    directory = reports_dir or DEFAULT_REPORTS_DIR
    path = (
        Path(output)
        if output is not None
        else default_report_path(result.scan_time, directory=directory, suffix=".html")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, findings, target), encoding="utf-8")
    return path
