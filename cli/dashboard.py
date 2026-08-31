"""Localhost-only HTML dashboard. No JavaScript, no plaintext secrets.

Binds ``127.0.0.1`` only. POST /scan requires the CSRF token from GET /.
This is not a remote scanner and it is not a file server.
"""

from __future__ import annotations

import argparse
import hmac
import secrets
import sys
import webbrowser
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from scanner.baseline import BaselineError
from scanner.config_file import ConfigError, FileSettings, load_config_file, resolve_config_path
from scanner.git_mode import GitError
from scanner.ignore import IgnoreError
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.patterns import merged_engine
from scanner.scanner import Scanner
from scanner.severity import sort_findings
from scanner.version import __version__
from utils.html_report import PAGE_CSS, render_findings_block
from utils.logger import get_logger

DASHBOARD_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY_BYTES = 8192

_LOG = get_logger()


class DashboardError(Exception):
    """Raised when the dashboard cannot bind or is misconfigured."""


def parse_scan_path(raw: str) -> Path:
    """Return a local existing path, or raise ValueError.

    URLs, UNC shares, and NUL bytes are rejected so the form cannot be
    turned into a remote fetch.
    """
    text = raw.strip()
    if not text or "\x00" in text:
        raise ValueError("Path is required.")
    if "://" in text or text.startswith(("\\\\", "//")):
        raise ValueError("Path must be a local directory or file, not a URL.")
    path = Path(text).expanduser()
    if not path.exists():
        raise ValueError(f"Target does not exist: {path}")
    return path


def render_dashboard(
    *,
    path_value: str,
    token: str,
    error: str = "",
    result: ScanResult | None = None,
    findings: list[SecretFinding] | None = None,
    target: Path | None = None,
) -> str:
    """Full dashboard document. Every user-controlled string is escaped."""
    error_html = f'<p class="error">{escape(error, quote=True)}</p>' if error else ""
    report = ""
    if result is not None and findings is not None and target is not None:
        report = (
            f'<p class="meta">Target: {escape(str(target), quote=True)} · '
            f"Scan time: {escape(result.scan_time.isoformat(), quote=True)}</p>"
            f"{render_findings_block(result, findings, target)}"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secret Scanner dashboard</title>
<style>
{PAGE_CSS}
</style>
</head>
<body>
<main>
<h1>Secret Scanner {escape(__version__, quote=True)}</h1>
<p class="meta">Local dashboard on 127.0.0.1. Values are masked. No source snippets.</p>
<form method="post" action="/scan">
  <input type="hidden" name="csrf" value="{escape(token, quote=True)}">
  <div>
    <label for="path">Path to scan</label>
    <input id="path" name="path" type="text" value="{escape(path_value, quote=True)}">
  </div>
  <button type="submit">Scan</button>
</form>
{error_html}
{report}
<p class="note">Working-tree scan only. Use the CLI for --staged, --changed, and
--history. Finding a real credential still requires revoke and rotate.</p>
</main>
</body>
</html>
"""


def host_is_local(header: str) -> bool:
    """True if the Host header names loopback (with or without a port)."""
    host = (header or "").strip().casefold()
    if not host:
        return False
    if host.startswith("[::1]"):
        return True
    name = host.rsplit(":", 1)[0] if host.rsplit(":", 1)[-1].isdigit() else host
    return name in {"127.0.0.1", "localhost", "::1"}


def make_handler(
    namespace: argparse.Namespace, *, token: str, default_path: Path
) -> type[BaseHTTPRequestHandler]:
    """Return a request handler closed over CLI flags and the CSRF token."""

    class DashboardHandler(BaseHTTPRequestHandler):
        csrf_token = token

        def version_string(self) -> str:
            return "SecretScanner"

        def log_message(self, fmt: str, *args: object) -> None:
            _LOG.info("dashboard " + fmt, *args)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/":
                self._send(
                    404,
                    render_dashboard(
                        path_value=str(default_path),
                        token=token,
                        error="Not found.",
                    ),
                )
                return
            if not host_is_local(self.headers.get("Host", "")):
                self._send(
                    403,
                    render_dashboard(
                        path_value=str(default_path),
                        token=token,
                        error="This dashboard only accepts localhost requests.",
                    ),
                )
                return
            self._send(
                200,
                render_dashboard(path_value=str(default_path), token=token),
            )

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/scan":
                self._send(
                    404,
                    render_dashboard(
                        path_value=str(default_path),
                        token=token,
                        error="Not found.",
                    ),
                )
                return
            if not host_is_local(self.headers.get("Host", "")):
                self._send(
                    403,
                    render_dashboard(
                        path_value=str(default_path),
                        token=token,
                        error="This dashboard only accepts localhost requests.",
                    ),
                )
                return
            length = self._content_length()
            if length > MAX_BODY_BYTES:
                self._send(
                    413,
                    render_dashboard(
                        path_value=str(default_path),
                        token=token,
                        error="Request is too large.",
                    ),
                )
                return
            body = self.rfile.read(length)
            fields = parse_qs(
                body.decode("utf-8", errors="replace"), keep_blank_values=True
            )
            posted_token = (fields.get("csrf") or [""])[0]
            path_raw = (fields.get("path") or [""])[0]
            try:
                token_ok = hmac.compare_digest(posted_token, token)
            except (TypeError, ValueError):
                token_ok = False
            if not token_ok:
                self._send(
                    403,
                    render_dashboard(
                        path_value=path_raw or str(default_path),
                        token=token,
                        error="Invalid or missing CSRF token. Reload the dashboard and try again.",
                    ),
                )
                return
            try:
                target = parse_scan_path(path_raw)
                result, findings = run_dashboard_scan(namespace, target)
            except ValueError as exc:
                self._send(
                    200,
                    render_dashboard(
                        path_value=path_raw,
                        token=token,
                        error=str(exc),
                    ),
                )
                return
            except (ConfigError, IgnoreError, BaselineError, GitError, OSError) as exc:
                _LOG.error("%s", exc)
                self._send(
                    200,
                    render_dashboard(
                        path_value=path_raw,
                        token=token,
                        error=str(exc),
                    ),
                )
                return
            self._send(
                200,
                render_dashboard(
                    path_value=str(target),
                    token=token,
                    result=result,
                    findings=findings,
                    target=target,
                ),
            )

        def _content_length(self) -> int:
            raw = self.headers.get("Content-Length", "0")
            try:
                return max(0, int(raw))
            except ValueError:
                return 0

        def _send(self, status: int, html: str) -> None:
            payload = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

    return DashboardHandler


def run_dashboard_scan(
    namespace: argparse.Namespace, target: Path
) -> tuple[ScanResult, list[SecretFinding]]:
    """Working-tree scan for one dashboard POST. Findings stay masked."""
    from cli.interface import apply_baseline, apply_ignore_file, build_scan_config, filter_findings

    config_path = resolve_config_path(namespace.config, target)
    settings = (
        load_config_file(config_path) if config_path is not None else FileSettings()
    )
    minimum = Severity(namespace.severity or settings.severity or Severity.LOW.value)
    scanner = Scanner(
        config=build_scan_config(namespace, settings),
        engine=merged_engine(settings.patterns),
    )
    apply_ignore_file(scanner.config, namespace, target, settings)
    apply_baseline(scanner.config, namespace, target, settings)
    result = scanner.scan(target)
    findings = sort_findings(
        filter_findings(result.findings, minimum),
        location_of=lambda item: item.location(root=target),
    )
    return result, findings


def create_dashboard_server(
    namespace: argparse.Namespace,
    default_path: Path,
    port: int,
) -> tuple[HTTPServer, str]:
    """Bind 127.0.0.1 and return (server, csrf_token). Does not serve forever."""
    if port < 0 or port > 65535:
        raise DashboardError("port must be between 1 and 65535")
    token = secrets.token_urlsafe(24)
    handler = make_handler(namespace, token=token, default_path=default_path)
    try:
        httpd = HTTPServer((DASHBOARD_HOST, port), handler)
    except OSError as exc:
        raise DashboardError(f"Unable to bind {DASHBOARD_HOST}:{port}: {exc}") from exc
    return httpd, token


def serve_dashboard(
    namespace: argparse.Namespace,
    *,
    default_path: Path,
    open_browser: bool,
) -> int:
    """Listen until KeyboardInterrupt. Returns 0 on shutdown, 2 on bind error."""
    port = namespace.port
    try:
        httpd, _token = create_dashboard_server(namespace, default_path, port)
    except DashboardError as exc:
        _LOG.error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    bound = httpd.server_address[1]
    url = f"http://{DASHBOARD_HOST}:{bound}/"
    print(f"Dashboard: {url}")
    print("Listening on 127.0.0.1 only. Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        httpd.server_close()
    return 0
