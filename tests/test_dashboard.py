"""Localhost dashboard tests. No real secrets. Does not open a browser."""

from __future__ import annotations

import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from cli.dashboard import (
    DASHBOARD_HOST,
    create_dashboard_server,
    host_is_local,
    parse_scan_path,
    render_dashboard,
    run_dashboard_scan,
)
from cli.interface import build_parser, run


def test_host_is_local() -> None:
    assert host_is_local("127.0.0.1")
    assert host_is_local("127.0.0.1:8765")
    assert host_is_local("localhost:8765")
    assert not host_is_local("example.com")
    assert not host_is_local("")


def test_parse_scan_path_rejects_urls(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="local"):
        parse_scan_path("https://example.com/repo")
    with pytest.raises(ValueError, match="required"):
        parse_scan_path("  ")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    assert parse_scan_path(str(tmp_path)) == Path(str(tmp_path))


def test_render_dashboard_escapes_markup() -> None:
    page = render_dashboard(
        path_value='"><script>alert(1)</script>',
        token="abc",
        error="<b>nope</script>",
    )
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "<b>nope" not in page


def test_dashboard_scan_masks_secret(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    namespace = build_parser().parse_args(["--no-color", str(tmp_path)])
    result, findings = run_dashboard_scan(namespace, tmp_path)
    assert findings
    page = render_dashboard(
        path_value=str(tmp_path),
        token="t",
        result=result,
        findings=findings,
        target=tmp_path,
    )
    assert aws not in page
    assert "AKIA" in findings[0].masked_value


def _start(namespace, default_path: Path):
    httpd, token = create_dashboard_server(namespace, default_path, port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, token, thread


def test_live_dashboard_get_and_scan(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "leak.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    namespace = build_parser().parse_args(["--no-color", "--no-browser", str(tmp_path)])
    httpd, token, thread = _start(namespace, tmp_path)
    try:
        assert httpd.server_address[0] == DASHBOARD_HOST
        port = httpd.server_address[1]
        base = f"http://127.0.0.1:{port}"
        with urlopen(base + "/", timeout=5) as response:
            home = response.read().decode("utf-8")
        assert "csrf" in home
        data = urlencode({"csrf": token, "path": str(tmp_path)}).encode("utf-8")
        request = Request(base + "/scan", data=data, method="POST")
        with urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
        assert aws not in body
        assert "Findings" in body
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_live_dashboard_rejects_bad_csrf(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    namespace = build_parser().parse_args(["--no-color", str(tmp_path)])
    httpd, _token, thread = _start(namespace, tmp_path)
    try:
        port = httpd.server_address[1]
        data = urlencode({"csrf": "wrong", "path": str(tmp_path)}).encode("utf-8")
        request = Request(f"http://127.0.0.1:{port}/scan", data=data, method="POST")
        with pytest.raises(HTTPError) as caught:
            urlopen(request, timeout=5)
        assert caught.value.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def test_cli_dashboard_rejects_git_flags(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    assert run(["--dashboard", "--staged", "--no-browser", str(tmp_path)]) == 2


def test_cli_dashboard_invokes_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    seen: dict[str, object] = {}

    def fake_serve(namespace, *, default_path, open_browser):
        seen["open"] = open_browser
        seen["path"] = default_path
        return 0

    monkeypatch.setattr("cli.interface.serve_dashboard", fake_serve)
    code = run(["--dashboard", "--no-browser", str(tmp_path)])
    assert code == 0
    assert seen["open"] is False
    assert seen["path"] == tmp_path


def test_cli_port_zero_rejected() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--dashboard", "--port", "0"])
