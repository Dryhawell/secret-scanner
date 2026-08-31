"""Git history scanning tests. Requires git on PATH. No real secrets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cli.interface import run
from scanner.history import parse_history_patch

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(root: Path, *args: str) -> None:
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _commit(root: Path, message: str) -> None:
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )


def test_parse_history_patch_reads_added_lines_only() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    commit = "a" * 40
    patch = (
        f"===COMMIT {commit}===\n"
        "diff --git a/leak.py b/leak.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/leak.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+print('ok')\n"
        f"+AWS_ACCESS_KEY_ID = '{aws}'\n"
        "===COMMIT " + ("b" * 40) + "===\n"
        "diff --git a/leak.py b/leak.py\n"
        "deleted file mode 100644\n"
        "--- a/leak.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-print('ok')\n"
        f"-AWS_ACCESS_KEY_ID = '{aws}'\n"
    )
    rows = parse_history_patch(patch)
    assert len(rows) == 2
    assert rows[1].text.endswith(aws + "'")
    assert rows[1].line_number == 2
    assert rows[1].relative_path == "leak.py"


def test_history_finds_deleted_commit_leak(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    _git(tmp_path, "init")
    leaked = tmp_path / "leak.py"
    leaked.write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    _git(tmp_path, "add", "leak.py")
    _commit(tmp_path, "add leak")
    _git(tmp_path, "rm", "leak.py")
    _commit(tmp_path, "remove leak")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")

    tree = run(
        ["--no-color", str(tmp_path)],
        log_file=tmp_path / "tree.log",
        reports_dir=tmp_path / "reports",
    )
    assert tree == 0

    report = tmp_path / "hist.json"
    code = run(
        [
            "--no-color",
            "--history",
            "--format",
            "json",
            "--output",
            str(report),
            str(tmp_path),
        ],
        log_file=tmp_path / "hist.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 1
    body = report.read_text(encoding="utf-8")
    assert aws not in body
    payload = json.loads(body)
    findings = payload["findings"]
    assert findings
    commit = findings[0]["commit"]
    assert len(commit) == 40
    assert findings[0]["file_path"] == "leak.py"


def test_history_outside_repo_exits_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    code = run(
        ["--no-color", "--history", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2


def test_history_depth_zero_exits_two(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "ok.py")
    _commit(tmp_path, "ok")
    code = run(
        ["--no-color", "--history", "--history-depth", "0", str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 2
