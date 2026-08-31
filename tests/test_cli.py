"""CLI tests. No real secrets are used."""

from pathlib import Path

import pytest

from cli.interface import (
    build_parser,
    build_scan_config,
    filter_findings,
    resolve_target,
    run,
)
from scanner.models import SecretFinding, Severity


def test_help_exits_zero() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["--help"])
    assert caught.value.code == 0


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["--version"])
    assert caught.value.code == 0
    assert "1.13.0" in capsys.readouterr().out


def test_staged_and_changed_are_exclusive() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--staged", "--changed"])


def test_history_and_staged_are_exclusive() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--history", "--staged"])


def test_since_and_staged_are_exclusive() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([".", "--since", "HEAD", "--staged"])


def test_resolve_target_prefers_path_option() -> None:
    namespace = build_parser().parse_args(["./src", "--path", "./other"])
    assert resolve_target(namespace) == Path("./other")


def test_exclude_is_added_to_scan_config() -> None:
    namespace = build_parser().parse_args([".", "--exclude", "dist", "--exclude", "build"])
    config = build_scan_config(namespace)
    assert "dist" in config.excluded_dirs
    assert "build" in config.excluded_dirs


def test_exclude_is_casefolded() -> None:
    namespace = build_parser().parse_args([".", "--exclude", "Dist"])
    config = build_scan_config(namespace)
    assert "dist" in config.excluded_dirs
    assert "Dist" not in config.excluded_dirs


def test_filter_findings_keeps_minimum_severity() -> None:
    critical = SecretFinding(
        file_path=Path("a.py"),
        line_number=1,
        secret_type="Private Key",
        severity=Severity.CRITICAL,
        masked_value="****",
        description="t",
        pattern_name="Private Key",
        confidence=90,
    )
    medium = SecretFinding(
        file_path=Path("b.py"),
        line_number=2,
        secret_type="Generic Password",
        severity=Severity.MEDIUM,
        masked_value="****",
        description="t",
        pattern_name="Generic Password",
        confidence=50,
    )
    kept = filter_findings((critical, medium), Severity.HIGH)
    assert kept == [critical]


def test_run_clean_directory_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    assert run(["--no-color", str(tmp_path)]) == 0


def test_run_with_finding_exits_one(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    assert run(["--no-color", str(tmp_path)]) == 1


def test_severity_filter_can_hide_medium_findings(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        'token = "LocalDevTokenValue1"\n',
        encoding="utf-8",
    )
    assert run(["--no-color", "--severity", "CRITICAL", str(tmp_path)]) == 0
    assert run(["--no-color", "--severity", "MEDIUM", str(tmp_path)]) == 1


def test_missing_target_exits_two(tmp_path: Path) -> None:
    assert run(["--no-color", str(tmp_path / "missing")]) == 2


def test_staged_missing_target_exits_two_without_calling_git(tmp_path: Path) -> None:
    assert run(["--no-color", "--staged", str(tmp_path / "missing")]) == 2


def test_cli_writes_json_to_output_file(tmp_path: Path) -> None:
    import json

    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report = tmp_path / "scan.json"
    code = run(["--no-color", "--output", str(report), str(tmp_path)])
    assert code == 0
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["files_scanned"] >= 1
    assert data["findings_count"] == 0


def test_output_write_failure_exits_two(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x\n", encoding="utf-8")
    assert run(["--no-color", "--output", str(blocker / "scan.json"), str(tmp_path)]) == 2

