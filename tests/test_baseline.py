"""Hashed baseline tests. No real secrets are stored or compared as plaintext."""

"""Hashed baseline tests. No real secrets are stored or compared as plaintext."""

from pathlib import Path

from cli.interface import run
from scanner.baseline import DEFAULT_BASELINE_NAME, load_baseline, write_baseline
from scanner.file_handler import ScanConfig
from scanner.fingerprint import secret_id
from scanner.ignore import ignore_root
from scanner.scanner import Scanner


def test_secret_id_is_stable_and_not_the_secret() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    first = secret_id("AWS Access Key ID", aws)
    second = secret_id("AWS Access Key ID", aws)
    assert first == second
    assert len(first) == 64
    assert aws not in first
    assert secret_id("AWS Access Key ID", aws + "X") != first


def test_baseline_suppresses_known_finding_not_a_new_one(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    other = "AKIA" + "ZZZZZZZZZZZZZZZZ"
    config_py = tmp_path / "config.py"
    config_py.write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    first = Scanner().scan(tmp_path)
    assert first.findings_count >= 1
    write_baseline(tmp_path / DEFAULT_BASELINE_NAME, first.findings, ignore_root(tmp_path))

    keys = load_baseline(tmp_path / DEFAULT_BASELINE_NAME)
    held = Scanner(config=ScanConfig(baseline_keys=keys)).scan(tmp_path)
    assert held.findings_count == 0
    assert held.baseline_ignored >= 1

    config_py.write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\nOTHER = '{other}'\n",
        encoding="utf-8",
    )
    again = Scanner(config=ScanConfig(baseline_keys=keys)).scan(tmp_path)
    assert again.findings_count >= 1
    assert all(aws not in item.fingerprint for item in again.findings)


def test_same_secret_in_new_file_is_not_baselined(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "old.py").write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    first = Scanner().scan(tmp_path)
    write_baseline(tmp_path / DEFAULT_BASELINE_NAME, first.findings, ignore_root(tmp_path))
    keys = load_baseline(tmp_path / DEFAULT_BASELINE_NAME)
    (tmp_path / "new.py").write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    result = Scanner(config=ScanConfig(baseline_keys=keys)).scan(tmp_path)
    paths = {item.file_path.name for item in result.findings}
    assert "new.py" in paths


def test_write_baseline_contains_no_plaintext(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    result = Scanner().scan(tmp_path)
    path = write_baseline(
        tmp_path / DEFAULT_BASELINE_NAME, result.findings, ignore_root(tmp_path)
    )
    text = path.read_text(encoding="utf-8")
    assert aws not in text
    assert "fingerprint" in text
    assert "ABCDEFGHIJ012345" not in text


def test_cli_update_baseline_exits_zero(tmp_path: Path) -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    (tmp_path / "config.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{aws}'\n",
        encoding="utf-8",
    )
    baseline = tmp_path / DEFAULT_BASELINE_NAME
    code = run(
        ["--no-color", "--update-baseline", "--baseline", str(baseline), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0
    assert baseline.is_file()
    assert aws not in baseline.read_text(encoding="utf-8")

    code = run(
        ["--no-color", "--baseline", str(baseline), str(tmp_path)],
        log_file=tmp_path / "cli.log",
        reports_dir=tmp_path / "reports",
    )
    assert code == 0


def test_missing_explicit_baseline_exits_two(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    assert (
        run(
            [
                "--no-color",
                "--baseline",
                str(tmp_path / "missing.json"),
                str(tmp_path),
            ],
            log_file=tmp_path / "cli.log",
            reports_dir=tmp_path / "reports",
        )
        == 2
    )
