"""Detector tests. All credentials below are constructed fakes, never real secrets."""

from pathlib import Path

from scanner.detector import Detector, mask_secret
from scanner.scanner import Scanner

# Split literals so the source file does not contain a contiguous fake key token.
FAKE_AWS_KEY = "AKIA" + "TESTKEYFAKE00000"
FAKE_API_KEY_VALUE = "TEST_API_KEY_" + "123456789"


def test_mask_secret_hides_payload() -> None:
    value = FAKE_AWS_KEY
    masked = mask_secret(value)
    assert masked.startswith("AKIA")
    assert "*" in masked
    assert value not in masked
    assert len(masked) == len(value)


def test_mask_secret_fully_redacts_short_values() -> None:
    assert mask_secret("abcd") == "****"
    assert mask_secret("12345678") == "********"


def test_detects_fake_aws_key_on_expected_line(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text(
        "DEBUG = True\n"
        "NAME = 'demo'\n"
        f"AWS_ACCESS_KEY_ID = '{FAKE_AWS_KEY}'\n",
        encoding="utf-8",
    )

    findings = Detector().scan_file(target)
    aws = [item for item in findings if item.pattern_name == "AWS Access Key ID"]

    assert len(aws) == 1
    assert aws[0].line_number == 3
    assert aws[0].severity.value == "CRITICAL"
    assert FAKE_AWS_KEY not in aws[0].masked_value
    assert aws[0].masked_value.startswith("AKIA")


def test_file_without_secrets_returns_empty(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    assert Detector().scan_file(target) == []


def test_generic_api_key_is_masked(tmp_path: Path) -> None:
    target = tmp_path / "settings.py"
    target.write_text(
        f'api_key = "{FAKE_API_KEY_VALUE}"\n',
        encoding="utf-8",
    )
    findings = Detector().scan_file(target)
    api = [item for item in findings if item.pattern_name == "Generic API Key"]
    assert len(api) == 1
    assert FAKE_API_KEY_VALUE not in api[0].masked_value


def test_scanner_scan_discovers_and_detects(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    leaked = tmp_path / "secrets.py"
    leaked.write_text(
        f"AWS_ACCESS_KEY_ID = '{FAKE_AWS_KEY}'\n",
        encoding="utf-8",
    )
    (tmp_path / "photo.png").write_bytes(b"\x89PNG\r\n")

    summary = Scanner().scan(tmp_path)

    assert summary.files_scanned == 2
    assert summary.findings_count >= 1
    assert all(FAKE_AWS_KEY not in item.masked_value for item in summary.findings)


def test_skips_extremely_long_line(tmp_path: Path) -> None:
    target = tmp_path / "bundle.js"
    payload = "AKIA" + "TESTKEYFAKE00000"
    target.write_text("x" * 100_001 + payload + "\n", encoding="utf-8")
    assert Detector().scan_file(target) == []
