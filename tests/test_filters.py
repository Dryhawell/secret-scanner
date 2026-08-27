"""Placeholder / false-positive filter tests. No real secrets are used."""

from pathlib import Path

from scanner.detector import Detector
from scanner.filters import is_placeholder
from scanner.patterns import PatternEngine


def test_exact_dummy_passwords_are_placeholders() -> None:
    assert is_placeholder("password")
    assert is_placeholder("changeme")
    assert is_placeholder("admin")
    assert is_placeholder("secret")


def test_your_api_key_here_is_placeholder() -> None:
    assert is_placeholder("YOUR_API_KEY_HERE")
    assert is_placeholder("your-secret-here")


def test_placeholder_and_example_fragments() -> None:
    assert is_placeholder("TEST_PASSWORD_PLACEHOLDER")
    assert is_placeholder("AKIA" + "IOSFODNN7EXAMPLE")
    assert is_placeholder("sk_test_" + "TESTPLACEHOLDER000000")


def test_redacted_stars_are_placeholders() -> None:
    assert is_placeholder("********")
    assert is_placeholder("xxxx-xxxx")


def test_does_not_treat_test_substring_as_placeholder() -> None:
    """Staging keys often contain 'test'. Skipping them would be a false negative."""
    assert not is_placeholder("AKIA" + "TESTKEYFAKE00000")
    assert not is_placeholder("TEST_API_KEY_123456789")


def test_pattern_engine_still_matches_placeholders() -> None:
    """The filter lives in the detector, not the regex engine."""
    matches = PatternEngine().find_in_text('api_key = "YOUR_API_KEY_HERE"')
    assert any(item.pattern_name == "Generic API Key" for item in matches)
    assert is_placeholder("YOUR_API_KEY_HERE")


def test_detector_ignores_placeholder_api_key(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text('api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8")
    file_scan = Detector().scan_file(target)
    assert file_scan.findings == ()
    assert file_scan.placeholders_ignored >= 1


def test_detector_ignores_password_equals_password(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text('password = "password"\n', encoding="utf-8")
    file_scan = Detector().scan_file(target)
    assert file_scan.findings == ()
    assert file_scan.placeholders_ignored >= 1


def test_detector_still_reports_non_placeholder_api_key(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    value = "TEST_API_KEY_" + "123456789"
    target.write_text(f'api_key = "{value}"\n', encoding="utf-8")
    file_scan = Detector().scan_file(target)
    assert any(item.pattern_name == "Generic API Key" for item in file_scan.findings)
    assert file_scan.placeholders_ignored == 0
