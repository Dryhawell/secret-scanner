"""Context-analysis tests. Values are fake placeholders, never real secrets."""

from pathlib import Path

from scanner.context import find_context_hits, is_sensitive_identifier
from scanner.detector import Detector


def test_token_and_secret_names_are_sensitive() -> None:
    assert is_sensitive_identifier("token")
    assert is_sensitive_identifier("access_token")
    assert is_sensitive_identifier("SECRET_KEY")
    assert is_sensitive_identifier("client_secret")
    assert is_sensitive_identifier("api-key")


def test_ordinary_names_are_not_sensitive() -> None:
    assert not is_sensitive_identifier("color")
    assert not is_sensitive_identifier("timeout")
    assert not is_sensitive_identifier("public_key")
    assert not is_sensitive_identifier("client_id")


def test_quoted_token_assignment_is_a_hit() -> None:
    hits = find_context_hits('token = "LocalDevTokenValue1"')
    assert len(hits) == 1
    assert hits[0].identifier == "token"
    assert hits[0].value == "LocalDevTokenValue1"


def test_env_unquoted_secret_key() -> None:
    hits = find_context_hits("SECRET_KEY=local_dev_value_ok")
    assert len(hits) == 1
    assert hits[0].identifier == "SECRET_KEY"


def test_non_sensitive_assignment_is_ignored() -> None:
    assert find_context_hits('color = "blueish_green_ok"') == []


def test_detector_reports_contextual_secret(tmp_path: Path) -> None:
    target = tmp_path / "auth.py"
    target.write_text('token = "LocalDevTokenValue1"\n', encoding="utf-8")
    findings = Detector().scan_file(target).findings
    assert len(findings) == 1
    assert findings[0].pattern_name == "Contextual Secret"
    assert findings[0].severity.value == "MEDIUM"
    assert "LocalDevTokenValue1" not in findings[0].masked_value


def test_detector_does_not_duplicate_generic_api_key(tmp_path: Path) -> None:
    target = tmp_path / "settings.py"
    value = "TEST_API_KEY_" + "123456789"
    target.write_text(f'api_key = "{value}"\n', encoding="utf-8")
    findings = Detector().scan_file(target).findings
    names = [item.pattern_name for item in findings]
    assert names.count("Generic API Key") == 1
    assert "Contextual Secret" not in names


def test_placeholder_token_is_still_ignored(tmp_path: Path) -> None:
    target = tmp_path / "auth.py"
    target.write_text('token = "YOUR_API_KEY_HERE"\n', encoding="utf-8")
    file_scan = Detector().scan_file(target)
    assert file_scan.findings == ()
    assert file_scan.placeholders_ignored >= 1


def test_json_quoted_key(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_text(
        '{ "access_token": "LocalDevTokenValue1" }\n',
        encoding="utf-8",
    )
    findings = Detector().scan_file(target).findings
    assert any(item.pattern_name == "Contextual Secret" for item in findings)
