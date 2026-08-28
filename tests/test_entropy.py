"""Shannon entropy tests. No real secrets are used."""

from scanner.entropy import (
    entropy_adjustment,
    is_low_entropy,
    shannon_entropy,
)


def test_repeated_characters_have_near_zero_entropy() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert is_low_entropy("aaaaaaaaaaaaaaaa")


def test_mixed_token_has_higher_entropy_than_repeated() -> None:
    mixed = "9f82aKx72LmQp91Z"
    assert shannon_entropy(mixed) > shannon_entropy("aaaaaaaaaaaaaaaa")
    assert shannon_entropy(mixed) > 3.0


def test_empty_string_has_zero_entropy() -> None:
    assert shannon_entropy("") == 0.0


def test_pem_header_is_not_penalized_for_low_entropy() -> None:
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert entropy_adjustment("Private Key", header) == 0


def test_generic_low_entropy_is_penalized() -> None:
    assert entropy_adjustment("Contextual Secret", "A" * 24) < 0


def test_high_entropy_without_sensitive_name_is_not_a_finding(tmp_path) -> None:
    """Entropy alone must not invent findings."""
    from scanner.detector import Detector

    target = tmp_path / "app.py"
    target.write_text(
        'nonce = "9f82aKx72LmQp91Zabcd"\n',
        encoding="utf-8",
    )
    assert Detector().scan_file(target).findings == ()


def test_low_entropy_token_assignment_is_dropped(tmp_path) -> None:
    from scanner.detector import Detector

    target = tmp_path / "auth.py"
    target.write_text('token = "aaaaaaaaaaaaaaaa"\n', encoding="utf-8")
    file_scan = Detector().scan_file(target)
    assert file_scan.findings == ()
    assert file_scan.placeholders_ignored >= 1
