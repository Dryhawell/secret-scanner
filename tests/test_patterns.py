"""Pattern engine tests. All values are fake placeholders, never real secrets."""

from scanner.models import Severity
from scanner.patterns import PatternEngine, default_patterns

# Intentional fakes. Lengths match the public formats; contents are dummy text.
FAKE_AWS_KEY = "AKIATESTKEYFAKE00000"
FAKE_GITHUB_TOKEN = "ghp_TESTPLACEHOLDER" + ("0" * 20) + "1"
FAKE_GOOGLE_KEY = "AIzaTESTGOOGLEAPIKEYPLACEHOLDER00000000"
FAKE_STRIPE_KEY = "sk_test_TESTPLACEHOLDER000000"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJURVNUX1VTRVIifQ."
    "TESTSIGNATUREPLACEHOLDER"
)
FAKE_API_KEY_VALUE = "TEST_API_KEY_123456789"
FAKE_PASSWORD_VALUE = "TEST_PASSWORD_PLACEHOLDER"
FAKE_DATABASE_URL = "postgres://testuser:TEST_PASSWORD_123@localhost:5432/appdb"


def _match_names(text: str) -> set[str]:
    return {item.pattern_name for item in PatternEngine().find_in_text(text)}


def test_fake_github_token_has_expected_length() -> None:
    """Guard the placeholder itself: ghp_ + 36 chars."""
    assert FAKE_GITHUB_TOKEN.startswith("ghp_")
    assert len(FAKE_GITHUB_TOKEN) == 4 + 36


def test_aws_access_key_matches_fake_format() -> None:
    assert "AWS Access Key ID" in _match_names(f"aws_access_key_id = {FAKE_AWS_KEY}")


def test_aws_access_key_rejects_short_or_lowercase() -> None:
    assert "AWS Access Key ID" not in _match_names("AKIA123")
    assert "AWS Access Key ID" not in _match_names("akiaTESTKEYFAKE00000")


def test_github_token_matches_fake_format() -> None:
    assert "GitHub Token" in _match_names(FAKE_GITHUB_TOKEN)


def test_github_token_rejects_short_value() -> None:
    assert "GitHub Token" not in _match_names("ghp_SHORT")


def test_github_fine_grained_token_matches_fake_format() -> None:
    fake = "github_pat_" + ("C" * 22)
    assert "GitHub Fine-Grained Token" in _match_names(fake)


def test_github_fine_grained_token_rejects_short_value() -> None:
    assert "GitHub Fine-Grained Token" not in _match_names("github_pat_short")


def test_google_api_key_matches_fake_format() -> None:
    assert "Google API Key" in _match_names(FAKE_GOOGLE_KEY)


def test_stripe_key_matches_fake_format() -> None:
    assert "Stripe API Key" in _match_names(FAKE_STRIPE_KEY)


def test_jwt_matches_three_segments() -> None:
    assert "JWT" in _match_names(f"token = {FAKE_JWT}")


def test_jwt_rejects_two_segments() -> None:
    assert "JWT" not in _match_names("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0In0")


def test_private_key_header_matches() -> None:
    assert "Private Key" in _match_names("-----BEGIN RSA PRIVATE KEY-----")
    assert "Private Key" in _match_names("-----BEGIN PRIVATE KEY-----")
    assert "Private Key" in _match_names("-----BEGIN OPENSSH PRIVATE KEY-----")


def test_public_key_header_does_not_match() -> None:
    assert "Private Key" not in _match_names("-----BEGIN PUBLIC KEY-----")
    assert "Private Key" not in _match_names("-----BEGIN RSA PUBLIC KEY-----")


def test_generic_api_key_assignment() -> None:
    text = f'api_key = "{FAKE_API_KEY_VALUE}"'
    matches = PatternEngine().find_in_text(text)
    api_matches = [item for item in matches if item.pattern_name == "Generic API Key"]
    assert len(api_matches) == 1
    assert api_matches[0].matched_text == FAKE_API_KEY_VALUE
    assert api_matches[0].severity == Severity.HIGH


def test_generic_api_key_rejects_short_value() -> None:
    assert "Generic API Key" not in _match_names('api_key = "short"')


def test_generic_password_assignment() -> None:
    text = f"password = '{FAKE_PASSWORD_VALUE}'"
    matches = PatternEngine().find_in_text(text)
    password_matches = [item for item in matches if item.pattern_name == "Generic Password"]
    assert len(password_matches) == 1
    assert password_matches[0].matched_text == FAKE_PASSWORD_VALUE
    assert password_matches[0].severity == Severity.MEDIUM


def test_database_connection_string() -> None:
    assert "Database Connection String" in _match_names(FAKE_DATABASE_URL)


def test_http_url_is_not_a_database_string() -> None:
    assert "Database Connection String" not in _match_names(
        "https://example.com/users/testuser"
    )


def test_default_catalog_is_non_empty_and_named() -> None:
    patterns = default_patterns()
    names = [pattern.name for pattern in patterns]
    assert len(patterns) >= 8
    assert len(names) == len(set(names))
    assert "AWS Access Key ID" in names
    assert "Private Key" in names
