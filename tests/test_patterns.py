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


def test_aws_temporary_asia_key_matches_same_rule() -> None:
    fake = "ASIA" + "ABCDEFGHIJ012345"
    names = _match_names(fake)
    assert "AWS Access Key ID" in names
    assert "AWS Access Key ID" not in _match_names("ASIA" + "SHORT")
    assert "AWS Access Key ID" not in _match_names("asiaABCDEFGHIJ012345")


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


def test_gitlab_token_matches_fake_format() -> None:
    fake = "glpat-" + "TESTPLACEHOLDER00000"
    assert len(fake) == 6 + 20
    assert "GitLab Token" in _match_names(fake)
    assert "GitLab Token" not in _match_names("glpat-short")


def test_slack_token_matches_fake_format() -> None:
    fake = "xoxb-" + "0000000000-TESTFAKE00"
    assert "Slack Token" in _match_names(fake)
    assert "Slack Token" not in _match_names("xoxb-short")


def test_npm_token_matches_fake_format() -> None:
    fake = "npm_" + ("A" * 36)
    assert "npm Token" in _match_names(fake)
    assert "npm Token" not in _match_names("npm_SHORT")


def test_hugging_face_token_matches_fake_format() -> None:
    fake = "hf_" + ("B" * 34)
    assert "Hugging Face Token" in _match_names(fake)
    assert "Hugging Face Token" not in _match_names("hf_short")


def test_openai_key_is_not_stripe() -> None:
    fake = "sk-" + "TESTOPENAIPLACEHOLDER00"
    names = _match_names(fake)
    assert "OpenAI API Key" in names
    assert "Stripe API Key" not in names
    assert "Anthropic API Key" not in names
    stripe = "sk_test_" + "TESTPLACEHOLDER000000"
    names = _match_names(stripe)
    assert "Stripe API Key" in names
    assert "OpenAI API Key" not in names


def test_pypi_token_matches_fake_format() -> None:
    fake = "pypi-" + ("C" * 32)
    assert "PyPI Token" in _match_names(fake)
    assert "PyPI Token" not in _match_names("pypi-short")


def test_sendgrid_key_matches_fake_format() -> None:
    fake = "SG." + ("A" * 22) + "." + ("B" * 43)
    assert "SendGrid API Key" in _match_names(fake)
    assert "SendGrid API Key" not in _match_names("SG.short.short")


def test_twilio_key_is_not_stripe_or_openai() -> None:
    fake = "SK" + ("a" * 32)
    names = _match_names(fake)
    assert "Twilio API Key" in names
    assert "Stripe API Key" not in names
    assert "OpenAI API Key" not in names
    assert "Twilio API Key" not in _match_names("SK" + "abcd")


def test_discord_webhook_matches_fake_url() -> None:
    fake = (
        "https://discord.com/api/webhooks/"
        + ("1" * 18)
        + "/"
        + ("A" * 68)
    )
    assert "Discord Webhook" in _match_names(fake)
    assert "Discord Webhook" not in _match_names(
        "https://discord.com/api/webhooks/12345/short"
    )
    assert "Database Connection String" not in _match_names(fake)


def test_azure_storage_key_matches_long_accountkey() -> None:
    fake = "AccountKey=" + ("A" * 88)
    assert "Azure Storage Account Key" in _match_names(fake)
    assert "Azure Storage Account Key" not in _match_names("AccountKey=short")
    lower = "accountkey=" + ("B" * 88)
    assert "Azure Storage Account Key" in _match_names(lower)


def test_shopify_token_matches_fake_format() -> None:
    fake = "shpat_" + ("ab" * 16)
    assert "Shopify Token" in _match_names(fake)
    assert "Shopify Token" not in _match_names("shpat_" + "ab")
    assert "Shopify Token" in _match_names("shpss_" + ("cd" * 16))


def test_telegram_bot_token_matches_fake_format() -> None:
    fake = "123456789:AA" + ("B" * 33)
    assert "Telegram Bot Token" in _match_names(fake)
    assert "Telegram Bot Token" not in _match_names("123:AAshort")


def test_anthropic_key_is_not_openai_or_stripe() -> None:
    fake = "sk-ant-" + "TESTPLACEHOLDERKEY00"
    names = _match_names(fake)
    assert "Anthropic API Key" in names
    assert "OpenAI API Key" not in names
    assert "Stripe API Key" not in names
    openai = "sk-" + "TESTOPENAIPLACEHOLDER00"
    names = _match_names(openai)
    assert "OpenAI API Key" in names
    assert "Anthropic API Key" not in names


def test_slack_webhook_matches_fake_url() -> None:
    fake = (
        "https://hooks.slack.com/services/"
        + "T"
        + ("0" * 8)
        + "/B"
        + ("1" * 8)
        + "/"
        + ("A" * 24)
    )
    names = _match_names(fake)
    assert "Slack Webhook" in names
    assert "Slack Token" not in names
    assert "Database Connection String" not in names
    assert "Discord Webhook" not in names
    assert "Slack Webhook" not in _match_names(
        "https://hooks.slack.com/services/T00/B00/short"
    )


def test_digitalocean_token_matches_fake_format() -> None:
    fake = "dop_v1_" + ("a" * 64)
    assert "DigitalOcean Token" in _match_names(fake)
    assert "DigitalOcean Token" not in _match_names("dop_v1_" + "ab")


def test_stripe_webhook_secret_is_not_api_key() -> None:
    fake = "whsec_" + "TESTPLACEHOLDER0000"
    names = _match_names(fake)
    assert "Stripe Webhook Secret" in names
    assert "Stripe API Key" not in names
    assert "Stripe Webhook Secret" not in _match_names("whsec_short")


def test_age_identity_is_not_pem_private_key() -> None:
    fake = "AGE-SECRET-KEY-" + "1" + ("A" * 58)
    names = _match_names(fake)
    assert "Age Identity Key" in names
    assert "Private Key" not in names
    assert "Age Identity Key" not in _match_names("AGE-SECRET-KEY-" + "1" + ("A" * 57))
    assert "Age Identity Key" not in _match_names("-----BEGIN PRIVATE KEY-----")


def test_planetscale_token_matches_fake_format() -> None:
    fake = "pscale_tkn_" + ("A" * 32)
    assert "PlanetScale Token" in _match_names(fake)
    assert "PlanetScale Token" not in _match_names("pscale_tkn_" + "ab")


def test_postman_api_key_matches_fake_format() -> None:
    fake = "PMAK-" + ("a" * 24) + "-" + ("B" * 34)
    names = _match_names(fake)
    assert "Postman API Key" in names
    assert "Postman API Key" not in _match_names("PMAK-" + "short")
    assert "Postman API Key" not in _match_names("PMAK-" + ("a" * 24))


def test_linear_api_key_matches_fake_format() -> None:
    fake = "lin_api_" + ("A" * 40)
    names = _match_names(fake)
    assert "Linear API Key" in names
    assert "Linear API Key" not in _match_names("lin_api_" + "short")
    assert "Linear API Key" not in _match_names("lin_api_" + ("A" * 39))


def test_grafana_token_matches_cloud_and_service_account() -> None:
    cloud = "glc_" + ("B" * 24)
    service = "glsa_" + ("C" * 32) + "_" + ("a" * 8)
    names = _match_names(cloud)
    assert "Grafana Token" in names
    assert "GitLab Token" not in names
    names = _match_names(service)
    assert "Grafana Token" in names
    assert "GitLab Token" not in names
    gitlab = "glpat-" + "TESTPLACEHOLDER00000"
    names = _match_names(gitlab)
    assert "GitLab Token" in names
    assert "Grafana Token" not in names
    assert "Grafana Token" not in _match_names("glc_" + ("B" * 19))
    assert "Grafana Token" not in _match_names("glsa_" + ("C" * 32))


def test_square_token_matches_access_and_oauth_secret() -> None:
    access = "sq0atp-" + ("D" * 22)
    secret = "sq0csp-" + ("E" * 43)
    names = _match_names(access)
    assert "Square Token" in names
    assert "Shopify Token" not in names
    names = _match_names(secret)
    assert "Square Token" in names
    assert "Square Token" not in _match_names("sq0atp-" + "short")
    assert "Square Token" not in _match_names("sq0idp-" + ("F" * 22))


def test_databricks_token_matches_fake_format() -> None:
    fake = "dapi" + ("a" * 32)
    names = _match_names(fake)
    assert "Databricks Token" in names
    assert "Databricks Token" in _match_names("dapi" + ("b" * 32) + "-3")
    assert "Databricks Token" not in _match_names("dapi" + "short")
    assert "Databricks Token" not in _match_names("dapi" + ("a" * 31))


def test_notion_key_is_not_legacy_secret_prefix() -> None:
    fake = "ntn_" + ("1" * 11) + ("A" * 35)
    names = _match_names(fake)
    assert "Notion API Key" in names
    assert "npm Token" not in names
    assert "Notion API Key" not in _match_names("ntn_" + "short")
    assert "Notion API Key" not in _match_names("ntn_" + ("A" * 46))
    assert "Notion API Key" not in _match_names("secret_" + ("B" * 43))


def test_netlify_token_is_not_npm() -> None:
    fake = "nfp_" + ("C" * 36)
    names = _match_names(fake)
    assert "Netlify Token" in names
    assert "npm Token" not in names
    assert "Netlify Token" in _match_names("nfc_" + ("D" * 36))
    npm = "npm_" + ("A" * 36)
    names = _match_names(npm)
    assert "npm Token" in names
    assert "Netlify Token" not in names
    assert "Netlify Token" not in _match_names("nfp_" + "short")


def test_new_relic_key_matches_user_and_ingest() -> None:
    user = "NRAK-" + ("A" * 27)
    ingest = "NRII-" + ("B" * 32)
    names = _match_names(user)
    assert "New Relic Key" in names
    names = _match_names(ingest)
    assert "New Relic Key" in names
    assert "New Relic Key" not in _match_names("NRAK-" + "short")
    assert "New Relic Key" not in _match_names("NRJS-" + ("a" * 19))


def test_sentry_token_matches_user_and_org() -> None:
    user = "sntryu_" + ("a" * 64)
    org = "sntrys_" + "eyJ" + ("A" * 20) + "_" + ("B" * 43)
    names = _match_names(user)
    assert "Sentry Token" in names
    assert "JWT" not in names
    names = _match_names(org)
    assert "Sentry Token" in names
    assert "JWT" not in names
    assert "Sentry Token" not in _match_names("sntryu_" + "short")
    assert "Sentry Token" not in _match_names("sntrys_" + "notjson_" + ("C" * 43))


def test_default_catalog_is_non_empty_and_named() -> None:
    patterns = default_patterns()
    names = [pattern.name for pattern in patterns]
    assert len(patterns) >= 8
    assert len(names) == len(set(names))
    assert "GitLab Token" in names
    assert "OpenAI API Key" in names
    assert "SendGrid API Key" in names
    assert "Azure Storage Account Key" in names
    assert "Anthropic API Key" in names
    assert "Slack Webhook" in names
    assert "DigitalOcean Token" in names
    assert "Stripe Webhook Secret" in names
    assert "Age Identity Key" in names
    assert "PlanetScale Token" in names
    assert "Postman API Key" in names
    assert "Linear API Key" in names
    assert "Grafana Token" in names
    assert "Square Token" in names
    assert "Databricks Token" in names
    assert "Notion API Key" in names
    assert "Netlify Token" in names
    assert "New Relic Key" in names
    assert "Sentry Token" in names
