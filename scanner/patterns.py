"""Central secret pattern catalog and regex engine.

This module knows *what* a secret looks like. It does not read files.
File-by-file detection is the next phase.

Every regex below targets a public *format*, never a real credential.
Test values must stay obvious placeholders.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from scanner.models import PatternMatch, SecretPattern
from scanner.severity import severity_for


def default_patterns() -> list[SecretPattern]:
    """Return the built-in pattern catalog.

    Keep this list the single place to add a new secret type.
    """
    return [
        SecretPattern(
            name="AWS Access Key ID",
            regex=r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
            severity=severity_for("AWS Access Key ID"),
            description="AWS access key IDs start with AKIA or ASIA (temporary) followed by 16 uppercase alphanumerics.",
        ),
        SecretPattern(
            name="GitHub Token",
            regex=r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",
            severity=severity_for("GitHub Token"),
            description="Classic GitHub tokens use a three-letter prefix, underscore, then 36 characters.",
        ),
        SecretPattern(
            name="GitHub Fine-Grained Token",
            regex=r"github_pat_[A-Za-z0-9_]{22,}",
            severity=severity_for("GitHub Fine-Grained Token"),
            description="Fine-grained GitHub PATs start with github_pat_ and a long alphanumeric payload.",
        ),
        SecretPattern(
            name="Google API Key",
            regex=r"AIza[0-9A-Za-z\-_]{35}",
            severity=severity_for("Google API Key"),
            description="Google API keys start with AIza and continue for 35 URL-safe characters.",
        ),
        SecretPattern(
            name="Stripe API Key",
            regex=r"(?<![A-Za-z0-9])(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}",
            severity=severity_for("Stripe API Key"),
            description="Stripe keys look like sk_live_, sk_test_, pk_live_, or pk_test_ plus a payload.",
        ),
        SecretPattern(
            name="JWT",
            regex=r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            severity=severity_for("JWT"),
            description="JWTs are three base64url segments. The header almost always starts with eyJ.",
        ),
        SecretPattern(
            name="Private Key",
            regex=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            severity=severity_for("Private Key"),
            description="PEM private keys are marked by a BEGIN PRIVATE KEY header, not the public key header.",
        ),
        SecretPattern(
            name="Generic API Key",
            regex=r"\b(?:api[_-]?key|apikey)\s*[:=]\s*(['\"])([A-Za-z0-9_\-]{16,})\1",
            severity=severity_for("Generic API Key"),
            description="Assignment of api_key / api-key to a quoted value of at least 16 characters.",
            flags=re.IGNORECASE,
            value_group=2,
        ),
        SecretPattern(
            name="Generic Password",
            regex=r"\b(?:password|passwd|pwd)\s*[:=]\s*(['\"])([^'\"]{8,})\1",
            severity=severity_for("Generic Password"),
            description="Assignment of password / passwd / pwd to a quoted value of at least 8 characters.",
            flags=re.IGNORECASE,
            value_group=2,
        ),
        SecretPattern(
            name="Database Connection String",
            regex=r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|mariadb)://[^\s'\"<>]+",
            severity=severity_for("Database Connection String"),
            description="Database URLs often embed username and password in the scheme://user:pass@host form.",
            flags=re.IGNORECASE,
        ),
        SecretPattern(
            name="GitLab Token",
            regex=r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
            severity=severity_for("GitLab Token"),
            description="GitLab personal access tokens start with glpat- and a long payload.",
        ),
        SecretPattern(
            name="Slack Token",
            regex=r"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z-]{10,}",
            severity=severity_for("Slack Token"),
            description="Slack bot and user tokens use xoxb-, xoxp-, xoxa-, xoxr-, or xoxs- prefixes.",
        ),
        SecretPattern(
            name="npm Token",
            regex=r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])",
            severity=severity_for("npm Token"),
            description="npm access tokens start with npm_ followed by 36 alphanumeric characters.",
        ),
        SecretPattern(
            name="Hugging Face Token",
            regex=r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])",
            severity=severity_for("Hugging Face Token"),
            description="Hugging Face access tokens start with hf_ and a long alphanumeric payload.",
        ),
        SecretPattern(
            name="OpenAI API Key",
            regex=r"(?<![A-Za-z0-9])sk-(?!ant-)[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])",
            severity=severity_for("OpenAI API Key"),
            description="OpenAI keys use sk- (hyphen), not Stripe sk_ or Anthropic sk-ant-.",
        ),
        SecretPattern(
            name="PyPI Token",
            regex=r"(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])",
            severity=severity_for("PyPI Token"),
            description="PyPI API tokens start with pypi- and a long payload.",
        ),
        SecretPattern(
            name="SendGrid API Key",
            regex=r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",
            severity=severity_for("SendGrid API Key"),
            description="SendGrid keys are SG. plus 22 characters, a dot, then 43 characters.",
        ),
        SecretPattern(
            name="Twilio API Key",
            regex=r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![0-9a-fA-F])",
            severity=severity_for("Twilio API Key"),
            description="Twilio API keys start with SK and 32 hex digits (not Stripe sk_ or OpenAI sk-).",
        ),
        SecretPattern(
            name="Discord Webhook",
            regex=(
                r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
                r"\d{5,}/[A-Za-z0-9_-]{40,}"
            ),
            severity=severity_for("Discord Webhook"),
            description="Discord webhook URLs embed the secret in the path; the URL is the credential.",
            flags=re.IGNORECASE,
        ),
        SecretPattern(
            name="Azure Storage Account Key",
            regex=r"(?<![A-Za-z0-9])AccountKey=([A-Za-z0-9+/=]{80,})(?![A-Za-z0-9+/=])",
            severity=severity_for("Azure Storage Account Key"),
            description="Azure Storage connection strings carry a long Base64 AccountKey.",
            flags=re.IGNORECASE,
            value_group=1,
        ),
        SecretPattern(
            name="Shopify Token",
            regex=r"(?<![A-Za-z0-9])shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}(?![0-9a-fA-F])",
            severity=severity_for("Shopify Token"),
            description="Shopify Admin/storefront tokens use shpat_, shpss_, shpca_, or shppa_ plus 32 hex.",
        ),
        SecretPattern(
            name="Telegram Bot Token",
            regex=r"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])",
            severity=severity_for("Telegram Bot Token"),
            description="Telegram bot tokens are a numeric id, a colon, then AA and 33 payload characters.",
        ),
        SecretPattern(
            name="Anthropic API Key",
            regex=r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
            severity=severity_for("Anthropic API Key"),
            description="Anthropic keys start with sk-ant- (not OpenAI sk- or Stripe sk_).",
        ),
        SecretPattern(
            name="Slack Webhook",
            regex=(
                r"https://hooks\.slack\.com/services/"
                r"T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"
            ),
            severity=severity_for("Slack Webhook"),
            description="Slack incoming webhook URLs embed the secret in the path; the URL is the credential.",
            flags=re.IGNORECASE,
        ),
        SecretPattern(
            name="DigitalOcean Token",
            regex=r"(?<![A-Za-z0-9])dop_v1_[a-fA-F0-9]{64}(?![a-fA-F0-9])",
            severity=severity_for("DigitalOcean Token"),
            description="DigitalOcean personal access tokens start with dop_v1_ and 64 hex digits.",
        ),
        SecretPattern(
            name="Stripe Webhook Secret",
            regex=r"(?<![A-Za-z0-9])whsec_[A-Za-z0-9+/=]{16,}(?![A-Za-z0-9+/=])",
            severity=severity_for("Stripe Webhook Secret"),
            description="Stripe webhook signing secrets start with whsec_ (not sk_live_ API keys).",
        ),
        SecretPattern(
            name="Age Identity Key",
            regex=r"(?<![A-Za-z0-9-])AGE-SECRET-KEY-1[A-Z0-9]{58}(?![A-Za-z0-9])",
            severity=severity_for("Age Identity Key"),
            description="age identity files start with AGE-SECRET-KEY-1 and a 58-character Bech32 payload.",
            flags=re.IGNORECASE,
        ),
        SecretPattern(
            name="PlanetScale Token",
            regex=r"(?<![A-Za-z0-9])pscale_tkn_[A-Za-z0-9]{32,}(?![A-Za-z0-9_])",
            severity=severity_for("PlanetScale Token"),
            description="PlanetScale service tokens start with pscale_tkn_ and a long payload.",
        ),
        SecretPattern(
            name="Postman API Key",
            regex=r"(?<![A-Za-z0-9])PMAK-[A-Fa-f0-9]{24}-[A-Za-z0-9]{34}(?![A-Za-z0-9])",
            severity=severity_for("Postman API Key"),
            description="Postman API keys look like PMAK-, 24 hex digits, a hyphen, then 34 characters.",
        ),
        SecretPattern(
            name="Linear API Key",
            regex=r"(?<![A-Za-z0-9])lin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])",
            severity=severity_for("Linear API Key"),
            description="Linear API keys start with lin_api_ followed by 40 alphanumeric characters.",
        ),
        SecretPattern(
            name="Grafana Token",
            regex=(
                r"(?<![A-Za-z0-9])(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}"
                r"|glc_[A-Za-z0-9+/=_-]{20,})(?![A-Za-z0-9+/=_-])"
            ),
            severity=severity_for("Grafana Token"),
            description="Grafana tokens use glc_ (Cloud) or glsa_ (service account) prefixes.",
        ),
        SecretPattern(
            name="Square Token",
            regex=(
                r"(?<![A-Za-z0-9])(?:sq0atp-[A-Za-z0-9_-]{22}"
                r"|sq0csp-[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"
            ),
            severity=severity_for("Square Token"),
            description="Square access tokens use sq0atp-; OAuth application secrets use sq0csp-.",
        ),
        SecretPattern(
            name="Databricks Token",
            regex=r"(?<![A-Za-z0-9])dapi[a-fA-F0-9]{32}(?:-\d)?(?![A-Za-z0-9])",
            severity=severity_for("Databricks Token"),
            description="Databricks personal access tokens start with dapi and 32 hex digits.",
        ),
        SecretPattern(
            name="Notion API Key",
            regex=r"(?<![A-Za-z0-9])ntn_[0-9]{11}[A-Za-z0-9]{35}(?![A-Za-z0-9])",
            severity=severity_for("Notion API Key"),
            description="Notion integration tokens start with ntn_, 11 digits, then 35 alphanumeric characters.",
        ),
        SecretPattern(
            name="Netlify Token",
            regex=r"(?<![A-Za-z0-9])nf[pcoub]_[A-Za-z0-9]{36}(?![A-Za-z0-9])",
            severity=severity_for("Netlify Token"),
            description="Netlify tokens use nfp_, nfc_, nfo_, nfu_, or nfb_ plus 36 alphanumeric characters.",
        ),
        SecretPattern(
            name="New Relic Key",
            regex=(
                r"(?<![A-Za-z0-9])(?:NRAK-[A-Za-z0-9]{27}"
                r"|NRII-[A-Za-z0-9-]{32})(?![A-Za-z0-9-])"
            ),
            severity=severity_for("New Relic Key"),
            description="New Relic user keys start with NRAK-; ingest keys start with NRII-.",
        ),
        SecretPattern(
            name="Sentry Token",
            regex=(
                r"(?<![A-Za-z0-9])(?:sntryu_[a-fA-F0-9]{64}"
                r"|sntrys_eyJ[A-Za-z0-9+/=]{8,}_[A-Za-z0-9+/]{43})"
                r"(?![A-Za-z0-9+/=])"
            ),
            severity=severity_for("Sentry Token"),
            description="Sentry user tokens use sntryu_; org tokens use sntrys_ plus a base64 payload.",
        ),
        SecretPattern(
            name="Vault Token",
            regex=r"(?<![A-Za-z0-9])hv[sbr]\.[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])",
            severity=severity_for("Vault Token"),
            description="HashiCorp Vault tokens start with hvs., hvb., or hvr. and a long base64url payload.",
        ),
        SecretPattern(
            name="Heroku Token",
            regex=r"(?<![A-Za-z0-9])HRKU-[A-Za-z0-9_-]{58,}(?![A-Za-z0-9_-])",
            severity=severity_for("Heroku Token"),
            description="Heroku OAuth access tokens start with HRKU- (not a bare UUID).",
        ),
        SecretPattern(
            name="Airtable Token",
            regex=r"(?<![A-Za-z0-9])pat[A-Za-z0-9]{14}\.[a-fA-F0-9]{64}(?![a-fA-F0-9])",
            severity=severity_for("Airtable Token"),
            description="Airtable personal access tokens look like pat, 14 id characters, a dot, then 64 hex.",
        ),
        SecretPattern(
            name="Doppler Token",
            regex=(
                r"(?<![A-Za-z0-9])dp\.(?:(?:pt|ct|sa|said|scim|audit)"
                r"|st(?:\.[a-z0-9_-]{2,35})?)\.[A-Za-z0-9]{40,44}(?![A-Za-z0-9])"
            ),
            severity=severity_for("Doppler Token"),
            description="Doppler tokens use dp.pt., dp.st., dp.ct., and related prefixes.",
        ),
    ]


class PatternEngine:
    """Compile patterns once, then search text as many times as needed."""

    def __init__(self, patterns: Sequence[SecretPattern] | None = None) -> None:
        self.patterns = list(patterns) if patterns is not None else default_patterns()
        self._compiled: list[tuple[SecretPattern, re.Pattern[str]]] = [
            (pattern, re.compile(pattern.regex, pattern.flags))
            for pattern in self.patterns
        ]

    def find_in_text(self, text: str) -> list[PatternMatch]:
        """Return every pattern hit in ``text``. Does not read files."""
        matches: list[PatternMatch] = []
        for pattern, compiled in self._compiled:
            for match in compiled.finditer(text):
                matched_text = (
                    match.group(pattern.value_group)
                    if pattern.value_group is not None
                    else match.group(0)
                )
                matches.append(
                    PatternMatch(
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        matched_text=matched_text,
                        start=match.start(),
                        end=match.end(),
                        compiled_pattern=compiled,
                    )
                )
        return matches


def merged_engine(extra: Sequence[SecretPattern] | None = None) -> PatternEngine:
    """Built-in catalog plus optional custom patterns from a config file."""
    extra = extra or ()
    if not extra:
        return PatternEngine()
    return PatternEngine([*default_patterns(), *extra])
