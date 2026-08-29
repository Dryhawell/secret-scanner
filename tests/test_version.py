"""Version constant for the v1.0.0 release."""

from scanner.version import __version__


def test_version_is_semver_v1() -> None:
    assert __version__ == "1.0.0"
