"""Version constant."""

from scanner.version import __version__


def test_version_is_semver() -> None:
    assert __version__ == "1.26.0"
