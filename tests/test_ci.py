"""Sanity checks for the GitHub Actions workflow file."""

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_exists_and_runs_pytest() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert WORKFLOW.is_file()
    assert "python -m pytest" in text
    assert "uses: ./" in text
    assert "include-hidden:" in text
    assert "permissions:" in text
    assert "contents: read" in text
    assert "persist-credentials: false" in text
    assert "--update-baseline" not in text
