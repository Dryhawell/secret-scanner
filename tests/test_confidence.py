"""Confidence scoring tests. No real secrets are used."""

from scanner.confidence import (
    MAX_CONFIDENCE,
    MIN_CONFIDENCE,
    calculate_confidence,
)
from scanner.entropy import shannon_entropy


def test_confidence_never_claims_certainty() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    score = calculate_confidence(
        "AWS Access Key ID",
        aws,
        "AWS_ACCESS_KEY_ID = '%s'" % aws,
    )
    assert MIN_CONFIDENCE <= score <= MAX_CONFIDENCE
    assert score < 100
    assert score > 0


def test_vendor_format_outranks_contextual_assignment() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    vendor = calculate_confidence("AWS Access Key ID", aws, "")
    contextual = calculate_confidence(
        "Contextual Secret",
        "LocalDevTokenValue1",
        'token = "LocalDevTokenValue1"',
    )
    assert vendor > contextual


def test_sensitive_name_on_line_raises_confidence() -> None:
    aws = "AKIA" + "ABCDEFGHIJ012345"
    bare = calculate_confidence("AWS Access Key ID", aws, aws)
    named = calculate_confidence(
        "AWS Access Key ID",
        aws,
        "AWS_ACCESS_KEY_ID = '%s'" % aws,
    )
    assert named > bare


def test_low_entropy_lowers_generic_score() -> None:
    repeated = "A" * 24
    mixed = "LocalDevTokenValue1"
    low = calculate_confidence("Contextual Secret", repeated, 'token = "%s"' % repeated)
    high = calculate_confidence("Contextual Secret", mixed, 'token = "%s"' % mixed)
    assert low < high
    assert shannon_entropy(repeated) == 0.0


def test_detector_sets_confidence(tmp_path) -> None:
    target = tmp_path / "config.py"
    aws = "AKIA" + "ABCDEFGHIJ012345"
    target.write_text(f"AWS_ACCESS_KEY_ID = '{aws}'\n", encoding="utf-8")
    from scanner.detector import Detector

    findings = Detector().scan_file(target).findings
    aws_hits = [item for item in findings if item.pattern_name == "AWS Access Key ID"]
    assert len(aws_hits) == 1
    assert MIN_CONFIDENCE <= aws_hits[0].confidence <= MAX_CONFIDENCE
