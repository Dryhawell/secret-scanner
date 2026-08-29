"""Command-line interface for Secret Scanner.

Text is the default surface. ``--format json`` writes a timestamped file
under ``reports/`` unless ``--output`` is given (``-o -`` prints JSON to stdout).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.file_handler import ScanConfig
from scanner.git_mode import GitError, list_changed_files, list_staged_files, repo_root, restrict_to_target
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.scanner import Scanner
from scanner.severity import (
    count_by_severity,
    format_severity_counts,
    meets_minimum,
    sort_findings,
)
from utils.logger import get_logger, setup_logging
from utils.reporter import dumps_report, write_json_report

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[1;33m",
    Severity.MEDIUM: "\033[1;36m",
    Severity.LOW: "\033[1;37m",
}

_EXAMPLES = """
examples:
  python main.py .
  python main.py ./src
  python main.py . --severity HIGH
  python main.py . --exclude dist --exclude build
  python main.py . --no-color
  python main.py . --format json
  python main.py . --output reports/latest.json
  python main.py . --format json -o -
  python main.py . --verbose
  python main.py . --staged
  python main.py . --changed
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description=(
            "Scan a project directory for accidentally committed secrets "
            "(API keys, tokens, passwords, private keys). "
            "Detected values are masked; nothing is printed in plaintext."
        ),
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Directory or file to scan (default: current directory)",
    )
    parser.add_argument(
        "--path",
        dest="path_option",
        metavar="DIR",
        help="Same as the positional path argument",
    )
    parser.add_argument(
        "--severity",
        choices=[item.value for item in Severity],
        default=Severity.LOW.value,
        help="Minimum severity to report (default: LOW = show all)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="NAME",
        help="Extra directory name to skip; may be repeated",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Scan hidden directories such as .github (never scans .git / .venv)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text (default) or json (writes reports/scan_*.json unless --output)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write JSON to FILE (use - for stdout). Without --output, "
        "--format json writes reports/scan_YYYY-MM-DD_HHMM.json",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Write DEBUG logs (per-file) to the log file",
    )
    git_group = parser.add_mutually_exclusive_group()
    git_group.add_argument(
        "--staged",
        action="store_true",
        help="Scan only files staged for commit (git diff --cached)",
    )
    git_group.add_argument(
        "--changed",
        action="store_true",
        help="Scan files changed vs HEAD plus untracked files",
    )
    return parser


def resolve_target(namespace: argparse.Namespace) -> Path:
    raw = namespace.path_option or namespace.path or "."
    return Path(raw)


def build_scan_config(namespace: argparse.Namespace) -> ScanConfig:
    config = ScanConfig(include_hidden=namespace.include_hidden)
    for name in namespace.exclude:
        config.excluded_dirs.add(name)
    return config


def _use_color(no_color: bool) -> bool:
    if no_color:
        return False
    return sys.stdout.isatty()


def _paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{code}{text}{_RESET}"


def filter_findings(
    findings: tuple[SecretFinding, ...] | list[SecretFinding],
    minimum: Severity,
) -> list[SecretFinding]:
    return [item for item in findings if meets_minimum(item.severity, minimum)]


def render_text(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    *,
    color: bool,
) -> None:
    title = _paint("Secret Scanner", _BOLD, color)
    print(title)
    print()
    print(f"Target: {target}")
    print()
    print(f"Files scanned: {result.files_scanned}")
    print(f"Lines scanned: {result.lines_scanned:,}")
    print(f"Potential secrets found: {len(findings)}")
    print(f"Placeholders ignored: {result.placeholders_ignored}")
    print(
        f"By severity: {format_severity_counts(count_by_severity(findings))}"
    )
    print()

    if not findings:
        print("Scan completed.")
        print("No potential secrets found.")
        return

    for finding in findings:
        label = _paint(
            finding.severity.value,
            _SEVERITY_COLOR[finding.severity],
            color,
        )
        print(label)
        print(finding.location(root=target))
        print(finding.secret_type)
        print(f"Confidence: {finding.confidence}%")
        print(_paint(finding.masked_value, _DIM, color))
        print()

    print("Scan completed.")


def emit_json(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    output: str | None,
    reports_dir: Path | None = None,
) -> Path | None:
    """Write JSON to a file, or to stdout when output is '-'."""
    if output == "-":
        sys.stdout.write(dumps_report(result, findings, target))
        return None
    written = write_json_report(
        result,
        findings,
        target,
        output=Path(output) if output else None,
        reports_dir=reports_dir or Path("reports"),
    )
    print(f"Report written: {written.as_posix()}")
    return written


def run(
    argv: list[str] | None = None,
    *,
    reports_dir: Path | None = None,
    log_file: Path | None = None,
) -> int:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    target = resolve_target(namespace)
    minimum = Severity(namespace.severity)
    color = _use_color(namespace.no_color)
    setup_logging(log_file=log_file, verbose=namespace.verbose)

    scanner = Scanner(config=build_scan_config(namespace))
    try:
        if namespace.staged or namespace.changed:
            root = repo_root(target)
            git_files = (
                list_staged_files(root)
                if namespace.staged
                else list_changed_files(root)
            )
            scoped = restrict_to_target(git_files, target.resolve())
            result = scanner.scan_paths(scoped, target=target)
        else:
            result = scanner.scan(target)
    except FileNotFoundError as exc:
        get_logger().error("Target does not exist: %s", target)
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except GitError as exc:
        get_logger().error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = sort_findings(
        filter_findings(result.findings, minimum),
        location_of=lambda item: item.location(root=target),
    )

    format_name = namespace.format
    if namespace.output:
        format_name = "json"

    if format_name == "json":
        emit_json(result, target, findings, namespace.output, reports_dir=reports_dir)
    else:
        render_text(result, target, findings, color=color)

    if findings:
        return 1
    return 0
