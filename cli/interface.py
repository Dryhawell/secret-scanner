"""Command-line interface for Secret Scanner.

Text is the default surface. ``--format json`` / ``sarif`` / ``html`` write
a timestamped file under ``reports/`` unless ``--output`` is given
(``-o -`` prints the report to stdout).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.baseline import (
    BaselineError,
    DEFAULT_BASELINE_NAME,
    default_baseline_file,
    load_baseline,
    write_baseline,
)
from scanner.config_file import ConfigError, FileSettings, load_config_file, resolve_config_path
from scanner.file_handler import ScanConfig
from scanner.git_mode import GitError, list_changed_files, list_staged_files, repo_root, restrict_to_target
from scanner.hook import HookError, install_pre_commit_hook
from scanner.ignore import IgnoreError, default_ignore_file, ignore_root, load_ignore_file
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.patterns import merged_engine
from scanner.scanner import Scanner
from scanner.severity import (
    count_by_severity,
    format_severity_counts,
    meets_minimum,
    sort_findings,
)
from scanner.version import __version__
from utils.logger import get_logger, setup_logging
from utils.html_report import render_html, write_html_report
from utils.reporter import dumps_report, write_json_report
from utils.sarif import dumps_sarif, write_sarif_report

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
  python main.py . --format sarif
  python main.py . --output reports/latest.sarif
  python main.py . --format html
  python main.py . --output reports/latest.html
  python main.py . --verbose
  python main.py . --staged
  python main.py . --changed
  python main.py --version
  python main.py . --ignore-file .secret-scanner-ignore
  python main.py . --update-baseline
  python main.py . --baseline .secret-scanner-baseline.json
  python main.py --install-hook
  python main.py . --config .secret-scanner.json
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
        "--version",
        action="version",
        version=f"Secret Scanner {__version__}",
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
        default=None,
        help="Minimum severity to report (default: LOW, or the config file)",
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
        choices=("text", "json", "sarif", "html"),
        default=None,
        help="text (default), json, sarif, or html (writes reports/scan_* unless --output)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write JSON, SARIF, or HTML to FILE (use - for stdout). Without --output, "
        "--format json|sarif|html writes reports/scan_YYYY-MM-DD_HHMM.*",
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
    parser.add_argument(
        "--ignore-file",
        metavar="FILE",
        help="Allowlist file (default: .secret-scanner-ignore next to the "
        "target or in the current directory, if present)",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Hashed baseline JSON (default: .secret-scanner-baseline.json "
        "if present). Does not contain plaintext secrets.",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Merge current findings into the baseline file and exit 0",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install a local Git pre-commit hook that scans staged files",
    )
    parser.add_argument(
        "--force-hook",
        action="store_true",
        help="Overwrite an existing pre-commit hook (used with --install-hook)",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="JSON or YAML config (default: .secret-scanner.json / .yml if present). "
        "CLI flags override file values.",
    )
    return parser


def resolve_target(namespace: argparse.Namespace) -> Path:
    raw = namespace.path_option or namespace.path or "."
    return Path(raw)


def build_scan_config(
    namespace: argparse.Namespace, settings: FileSettings | None = None
) -> ScanConfig:
    hidden = namespace.include_hidden or (
        settings.include_hidden is True if settings is not None else False
    )
    config = ScanConfig(include_hidden=hidden)
    names: list[str] = []
    if settings is not None:
        names.extend(settings.exclude)
    names.extend(namespace.exclude)
    for name in names:
        config.exclude_dir(name)
    return config


def apply_ignore_file(
    config: ScanConfig,
    namespace: argparse.Namespace,
    target: Path,
    settings: FileSettings | None = None,
) -> None:
    """Load allowlist rules into ``config``. Missing default file is a no-op."""
    if namespace.ignore_file:
        path = Path(namespace.ignore_file)
        if not path.is_file():
            raise IgnoreError(f"Ignore file does not exist: {path}")
    elif settings is not None and settings.ignore_file is not None:
        path = settings.ignore_file
        if not path.is_file():
            raise IgnoreError(f"Ignore file does not exist: {path}")
    else:
        found = default_ignore_file(target)
        if found is None:
            return
        path = found
    rules = load_ignore_file(path)
    config.ignore_paths.extend(rules.paths)
    config.ignore_findings.extend(rules.findings)


def apply_baseline(
    config: ScanConfig,
    namespace: argparse.Namespace,
    target: Path,
    settings: FileSettings | None = None,
) -> None:
    """Load baseline keys. Missing default file is a no-op. Skip on --update-baseline."""
    if namespace.update_baseline:
        return
    if namespace.baseline:
        path = Path(namespace.baseline)
        if not path.is_file():
            raise BaselineError(f"Baseline file does not exist: {path}")
    elif settings is not None and settings.baseline is not None:
        path = settings.baseline
        if not path.is_file():
            raise BaselineError(f"Baseline file does not exist: {path}")
    else:
        found = default_baseline_file(target)
        if found is None:
            return
        path = found
    config.baseline_keys.update(load_baseline(path))


def resolve_baseline_path(
    namespace: argparse.Namespace,
    target: Path,
    settings: FileSettings | None = None,
) -> Path:
    """Path used by --update-baseline."""
    if namespace.baseline:
        return Path(namespace.baseline)
    if settings is not None and settings.baseline is not None:
        return settings.baseline
    found = default_baseline_file(target)
    if found is not None:
        return found
    search = target if target.is_dir() else target.parent
    return search / DEFAULT_BASELINE_NAME


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
    print(f"Allowlist ignored: {result.allowlist_ignored}")
    print(f"Baseline ignored: {result.baseline_ignored}")
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


def resolve_output_format(
    namespace: argparse.Namespace, settings: FileSettings
) -> str:
    """CLI --format wins. ``--output file.sarif|.html`` infers format. ``--output`` still defaults to json."""
    if namespace.format:
        chosen = namespace.format
    elif settings.format:
        chosen = settings.format
    else:
        chosen = "text"
    if not namespace.output:
        return chosen
    if namespace.format:
        return namespace.format
    if namespace.output != "-":
        suffix = Path(namespace.output).suffix.casefold()
        if suffix == ".sarif":
            return "sarif"
        if suffix == ".html":
            return "html"
    return "json"


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


def emit_sarif(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    output: str | None,
    reports_dir: Path | None = None,
) -> Path | None:
    """Write SARIF to a file, or to stdout when output is '-'."""
    if output == "-":
        sys.stdout.write(dumps_sarif(result, findings, target))
        return None
    written = write_sarif_report(
        result,
        findings,
        target,
        output=Path(output) if output else None,
        reports_dir=reports_dir or Path("reports"),
    )
    print(f"Report written: {written.as_posix()}")
    return written


def emit_html(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    output: str | None,
    reports_dir: Path | None = None,
) -> Path | None:
    """Write HTML to a file, or to stdout when output is '-'."""
    if output == "-":
        sys.stdout.write(render_html(result, findings, target))
        return None
    written = write_html_report(
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
    setup_logging(log_file=log_file, verbose=namespace.verbose)

    if not target.exists():
        get_logger().error("Target does not exist: %s", target)
        print(f"Error: Target does not exist: {target}", file=sys.stderr)
        return 2

    if namespace.install_hook:
        try:
            dest = install_pre_commit_hook(
                repo_root(target), force=namespace.force_hook
            )
        except (GitError, HookError) as exc:
            get_logger().error("%s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"Installed pre-commit hook: {dest.as_posix()}")
        return 0

    try:
        config_path = resolve_config_path(namespace.config, target)
        settings = (
            load_config_file(config_path) if config_path is not None else FileSettings()
        )
    except ConfigError as exc:
        get_logger().error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    verbose = namespace.verbose or (settings.verbose is True)
    setup_logging(log_file=log_file, verbose=verbose)
    minimum = Severity(namespace.severity or settings.severity or Severity.LOW.value)
    color = _use_color(namespace.no_color or (settings.no_color is True))

    scanner = Scanner(
        config=build_scan_config(namespace, settings),
        engine=merged_engine(settings.patterns),
    )
    try:
        apply_ignore_file(scanner.config, namespace, target, settings)
        apply_baseline(scanner.config, namespace, target, settings)
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
    except IgnoreError as exc:
        get_logger().error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except BaselineError as exc:
        get_logger().error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = sort_findings(
        filter_findings(result.findings, minimum),
        location_of=lambda item: item.location(root=target),
    )

    format_name = resolve_output_format(namespace, settings)

    try:
        if format_name == "json":
            emit_json(result, target, findings, namespace.output, reports_dir=reports_dir)
        elif format_name == "sarif":
            emit_sarif(result, target, findings, namespace.output, reports_dir=reports_dir)
        elif format_name == "html":
            emit_html(result, target, findings, namespace.output, reports_dir=reports_dir)
        else:
            render_text(result, target, findings, color=color)
    except OSError as exc:
        get_logger().error("Unable to write output: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if namespace.update_baseline:
        try:
            written = write_baseline(
                resolve_baseline_path(namespace, target, settings),
                result.findings,
                ignore_root(target),
            )
        except OSError as exc:
            get_logger().error("Unable to write baseline: %s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"Baseline updated: {written.as_posix()}")
        return 0

    if findings:
        return 1
    return 0
