"""Command-line interface for Secret Scanner.

Text is the default surface. ``--format json`` / ``sarif`` / ``html`` write
a timestamped file under ``reports/`` unless ``--output`` is given
(``-o -`` prints the report to stdout).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from scanner.baseline import (
    BaselineError,
    DEFAULT_BASELINE_NAME,
    default_baseline_file,
    load_baseline,
    write_baseline,
)
from scanner.confidence import MAX_CONFIDENCE
from scanner.context import CONTEXTUAL_PATTERN_NAME
from scanner.config_file import (
    ConfigError,
    FileSettings,
    MAX_SKIP_PATTERNS,
    load_config_file,
    resolve_config_path,
)
from scanner.entropy import ENTROPY_GATED_PATTERNS, FORMAT_LOCKED_PATTERNS
from scanner.file_handler import (
    DEFAULT_MAX_FILE_SIZE,
    MAX_FILE_SIZE_MIB,
    MAX_JOBS,
    MIB,
    GlobError,
    ScanConfig,
    bytes_for_mib,
    normalize_glob,
    resolve_jobs,
)
from scanner.git_mode import (
    GitError,
    list_changed_files,
    list_since_files,
    list_staged_files,
    repo_root,
    restrict_to_target,
)
from scanner.history import list_history_lines, path_in_target
from scanner.hook import HookError, install_pre_commit_hook
from scanner.ignore import IgnoreError, default_ignore_file, ignore_root, load_ignore_file
from scanner.models import ScanResult, SecretFinding, Severity
from scanner.patterns import PatternEngine, merged_engine
from scanner.scanner import Scanner
from scanner.severity import (
    count_by_severity,
    format_severity_counts,
    meets_minimum,
    severity_for,
    sort_findings,
)
from scanner.version import __version__
from cli.dashboard import DEFAULT_PORT, serve_dashboard
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
  python main.py --list-patterns
  python main.py . --skip-pattern "Contextual Secret"
  python main.py . --only-pattern "AWS Access Key ID"
  python main.py . --max-file-size 10
  python main.py . --exclude dist --exclude build
  python main.py . --glob "*.env" --glob "*.py"
  python main.py . --skip-glob "*.min.js"
  python main.py . --no-color
  python main.py . --quiet
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
  python main.py . --history
  python main.py . --since origin/main
  python main.py --stdin
  python main.py --jobs 4
  python main.py --dashboard --no-browser
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
        "--list-patterns",
        action="store_true",
        help="Print built-in (and config custom) rule names and exit. Does not scan.",
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
        "--min-confidence",
        type=_parse_min_confidence,
        default=None,
        metavar="N",
        help="Hide findings with confidence below N (0-99, default: 0 = no extra floor). "
        "Not the same as --severity.",
    )
    parser.add_argument(
        "--skip-pattern",
        action="append",
        default=[],
        metavar="NAME",
        help="Disable a detection rule (repeatable). Names from --list-patterns. "
        "Skipping a vendor format can still leave a Contextual Secret on the same line.",
    )
    parser.add_argument(
        "--only-pattern",
        action="append",
        default=[],
        metavar="NAME",
        help="Only run these detection rules (repeatable). Names from --list-patterns. "
        "Applied before --skip-pattern. An empty remaining set exits 2.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="NAME",
        help="Extra directory name to skip; may be repeated",
    )
    parser.add_argument(
        "--glob",
        action="append",
        default=[],
        type=_parse_glob,
        metavar="PATTERN",
        help="Only scan files matching this glob (repeatable). "
        "*.env matches the file name in any folder. Patterns with / are "
        "relative to the scan root. Not a directory name (see --exclude).",
    )
    parser.add_argument(
        "--skip-glob",
        action="append",
        default=[],
        type=_parse_glob,
        metavar="PATTERN",
        help="Skip files matching this glob (repeatable). Applied after --glob.",
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
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress the text report (exit code still 1 on findings). "
        "Does not suppress --output - or error messages.",
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
    git_group.add_argument(
        "--history",
        action="store_true",
        help="Scan added lines in recent Git commits (not the working tree)",
    )
    git_group.add_argument(
        "--since",
        metavar="REF",
        help="Scan files changed since REF (git diff REF...HEAD). Not untracked.",
    )
    parser.add_argument(
        "--history-depth",
        type=int,
        default=200,
        metavar="N",
        help="How many recent commits --history reads (default: 200, max 5000)",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=_parse_jobs,
        default=None,
        metavar="N",
        help="Worker threads for file scans (default: 1, 0 = CPU count, max 32). "
        "Does not apply to --history or --stdin.",
    )
    parser.add_argument(
        "--max-file-size",
        type=_parse_max_file_size,
        default=None,
        metavar="N",
        help="Skip files larger than N mebibytes (default: 5, 0 = unlimited, "
        f"max {MAX_FILE_SIZE_MIB}). Also applies to --stdin.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Scan text from stdin (pipe). Does not write the buffer to disk.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Serve a localhost-only HTML dashboard (127.0.0.1, no JavaScript)",
    )
    parser.add_argument(
        "--port",
        type=_parse_port,
        default=DEFAULT_PORT,
        metavar="N",
        help="Dashboard listen port (default: 8765). Bound to 127.0.0.1 only.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open a browser when --dashboard starts",
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


def _parse_min_confidence(raw: str) -> int:
    """Argparse type for --min-confidence. 0 means report every finding."""
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("min-confidence must be an integer") from exc
    if value < 0 or value > MAX_CONFIDENCE:
        raise argparse.ArgumentTypeError(
            f"min-confidence must be between 0 and {MAX_CONFIDENCE}"
        )
    return value


def _parse_glob(raw: str) -> str:
    """Argparse type for --glob / --skip-glob."""
    try:
        return normalize_glob(raw)
    except GlobError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_jobs(raw: str) -> int:
    """Argparse type for --jobs. 0 means auto (CPU count)."""
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("jobs must be an integer") from exc
    if value < 0 or value > MAX_JOBS:
        raise argparse.ArgumentTypeError(
            f"jobs must be between 0 and {MAX_JOBS} (0 = auto)"
        )
    return value


def _parse_max_file_size(raw: str) -> int:
    """Argparse type for --max-file-size (mebibytes). 0 means unlimited."""
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("max-file-size must be an integer") from exc
    if value < 0 or value > MAX_FILE_SIZE_MIB:
        raise argparse.ArgumentTypeError(
            f"max-file-size must be between 0 and {MAX_FILE_SIZE_MIB} (0 = unlimited)"
        )
    return value


def _parse_port(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if value < 1 or value > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return value


def resolve_target(namespace: argparse.Namespace) -> Path:
    raw = namespace.path_option or namespace.path or "."
    return Path(raw)


def stdin_virtual_path(namespace: argparse.Namespace) -> Path:
    """Finding path label for --stdin. ``.`` is a stream, not a directory walk."""
    raw = namespace.path_option or namespace.path
    if not raw or raw in {".", "./"}:
        return Path("stdin")
    return Path(raw)


def stdin_is_tty(stream: TextIO) -> bool:
    """True when the stream is an interactive terminal. StringIO is not a TTY."""
    checker = getattr(stream, "isatty", None)
    if not callable(checker):
        return False
    return bool(checker())


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
    includes: list[str] = []
    skips: list[str] = []
    if settings is not None:
        includes.extend(settings.glob)
        skips.extend(settings.skip_glob)
    includes.extend(namespace.glob)
    skips.extend(namespace.skip_glob)
    config.include_globs = includes
    config.skip_globs = skips
    requested = 1
    if settings is not None and settings.jobs is not None:
        requested = settings.jobs
    if namespace.jobs is not None:
        requested = namespace.jobs
    config.jobs = resolve_jobs(requested)
    config.max_file_size_bytes = resolve_max_file_size_bytes(namespace, settings)
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
    min_confidence: int = 0,
) -> list[SecretFinding]:
    """Keep findings that meet severity and confidence floors (reporting only)."""
    return [
        item
        for item in findings
        if meets_minimum(item.severity, minimum) and item.confidence >= min_confidence
    ]


class SkipPatternError(ValueError):
    """Unknown or empty skip-pattern list after validation."""


def _entropy_policy_label(name: str) -> str:
    if name in FORMAT_LOCKED_PATTERNS:
        return "format-locked"
    if name in ENTROPY_GATED_PATTERNS:
        return "entropy-gated"
    return "custom"


def render_pattern_list(engine: PatternEngine, *, color: bool) -> None:
    """Print rule names for --list-patterns. Does not print regexes."""
    rows: list[tuple[str, str, str]] = [
        (pattern.name, pattern.severity.value, _entropy_policy_label(pattern.name))
        for pattern in engine.patterns
    ]
    if CONTEXTUAL_PATTERN_NAME not in {pattern.name for pattern in engine.patterns}:
        rows.append(
            (
                CONTEXTUAL_PATTERN_NAME,
                severity_for(CONTEXTUAL_PATTERN_NAME).value,
                _entropy_policy_label(CONTEXTUAL_PATTERN_NAME),
            )
        )
    rows.sort(key=lambda item: item[0].casefold())
    width = max(len(item[0]) for item in rows)
    title = _paint("Secret Scanner patterns", _BOLD, color)
    print(title)
    for name, severity, policy in rows:
        print(f"{name:<{width}}  {severity:<8}  {policy}")


def known_pattern_names(engine: PatternEngine) -> dict[str, str]:
    """Map casefolded name → canonical name (builtins, custom, Contextual Secret)."""
    names = {pattern.name for pattern in engine.patterns}
    names.add(CONTEXTUAL_PATTERN_NAME)
    return {name.casefold(): name for name in names}


def _canonical_pattern_names(
    requested: list[str],
    known: dict[str, str],
    *,
    kind: str,
) -> list[str]:
    """Resolve operator names to catalog names. Unknown names raise SkipPatternError."""
    if len(requested) > MAX_SKIP_PATTERNS:
        raise SkipPatternError(
            f"at most {MAX_SKIP_PATTERNS} {kind} names are allowed"
        )
    names: list[str] = []
    seen: set[str] = set()
    for raw in requested:
        key = raw.strip()
        if not key:
            raise SkipPatternError(f"{kind} names must be non-empty")
        canon = known.get(key.casefold())
        if canon is None:
            raise SkipPatternError(
                f"Unknown pattern {raw!r}. Use --list-patterns for names."
            )
        if canon not in seen:
            seen.add(canon)
            names.append(canon)
    return names


def resolve_skip_patterns(
    namespace: argparse.Namespace,
    settings: FileSettings,
    engine: PatternEngine,
) -> list[str]:
    """Disabled rule names after --only-pattern allowlist and --skip-pattern."""
    skip_raw: list[str] = []
    skip_raw.extend(settings.skip_patterns)
    skip_raw.extend(namespace.skip_pattern)
    only_raw: list[str] = []
    only_raw.extend(settings.only_patterns)
    only_raw.extend(namespace.only_pattern)
    if not skip_raw and not only_raw:
        return []
    known = known_pattern_names(engine)
    skip_set = set(
        _canonical_pattern_names(skip_raw, known, kind="skip-pattern")
        if skip_raw
        else []
    )
    only_set = set(
        _canonical_pattern_names(only_raw, known, kind="only-pattern")
        if only_raw
        else []
    )
    if only_set:
        disabled = (set(known.values()) - only_set) | skip_set
    else:
        disabled = skip_set
    regex_left = any(pattern.name not in disabled for pattern in engine.patterns)
    context_on = CONTEXTUAL_PATTERN_NAME not in disabled
    if not regex_left and not context_on:
        raise SkipPatternError("all detection rules were skipped")
    return sorted(disabled)


def resolve_min_confidence(
    namespace: argparse.Namespace, settings: FileSettings | None = None
) -> int:
    """CLI wins, then config, else 0 (no extra floor)."""
    if namespace.min_confidence is not None:
        return namespace.min_confidence
    if settings is not None and settings.min_confidence is not None:
        return settings.min_confidence
    return 0


def resolve_max_file_size_bytes(
    namespace: argparse.Namespace, settings: FileSettings | None = None
) -> int | None:
    """CLI wins, then config, else 5 MiB. ``0`` means unlimited."""
    mib: int | None = None
    if namespace.max_file_size is not None:
        mib = namespace.max_file_size
    elif settings is not None:
        mib = settings.max_file_size
    if mib is None:
        return DEFAULT_MAX_FILE_SIZE
    return bytes_for_mib(mib)


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
    *,
    quiet: bool = False,
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
    if not quiet:
        print(f"Report written: {written.as_posix()}")
    return written


def emit_sarif(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    output: str | None,
    reports_dir: Path | None = None,
    *,
    quiet: bool = False,
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
    if not quiet:
        print(f"Report written: {written.as_posix()}")
    return written


def emit_html(
    result: ScanResult,
    target: Path,
    findings: list[SecretFinding],
    output: str | None,
    reports_dir: Path | None = None,
    *,
    quiet: bool = False,
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
    if not quiet:
        print(f"Report written: {written.as_posix()}")
    return written


def run(
    argv: list[str] | None = None,
    *,
    reports_dir: Path | None = None,
    log_file: Path | None = None,
    stdin: TextIO | None = None,
) -> int:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    target = resolve_target(namespace)
    setup_logging(log_file=log_file, verbose=namespace.verbose)
    stdin_stream: TextIO | None = None
    stdin_label: Path | None = None

    if namespace.list_patterns:
        if namespace.dashboard:
            print(
                "Error: --list-patterns cannot be combined with --dashboard",
                file=sys.stderr,
            )
            return 2
        config_root = target if target.exists() else Path.cwd()
        try:
            config_path = resolve_config_path(namespace.config, config_root)
            settings = (
                load_config_file(config_path)
                if config_path is not None
                else FileSettings()
            )
        except ConfigError as exc:
            get_logger().error("%s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        engine = merged_engine(settings.patterns)
        color = _use_color(namespace.no_color or (settings.no_color is True))
        render_pattern_list(engine, color=color)
        return 0

    if namespace.dashboard:
        if namespace.install_hook or namespace.update_baseline:
            print(
                "Error: --dashboard cannot be combined with --install-hook or --update-baseline",
                file=sys.stderr,
            )
            return 2
        if namespace.stdin:
            print(
                "Error: --dashboard cannot be combined with --stdin",
                file=sys.stderr,
            )
            return 2
        if namespace.quiet:
            print(
                "Error: --dashboard cannot be combined with --quiet",
                file=sys.stderr,
            )
            return 2
        if namespace.staged or namespace.changed or namespace.history or namespace.since:
            print(
                "Error: --dashboard cannot be combined with Git scan flags",
                file=sys.stderr,
            )
            return 2
        default_path = target if target.exists() else Path(".")
        return serve_dashboard(
            namespace,
            default_path=default_path,
            open_browser=not namespace.no_browser,
        )

    if namespace.stdin:
        if namespace.install_hook:
            print(
                "Error: --stdin cannot be combined with --install-hook",
                file=sys.stderr,
            )
            return 2
        if namespace.staged or namespace.changed or namespace.history or namespace.since:
            print(
                "Error: --stdin cannot be combined with Git scan flags",
                file=sys.stderr,
            )
            return 2
        stdin_stream = stdin if stdin is not None else sys.stdin
        if stdin_is_tty(stdin_stream):
            print("Error: --stdin requires piped input", file=sys.stderr)
            return 2
        stdin_label = stdin_virtual_path(namespace)
        target = Path.cwd()

    if not namespace.stdin and not target.exists():
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
    quiet = namespace.quiet or (settings.quiet is True)
    confidence_floor = resolve_min_confidence(namespace, settings)
    engine = merged_engine(settings.patterns)
    try:
        skip = resolve_skip_patterns(namespace, settings, engine)
    except SkipPatternError as exc:
        get_logger().error("%s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(
        config=build_scan_config(namespace, settings),
        engine=engine,
        skip_patterns=skip,
    )
    try:
        apply_ignore_file(scanner.config, namespace, target, settings)
        apply_baseline(scanner.config, namespace, target, settings)
        if namespace.stdin:
            assert stdin_stream is not None
            assert stdin_label is not None
            try:
                text = stdin_stream.read()
            except (OSError, UnicodeError) as exc:
                get_logger().error("Unable to read stdin: %s", exc)
                print(f"Error: {exc}", file=sys.stderr)
                return 2
            limit = scanner.config.max_file_size_bytes
            if limit is not None and len(text.encode("utf-8")) > limit:
                mib = limit // MIB if limit >= MIB else 0
                label = f"{mib} MiB" if mib else f"{limit} bytes"
                get_logger().error("stdin exceeds the %s size limit", label)
                print(f"Error: stdin exceeds the {label} size limit", file=sys.stderr)
                return 2
            result = scanner.scan_text(
                text, virtual_path=stdin_label, target=target
            )
        elif namespace.history:
            if namespace.history_depth < 1 or namespace.history_depth > 5000:
                raise GitError("history depth must be between 1 and 5000")
            root = repo_root(target)
            rows = list_history_lines(root, namespace.history_depth)
            scoped = [
                item
                for item in rows
                if path_in_target(item.relative_path, root, target.resolve())
            ]
            result = scanner.scan_history(scoped, target=target)
        elif namespace.since:
            root = repo_root(target)
            git_files = list_since_files(root, namespace.since)
            scoped = restrict_to_target(git_files, target.resolve())
            result = scanner.scan_paths(scoped, target=target)
        elif namespace.staged or namespace.changed:
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
        filter_findings(result.findings, minimum, confidence_floor),
        location_of=lambda item: item.location(root=target),
    )

    format_name = resolve_output_format(namespace, settings)

    try:
        if format_name == "json":
            emit_json(
                result,
                target,
                findings,
                namespace.output,
                reports_dir=reports_dir,
                quiet=quiet,
            )
        elif format_name == "sarif":
            emit_sarif(
                result,
                target,
                findings,
                namespace.output,
                reports_dir=reports_dir,
                quiet=quiet,
            )
        elif format_name == "html":
            emit_html(
                result,
                target,
                findings,
                namespace.output,
                reports_dir=reports_dir,
                quiet=quiet,
            )
        elif not quiet:
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
        if not quiet:
            print(f"Baseline updated: {written.as_posix()}")
        return 0

    if findings:
        return 1
    return 0
