# Secret Scanner

[![CI](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml)

A defensive Python CLI that scans a project directory (and Git staged/changed
files) for accidentally committed secrets: API keys, tokens, passwords,
private keys, cloud credentials, JWTs, and generic high-entropy assignments.

Built for **secret leakage prevention**. It is not an offensive security tool
and it is not a secret manager.

Detected values are **masked** in the terminal, JSON reports, and log files.
Plaintext secrets are never printed or written to disk.

## Why Secret Scanner?

Credentials in Git are a common incident: one `git push` can leak an AWS key,
a GitHub PAT, or a database URL to anyone with repo access (or to the public
internet). Rotation after the fact is mandatory; catching the leak *before*
or *right after* commit is cheaper.

This tool is a local / CI gate, not a replacement for vaults, IAM, or
`.gitignore`. Finding a secret is the start of incident response, not the end.

## Features

- Recursive directory scan with binary, size, and ignore rules
- Vendor format regexes plus contextual assignment analysis
- Placeholder filtering (documentation dummies are dropped)
- Shannon entropy as a supporting signal (not a standalone detector)
- Severity (CRITICAL → LOW) and confidence (5–99)
- Masked terminal output and JSON reports
- `--staged` / `--changed` Git modes
- Exit codes for CI (`0` clean, `1` findings, `2` error)
- File logging without secret values

## Detection Engine

The pipeline is **pattern + context + placeholder filter + entropy (gated)**.

1. **File discovery** — skip `.git`, `.venv`, `node_modules`, known binary
   extensions, files over 5 MiB, and lines longer than 100 000 characters.
   Hidden *directories* (`.github`) are skipped unless `--include-hidden`.
   Hidden *files* such as `.env` are still scanned.
2. **Format patterns** — public prefixes and shapes (`AKIA…`, `ghp_`, PEM
   headers, JWTs, Stripe keys, database URLs, …).
3. **Context** — sensitive names (`password`, `token`, `api_key`, …) with a
   long-enough value that has no vendor prefix.
4. **Placeholder filter** — `YOUR_API_KEY`, `changeme`, `example`, and similar
   dummies are ignored. The substring `test` alone is **not** treated as a
   dummy (staging keys must not be skipped).
5. **Entropy gate** — generic/contextual hits with very low randomness are
   dropped. Vendor formats are **format-locked**: a PEM header is English and
   low-entropy by design; it is still reported.

Entropy is never used alone. A minified JS bundle looks random; flagging every
high-entropy string would drown real leaks.

Confidence is a detection score (“how much does this look like a secret to
the detector?”), not proof that a credential is live or exploitable. It is
clamped to 5–99.

## Supported Secret Types

| Type | Severity |
|---|---|
| AWS Access Key ID | CRITICAL |
| Private Key (PEM / OpenSSH header) | CRITICAL |
| GitHub Token (`ghp_` / `gho_` / …) | HIGH |
| GitHub Fine-Grained Token (`github_pat_`) | HIGH |
| Google API Key | HIGH |
| Stripe API Key | HIGH |
| JWT | HIGH |
| Generic API Key assignment | HIGH |
| Database connection string | HIGH |
| Generic Password assignment | MEDIUM |
| Contextual Secret (sensitive name, unknown format) | MEDIUM |

Public key PEM headers are not treated as private keys.

## False Positives and False Negatives

Both are expected.

**False positive** — a documentation string, test fixture, or contextual
assignment that is not a live credential. Noisy, but usually easy to dismiss.

**False negative** — a novel vendor format, a secret split across lines, a
file skipped as binary/oversize, or a value that does not match any pattern.

This scanner does not validate credentials against AWS, GitHub, or any API.
A finding means “looks like a leak”; it does not mean “this key still works”.

## Installation

Python **3.11+**. Runtime is the standard library. `requirements.txt` is
**pytest only** (for development).

```text
git clone https://github.com/Dryhawell/secret-scanner.git
cd secret-scanner
python -m pip install -r requirements.txt
python main.py --help
```

`pip install` is optional if you only want to scan: `python main.py .`

## Usage

```text
python main.py [path] [options]
```

`path` defaults to the current directory.

| Flag | Meaning |
|---|---|
| `--severity LOW\|MEDIUM\|HIGH\|CRITICAL` | Minimum severity to report (default: LOW) |
| `--exclude NAME` | Extra directory name to skip (repeatable) |
| `--include-hidden` | Scan hidden directories such as `.github` (never `.git` / `.venv`) |
| `--staged` | Only files in the Git index (`git diff --cached`) |
| `--changed` | Working tree vs `HEAD`, plus untracked files |
| `--format text\|json` | Terminal text, or JSON under `reports/` |
| `--output FILE` / `-o -` | Write JSON to a file, or stdout |
| `--no-color` | Disable ANSI colors |
| `--verbose` | DEBUG per-file lines in the log file |

`--staged` and `--changed` are mutually exclusive. They require a Git repository
and the `git` executable. After a clean CI checkout, both lists are empty —
scan the committed tree (`python main.py .`) in pipelines.

## CLI Examples

```text
python main.py .
python main.py ./src
python main.py . --severity HIGH
python main.py . --exclude dist --exclude build
python main.py . --staged
python main.py . --changed
python main.py . --format json
python main.py . --output reports/latest.json
python main.py . --format json -o -
python main.py . --verbose --no-color
```

Example terminal output (values are **masked**; this is a fake AWS key ID):

```text
Secret Scanner

Target: ./example

Files scanned: 12
Lines scanned: 840
Potential secrets found: 2
Placeholders ignored: 1
By severity: CRITICAL=1  HIGH=1  MEDIUM=0  LOW=0

CRITICAL
config.py:17
AWS Access Key ID
Confidence: 98%
AKIA****************

HIGH
auth.py:52
GitHub Token
Confidence: 88%
ghp_************************************

Scan completed.
```

## JSON Reports

```text
python main.py . --format json
# Report written: reports/scan_YYYY-MM-DD_HHMM.json
```

`reports/*.json` is gitignored so a scan of your own tree cannot commit
findings. Payload shape (no plaintext `value` field):

```json
{
  "target": "...",
  "scan_time": "2026-08-29T09:00:00+00:00",
  "files_scanned": 142,
  "lines_scanned": 28421,
  "findings_count": 1,
  "placeholders_ignored": 5,
  "findings": [
    {
      "file_path": "config.py",
      "line_number": 17,
      "secret_type": "AWS Access Key ID",
      "severity": "CRITICAL",
      "confidence": 98,
      "masked_value": "AKIA****************",
      "description": "...",
      "pattern_name": "AWS Access Key ID",
      "timestamp": "..."
    }
  ]
}
```

## Security Considerations

- Terminal, JSON, and logs store **masked** values only. Logs record type,
  location, and severity — never the secret, not even masked.
- Tests use fake/placeholder credentials, often split string literals, never
  live keys.
- Scan only repositories and directories you own or have permission to audit.
- This is not a secret management system. It does not rotate, revoke, or
  store credentials.

If a **real** credential is found: treat it as compromised, **revoke and
rotate** it, then remove it from Git history if it was committed. A scanner
finding is not a complete incident response.

## CI/CD Integration

GitHub Actions workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

This repository’s pipeline:

1. Runs `pytest` on Python 3.11 and 3.12.
2. Scans **product code** (`--exclude tests --severity HIGH --include-hidden`).
   Test fixtures contain synthetic AWS/PEM values on purpose; an allowlist is
   not implemented yet.

Exit codes (the language of CI):

| Code | Meaning |
|---|---|
| 0 | No findings after severity filter |
| 1 | Findings reported — fail the job |
| 2 | Scanner error (missing path, not a Git repo, …) |

Example job for another project (stdlib only; no `pip` required to scan):

```yaml
- name: Secret scan
  run: python main.py . --no-color
```

A failing scan must not print live secrets into public Actions logs. This
CLI already masks values.

## Testing

```text
python -m pytest
```

The suite covers pattern matching, filters, context, confidence, entropy,
CLI exit codes, JSON reports, logging (no secret payload), Git staged/changed
mode, and the CI workflow file. All credentials in tests are fakes.

## Limitations

- Regex cannot know every secret format. New vendors will be missed until a
  pattern is added.
- Secrets split across lines, encoded, or stored only in Git history are out
  of scope for this version.
- Files larger than 5 MiB and skipped binaries are not scanned (false
  negatives by design, for performance).
- `--staged` does not scan untracked files; `--changed` does not equal
  “the whole repository”.
- No allowlist, baseline, YAML config, SARIF, HTML report, or pre-commit
  hook installer in this version.
- Detection is never 100% accurate.

## Architecture

```text
main.py                 entry point (exit code from cli)
cli/interface.py        argparse, text/JSON output, Git flags
scanner/
  file_handler.py       discovery, excludes, binary/size caps
  patterns.py           compiled regex catalog
  detector.py           line-by-line scan, masking
  context.py            sensitive assignments
  filters.py            placeholder / dummy values
  entropy.py            Shannon entropy (support signal)
  confidence.py         5–99 detection score
  severity.py           pattern → CRITICAL/HIGH/MEDIUM/LOW
  models.py             SecretFinding, ScanResult
  git_mode.py           staged / changed file lists
  scanner.py            orchestration
utils/logger.py         file logs, no secret values
utils/reporter.py       masked JSON
tests/                  pytest
.github/workflows/     CI
```

Runtime modules: `pathlib`, `re`, `json`, `argparse`, `logging`, `datetime`,
`dataclasses`, `subprocess` (Git). No network calls.

## Roadmap

Possible later work (not in the current tree):

- Git pre-commit hook installer
- YAML configuration and custom regexes
- Allowlist / baseline / ignore rules
- SARIF and HTML reports
- Git history scanning
- Parallel scanning
- GUI / dashboard

## Authorized / Responsible Use

Scan only repositories and directories you own or have **explicit permission**
to audit. Do not use this tool to search for credentials in systems you are not
authorized to access.

## License

[MIT](LICENSE)
