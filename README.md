# Secret Scanner

[![CI](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml)

A defensive Python CLI that scans a project directory (and Git staged/changed
files) for accidentally committed secrets: API keys, tokens, passwords,
private keys, cloud credentials, JWTs, and generic high-entropy assignments.

Built for **secret leakage prevention**. It is not an offensive security tool
and it is not a secret manager.

Detected values are **masked** in the terminal, JSON reports, and log files.
Plaintext secrets are never printed or written to disk.

**v1.4.0** — Python 3.11+. Runtime is the standard library (`pytest` is for development only).

```text
python main.py --version
# Secret Scanner 1.4.0
```

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
- Path / finding allowlist (`.secret-scanner-ignore`)
- Hashed finding baseline (SHA-256, no plaintext)
- Optional local Git pre-commit hook (`--install-hook`)
- JSON / subset-YAML project config (`--config`)
- File logging without secret values
- Exit codes for CI (`0` clean, `1` findings, `2` error)

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
| `--ignore-file FILE` | Allowlist (default: `.secret-scanner-ignore` if present) |
| `--baseline FILE` | Hashed baseline JSON (default: `.secret-scanner-baseline.json` if present) |
| `--update-baseline` | Merge current findings into the baseline and exit 0 |
| `--install-hook` | Copy `hooks/pre-commit` into `.git/hooks/pre-commit` |
| `--force-hook` | Overwrite an existing hook |
| `--config FILE` | JSON or YAML project config (default: `.secret-scanner.json` / `.yml`) |
| `--version` | Print the version and exit |

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
python main.py --version
python main.py . --ignore-file .secret-scanner-ignore
python main.py . --update-baseline
python main.py . --baseline .secret-scanner-baseline.json
python main.py --install-hook
python main.py . --config .secret-scanner.json
```

## Ignore rules

`.secret-scanner-ignore` skips **reporting**. It is not `.gitignore`. Use it
for fixtures and known false positives, not live credentials.

```text
# Skip a directory tree (test fixtures with fake keys).
tests/

# Still scan the file; drop only this finding type.
scanner/detector.py | Contextual Secret
```

`path | Pattern Name` does not hide other types on that file. An AWS key in
`scanner/detector.py` is still reported.

`--ignore-file` must exist when given (exit `2` if missing). Without the flag,
the scanner loads `.secret-scanner-ignore` next to the target, or from the
current directory when that directory is a parent of the target.

## Baseline

Ignore skips a **path**. Baseline skips a **specific hashed value in a file**.
A new key in the same file still fails. The same value copied to another file
still fails.

```text
python main.py . --update-baseline
python main.py . --baseline .secret-scanner-baseline.json
```

The file stores SHA-256 fingerprints plus a masked prefix — never the
plaintext secret. The default filename is not scanned as source. Review
findings before updating. Rotating a real credential is still required; the
baseline only means “we already triaged this hash.”

## Project config

Commit a `.secret-scanner.json` (preferred) or `.secret-scanner.yml` next
to the scan root. `--config FILE` must exist when given (exit `2` if missing).
CLI flags override the file. Relative `ignore_file` / `baseline` paths are
resolved from the config file's directory.

JSON:

```json
{
  "severity": "HIGH",
  "exclude": ["dist", "build"],
  "include_hidden": false,
  "no_color": true,
  "format": "text",
  "ignore_file": ".secret-scanner-ignore",
  "baseline": ".secret-scanner-baseline.json"
}
```

YAML is a **restricted subset** (no PyYAML): `key: value`, booleans, `#`
comments, and indented dash lists. Anchors, tags, and nested maps are
rejected. Unknown keys fail the run (exit `2`). Custom regexes are not in
this schema yet.

Default config filenames are not scanned as source.

## Pre-commit hook

The committed file `hooks/pre-commit` is a template. Git does not run it until
it is copied into `.git/hooks/pre-commit` (that copy is local and is not
committed).

```text
python main.py --install-hook
python main.py --install-hook --force-hook
```

The hook runs `python main.py . --staged --no-color` from the repository root.
Untracked files are not scanned. Exit `1` from the scanner blocks the commit.

This is a local convenience, not a security control. Anyone can skip it with
`git commit --no-verify`. Keep the CI product scan.

## Example terminal output

Example terminal output (values are **masked**; this is a fake AWS key ID):

```text
Secret Scanner

Target: ./example

Files scanned: 12
Lines scanned: 840
Potential secrets found: 2
Placeholders ignored: 1
Allowlist ignored: 0
Baseline ignored: 0
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
      "secret_type": "AwsAccessKeyId",
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
2. Scans the tree (`--include-hidden`) using [`.secret-scanner-ignore`](.secret-scanner-ignore)
   so test fixtures and a known contextual false positive are skipped. A real
   vendor-format key in product code still fails the job.

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
mode, the hook installer, project config files, and the CI workflow file. All credentials in tests are fakes.

## Limitations

- Regex cannot know every secret format. New vendors will be missed until a
  pattern is added.
- Secrets split across lines, encoded, or stored only in Git history are out
  of scope for this version.
- Files larger than 5 MiB and skipped binaries are not scanned (false
  negatives by design, for performance).
- `--staged` does not scan untracked files; `--changed` does not equal
  “the whole repository”.
- Allowlist is path/finding-name based. An ignored path will not report a newly
  added live key. Baseline hashes a specific value in a file; it is not a
  substitute for rotation.
- The pre-commit hook is local and bypassable (`git commit --no-verify`).
  It is not a substitute for CI.
- YAML config is a documented subset, not a full YAML 1.1 parser. There is
  no custom regex catalog in this version.
- No SARIF or HTML report in this version.
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
  ignore.py             path / finding allowlist
  fingerprint.py        SHA-256 secret id (no plaintext)
  baseline.py           hashed finding baseline
  hook.py               copy template into .git/hooks
  config_file.py        JSON / subset-YAML project config
  scanner.py            orchestration
utils/logger.py         file logs, no secret values
utils/reporter.py       masked JSON
hooks/pre-commit         committed hook template
tests/                  pytest
.github/workflows/     CI
```

Runtime modules: `pathlib`, `re`, `json`, `argparse`, `logging`, `datetime`,
`dataclasses`, `subprocess` (Git), `hashlib`. No network calls.

## Roadmap

Possible later work (not in the current tree):

- Custom detection regexes
- SARIF and HTML reports
- Git history scanning
- Parallel scanning
- GUI / dashboard

## Authorized / Responsible Use

Scan only repositories and directories you own or have **explicit permission**
to audit. Do not use this tool to search for credentials in systems you are not
authorized to access.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
