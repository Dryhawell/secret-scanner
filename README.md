# Secret Scanner

[![CI](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Dryhawell/secret-scanner/actions/workflows/ci.yml)

A defensive Python CLI that scans a project directory, Git staged/changed
files, recent Git history, or a piped stdin buffer for accidentally committed
secrets: API keys, tokens, passwords, private keys, cloud credentials, JWTs,
and generic high-entropy assignments.

Built for **secret leakage prevention**. It is not an offensive security tool
and it is not a secret manager.

Detected values are **masked** in the terminal, JSON reports, and log files.
Plaintext secrets are never printed or written to disk.

**v1.18.0** — Python 3.11+. Runtime is the standard library (`pytest` is for development only).

```text
python main.py --version
# Secret Scanner 1.18.0
```

## Why Secret Scanner?

Credentials in Git are a common incident: one `git push` can leak an AWS key,
a GitHub PAT, or a database URL to anyone with repo access (or to the public
internet). Rotation after the fact is mandatory; catching the leak *before*
or *right after* commit is cheaper.

This tool is a local / CI gate, not a replacement for vaults, IAM, or
`.gitignore`. Finding a secret is the start of incident response, not the end.

## Features

- Recursive directory scan with binary, size, ignore, and file glob rules
- Vendor format regexes plus contextual assignment analysis
- Placeholder filtering (documentation dummies are dropped)
- Shannon entropy as a supporting signal (not a standalone detector)
- Severity (CRITICAL → LOW) and confidence (5–99)
- Masked terminal output, JSON, SARIF 2.1.0, and HTML reports
- `--staged` / `--changed` Git modes, `--history` for recent commits, `--since` for a branch delta
- `--stdin` piped buffer (no temp file)
- GitHub composite action (`uses: Dryhawell/secret-scanner@v1.18.0`)
- `--jobs` worker threads for file scans (default 1)
- Localhost HTML dashboard (`--dashboard`)
- Path / finding allowlist (`.secret-scanner-ignore`) and inline `secret-scanner:ignore`
- Hashed finding baseline (SHA-256, no plaintext)
- Optional local Git pre-commit hook (`--install-hook`)
- JSON / subset-YAML project config (`--config`)
- Custom detection regexes in that config (`patterns`)
- File logging without secret values
- Exit codes for CI (`0` clean, `1` findings, `2` error)
- `--quiet` / `-q` (text report off; exit code unchanged)

## Detection Engine

The pipeline is **pattern + context + placeholder filter + entropy (gated)**.

1. **File discovery** — skip `.git`, `.venv`, `node_modules`, known binary
   extensions, files over 5 MiB, and lines longer than 100 000 characters.
   Hidden *directories* (`.github`) are skipped unless `--include-hidden`.
   Hidden *files* such as `.env` are still scanned.
2. **Format patterns** — public prefixes and shapes (`AKIA…`, `ghp_`, `glpat-`,
   `xoxb-`, `npm_`, `hf_`, `sk-`, `SG.`, `shpat_`, PEM headers, JWTs, Stripe
   `sk_live_`, Azure `AccountKey=`, Discord webhooks, …).
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
| GitLab Token (`glpat-`) | HIGH |
| Slack Token (`xoxb-` / `xoxp-` / …) | HIGH |
| npm Token (`npm_`) | HIGH |
| Hugging Face Token (`hf_`) | HIGH |
| OpenAI API Key (`sk-`, not Stripe `sk_`) | HIGH |
| PyPI Token (`pypi-`) | HIGH |
| SendGrid API Key (`SG.`) | HIGH |
| Twilio API Key (`SK` + hex, not Stripe `sk_` / OpenAI `sk-`) | HIGH |
| Discord Webhook URL | HIGH |
| Azure Storage Account Key (`AccountKey=`) | CRITICAL |
| Shopify Token (`shpat_` / `shpss_` / …) | HIGH |
| Telegram Bot Token | HIGH |
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
| `--exclude NAME` | Extra directory name to skip (repeatable), not a file glob |
| `--glob PATTERN` | Only files matching this glob (repeatable). `*.env` is the name in any folder |
| `--skip-glob PATTERN` | Skip matching files (repeatable). Applied after `--glob` |
| `--include-hidden` | Scan hidden directories such as `.github` (never `.git` / `.venv`) |
| `--staged` | Only files in the Git index (`git diff --cached`) |
| `--changed` | Working tree vs `HEAD`, plus untracked files |
| `--history` | Scan added lines in recent Git commits (not the working tree) |
| `--history-depth N` | How many recent commits `--history` reads (default: 200, max 5000) |
| `--since REF` | Files changed since REF (`git diff REF...HEAD`, not untracked) |
| `--jobs N` / `-j N` | Worker threads for file scans (default: 1, `0` = CPU count, max 32) |
| `--stdin` | Scan text from stdin (pipe). Does not write the buffer to disk |
| `--dashboard` | Localhost HTML dashboard (`127.0.0.1` only) |
| `--port N` | Dashboard port (default: 8765) |
| `--no-browser` | Do not open a browser when the dashboard starts |
| `--format text\|json\|sarif\|html` | Terminal text, JSON, SARIF 2.1.0, or HTML under `reports/` |
| `--output FILE` / `-o -` | Write JSON, SARIF, or HTML to a file, or stdout |
| `--no-color` | Disable ANSI colors |
| `--quiet` / `-q` | Suppress the text report (exit code still 1 on findings) |
| `--verbose` | DEBUG per-file lines in the log file |
| `--ignore-file FILE` | Allowlist (default: `.secret-scanner-ignore` if present) |
| `--baseline FILE` | Hashed baseline JSON (default: `.secret-scanner-baseline.json` if present) |
| `--update-baseline` | Merge current findings into the baseline and exit 0 |
| `--install-hook` | Copy `hooks/pre-commit` into `.git/hooks/pre-commit` |
| `--force-hook` | Overwrite an existing hook |
| `--config FILE` | JSON or YAML project config (default: `.secret-scanner.json` / `.yml`) |
| `--version` | Print the version and exit |

`--staged`, `--changed`, `--history`, and `--since` are mutually exclusive. They
require a Git repository and the `git` executable. After a clean CI checkout,
staged and changed lists are empty — scan the committed tree (`python main.py .`)
in pipelines. `--history` walks `git log -p` for the last N commits; deleting a
file in HEAD does not hide the commit that introduced it. `--since origin/main`
scans only files in the PR delta (`origin/main...HEAD`); fetch the base ref
first (`fetch-depth: 0`). `--dashboard` cannot be combined with those Git flags,
`--stdin`, `--install-hook`, `--update-baseline`, or `--quiet`. `--stdin` cannot be
combined with those Git flags, `--dashboard`, or `--install-hook`. A TTY
(no pipe) with `--stdin` exits 2.

## CLI Examples

```text
python main.py .
python main.py ./src
python main.py . --severity HIGH
python main.py . --exclude dist --exclude build
python main.py . --glob "*.env" --glob "*.py"
python main.py . --skip-glob "*.min.js"
python main.py . --quiet
python main.py . --staged
python main.py . --changed
python main.py . --history
python main.py . --history --history-depth 500
python main.py . --since origin/main
python main.py --stdin
python main.py leak.py --stdin
Get-Content app.py -Raw | python main.py --stdin
python main.py . --jobs 4
python main.py --dashboard
python main.py --dashboard --no-browser --port 8765
python main.py . --format json
python main.py . --output reports/latest.json
python main.py . --format json -o -
python main.py . --format sarif
python main.py . --output reports/latest.sarif
python main.py . --format html
python main.py . --output reports/latest.html
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

### Inline ignore

Put `secret-scanner:ignore` on the **same line** as a known false positive.
That line's findings are dropped and counted under allowlist. Other lines
in the file are unchanged.

```text
# Same line as the assignment (not the line above):
#     ...  # secret-scanner:ignore
#     ...  # secret-scanner:ignore AWS Access Key ID
```

A typed marker (`secret-scanner:ignore AWS Access Key ID`) drops only that
pattern on that line. A live credential on an ignored line is also hidden —
same risk as a path allowlist. Prefer rotating real secrets; do not use
inline ignore to keep a live key in source.

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
resolved from the config file's directory. `jobs` is a worker-thread count
(`0` = CPU count).

JSON:

```json
{
  "severity": "HIGH",
  "exclude": ["dist", "build"],
  "glob": ["*.py", "*.env"],
  "skip_glob": ["*.min.js"],
  "include_hidden": false,
  "no_color": true,
  "quiet": false,
  "format": "text",
  "ignore_file": ".secret-scanner-ignore",
  "baseline": ".secret-scanner-baseline.json",
  "jobs": 4,
  "patterns": [
    {
      "name": "Internal Token",
      "regex": "intok_[A-Za-z0-9]{16}",
      "severity": "HIGH",
      "description": "Company-internal token prefix"
    }
  ]
}
```

YAML is a **restricted subset** (no PyYAML): `key: value`, booleans, `#`
comments, indented dash lists, and a list of flat mappings for `patterns`.
Anchors, tags, and deeper nesting are rejected. Unknown keys fail the run
(exit `2`).

Custom `patterns` **extend** the built-in catalog. They cannot reuse a
built-in name (including `Contextual Secret`). A regex that matches the
empty string is rejected. Invalid regex → exit `2`. Keep patterns specific:
`.+` will match whole lines and is noisy; some regexes can also be slow
(catastrophic backtracking).

YAML:

```text
patterns:
  - name: Internal Token
    regex: intok_[A-Za-z0-9]{16}
    severity: HIGH
```

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
findings. `reports/*.sarif` is gitignored the same way. Payload shape (no plaintext `value` field):

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

## SARIF reports

SARIF 2.1.0 is what GitHub Code Scanning (and many IDEs) ingest.

```text
python main.py . --format sarif
python main.py . --output reports/latest.sarif
```

`reports/*.sarif` is gitignored. The document has **no source snippets**
and no plaintext secret: a snippet would copy the original line into the
code scanning API. Messages use the masked value. `partialFingerprints`
store the SHA-256 finding id, not the secret.

Upload example (does not replace the product-code scan job):

```yaml
- name: Secret scan (SARIF)
  run: python main.py . --no-color --format sarif --output reports/scan.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/scan.sarif
```

## HTML reports

A self-contained page for humans (open the file in a browser). No CDN, no
JavaScript, no source snippets. Paths, types, and masked values are
HTML-escaped so a hostile filename cannot inject a script.

```text
python main.py . --format html
python main.py . --output reports/latest.html
```

`reports/*.html` is gitignored. HTML is not a CI signal: exit codes still
come from the scanner process. Do not email or publish a report if you
are unsure it is masked; this tool only writes masked values.

## Dashboard

`python main.py --dashboard` serves a **localhost-only** HTML form at
`http://127.0.0.1:8765/`. It is not bound on `0.0.0.0`. There is no
JavaScript. POST `/scan` requires the CSRF token from the form. The Host
header must be loopback. Paths that look like URLs are rejected.

The dashboard runs a working-tree scan (the same engine as `python main.py PATH`).
Use the CLI for `--staged`, `--changed`, `--history`, `--since`, and `--stdin`. Do not expose this
port on a network or reverse-proxy it to the internet.

```text
python main.py --dashboard
python main.py --dashboard --no-browser --port 8765
```

## Security Considerations

- Terminal, JSON, SARIF, HTML, dashboard, and logs store **masked** values only. Logs record type,
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
Composite action: [`action.yml`](action.yml).

This repository’s pipeline:

1. Runs `pytest` on Python 3.11 and 3.12.
2. Scans the tree via `uses: ./` (`include-hidden: true`) using
   [`.secret-scanner-ignore`](.secret-scanner-ignore) so test fixtures and a known
   contextual false positive are skipped. A real vendor-format key in product
   code still fails the job.

Exit codes (the language of CI):

| Code | Meaning |
|---|---|
| 0 | No findings after severity filter |
| 1 | Findings reported — fail the job |
| 2 | Scanner error (missing path, not a Git repo, …) |

Other repositories (pin a **tag**, not `@main`):

```yaml
permissions:
  contents: read
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: Dryhawell/secret-scanner@v1.18.0
        with:
          include-hidden: true
```

Inputs: `path` (default `.`), `include-hidden`, `severity`, `python-version`,
`quiet` (default false; keep false so masked findings stay in the job log).
The action always passes `--no-color` (Actions logs). It does not run
`--dashboard`, `--update-baseline`, `--stdin`, or Git scan flags. Put extra
policy in `.secret-scanner.json` / `.secret-scanner-ignore` in *your* repo.

Without the action, if this tree is already checked out:

```yaml
- name: Secret scan
  run: python main.py . --no-color
```

PR-only delta (does **not** replace a full-tree product scan; secrets in
untouched files are missed). Fetch the base branch:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- name: Secret scan (PR files)
  run: python main.py . --no-color --since origin/${{ github.base_ref }}
```

A failing scan must not print live secrets into public Actions logs. This
CLI already masks values.

## Testing

```text
python -m pytest
```

The suite covers pattern matching, filters, context, confidence, entropy,
CLI exit codes, JSON reports, logging (no secret payload), Git staged/changed
and history modes, `--since` deltas, `--stdin`, the GitHub composite action, file globs, `--quiet`, parallel file scans, the localhost dashboard, the hook
installer, project config files, custom patterns, SARIF and HTML reports, and
the CI workflow file. All credentials in tests are fakes.

## Limitations

- Regex cannot know every secret format. New vendors will be missed until a
  pattern is added.
- Secrets split across lines or encoded (base64 without a known prefix) are
  still missed. `--history` only sees **added** (`+`) lines in `git log -p`
  for the last `--history-depth` commits (newest first). A leak older than
  that window is a false negative.
- `--history` is not a history rewriter. Finding a secret in a commit means
  **rotate** the credential. `git filter-repo` / force-push is incident
  response, not a scanner feature.
- Merge commits often have an empty default patch; a blob introduced only in
  a merge may be missed.
- Files larger than 5 MiB and skipped binaries are not scanned (false
  negatives by design, for performance).
- `--glob` / `--skip-glob` use `fnmatch`, not gitignore. A name pattern
  (`*.py`) matches the file name in any folder. A pattern with `/` is
  relative to the scan root; `*` there can match across directories.
  Excluded directories (`node_modules`, `--exclude dist`) are never
  walked, so a glob cannot re-include them.
- `--staged` does not scan untracked files; `--changed` does not equal
  “the whole repository”. `--since REF` only lists `REF...HEAD`; a leak
  that already sat on the base branch and was not edited is skipped.
  Shallow clones without the base ref make `--since` exit 2.
- Allowlist is path/finding-name based, plus same-line `secret-scanner:ignore`.
  An ignored path or line will not report a newly added live key. Baseline
  hashes a specific value in a file; it is not a substitute for rotation.
- The pre-commit hook is local and bypassable (`git commit --no-verify`).
  It is not a substitute for CI.
- YAML config is a documented subset, not a full YAML 1.1 parser.
- Custom regexes cannot replace built-in rules. A broad pattern will
  create noise; a regex that matches the empty string is rejected.
- SARIF reports omit source snippets so GitHub Code Scanning cannot leak
  the original line. HTML reports are escaped and also omit snippets.
- `--jobs` uses threads (`concurrent.futures`). CPython's GIL means regex
  matching does not scale linearly with cores; overlapping file reads still
  help. Default is 1 (same as a sequential scan). `--history` and `--stdin` stay
  single-threaded.
- `--stdin` scans one in-memory buffer, not a repository walk. A TTY is
  refused (exit 2). The same 5 MiB cap as files applies.
- Detection is never 100% accurate.
- `--dashboard` is a local helper, not a multi-user app. It does not scan
  Git history. Binding is loopback-only; do not publish the port.
- `--quiet` hides finding locations from the terminal. The exit code still
  fails the job; use JSON/SARIF or omit `--quiet` when triaging.
- The GitHub composite action scans the **caller workspace** after checkout.
  Pin a release tag (or commit SHA). `uses: ./` is only for this repository.
  It does not upload SARIF and does not grant extra `permissions`.

## Architecture

```text
main.py                 entry point (exit code from cli)
cli/interface.py        argparse, text/JSON output, Git flags, --stdin, --quiet
cli/github_action.py    composite-action argv (env → CLI, --no-color)
cli/dashboard.py        localhost HTML dashboard (127.0.0.1)
scanner/
  file_handler.py       discovery, excludes, globs, binary/size caps
  patterns.py           compiled regex catalog (plus config custom patterns)
  detector.py           line-by-line scan, masking
  context.py            sensitive assignments
  filters.py            placeholder / dummy values
  entropy.py            Shannon entropy (support signal)
  confidence.py         5–99 detection score
  severity.py           pattern → CRITICAL/HIGH/MEDIUM/LOW
  models.py             SecretFinding, ScanResult
  git_mode.py           staged / changed / since file lists, history patch
  history.py            parse git log -p added lines
  ignore.py             path / finding allowlist and inline markers
  fingerprint.py        SHA-256 secret id (no plaintext)
  baseline.py           hashed finding baseline
  hook.py               copy template into .git/hooks
  config_file.py        JSON / subset-YAML project config (including patterns)
  scanner.py            orchestration (optional thread pool for files; stdin/history stay sequential)
utils/logger.py         file logs, no secret values
utils/reporter.py       masked JSON
utils/sarif.py          SARIF 2.1.0 (no snippets)
utils/html_report.py    self-contained HTML (escaped, no snippets)
hooks/pre-commit         committed hook template
action.yml              GitHub composite action (repo root)
tests/                  pytest
.github/workflows/     CI
```

Runtime modules: `pathlib`, `re`, `json`, `argparse`, `logging`, `datetime`,
`dataclasses`, `subprocess` (Git), `hashlib`, `concurrent.futures`,
`http.server` (dashboard, 127.0.0.1 only). No outbound network calls.

## Roadmap

The original feature list for this tree is implemented. Later work would be
new product ideas, not a listed gap.

## Authorized / Responsible Use

Scan only repositories and directories you own or have **explicit permission**
to audit. Do not use this tool to search for credentials in systems you are not
authorized to access.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
