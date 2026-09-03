# Changelog

## 1.36.0 — 2026-09-03

### Added

- GitHub Action input `exclude` (directory names, not globs; comma or newline separated; via env, not the shell)
- Flag-like names and path separators are rejected so they cannot become extra CLI flags

## 1.35.0 — 2026-09-03

### Added

- GitHub Action input `jobs` (empty = CLI default 1; `0` = CPU count; max 32; via env, not the shell)

## 1.34.0 — 2026-09-03

### Added

- GitHub Action inputs `glob` and `skip-glob` (comma or newline separated `fnmatch`; via env, not the shell)
- Flag-like patterns (leading `-`) are rejected by the same glob rules as the CLI

## 1.33.0 — 2026-09-03

### Added

- AWS Access Key ID also matches temporary `ASIA` prefixes (same CRITICAL rule)
- Built-in formats: age identities (`AGE-SECRET-KEY-1`), PlanetScale (`pscale_tkn_`),
  Postman API keys (`PMAK-`)

## 1.32.0 — 2026-09-03

### Added

- GitHub Action input `only-pattern` (allowlist; comma or newline separated; via env, not the shell)
- Combined with `skip-pattern` until no rules remain, the action still exits 2

## 1.31.0 — 2026-09-03

### Added

- GitHub Action input `skip-pattern` (comma or newline separated names; via env, not the shell)
- Flag-like names (leading `-`) are rejected so they cannot become extra CLI flags

## 1.30.0 — 2026-09-03

### Added

- GitHub Action input `min-confidence` (empty = CLI default 0; 0–99; via env, not the shell)

## 1.29.0 — 2026-09-02

### Added

- Scan summary counts NUL-sniffed binary skips (`files_skipped_binary`)
- Text, JSON, SARIF, and HTML reports surface the count (not a finding; exit 0)
- Known binary extensions and glob-excluded files are not counted

## 1.28.0 — 2026-09-02

### Added

- GitHub Action input `max-file-size` (empty = CLI default 5 MiB; `0` = unlimited; via env, not the shell)

## 1.27.0 — 2026-09-02

### Added

- Built-in formats: Anthropic (`sk-ant-`), Slack incoming webhooks,
  DigitalOcean (`dop_v1_` + hex), Stripe webhook secrets (`whsec_`)
- OpenAI `sk-` no longer matches Anthropic `sk-ant-`

## 1.26.0 — 2026-09-02

### Added

- GitHub Action input `fail-on-severity` (empty = same as `severity`; via env, not the shell)

## 1.25.0 — 2026-09-02

### Added

- `--fail-on-severity` is the CI exit gate (default: same as `--severity`)
- Config key `fail_on_severity`; CLI overrides. Findings below the gate can still be reported

## 1.24.0 — 2026-09-02

### Added

- `--sarif-file FILE` writes SARIF in addition to the selected `--format`
- GitHub Action inputs `sarif` / `sarif-file` (upload is opt-in; needs `security-events: write`)

## 1.23.0 — 2026-09-02

### Added

- Scan summary counts oversized skipped files (`files_skipped_oversized`)
- Text, JSON, SARIF, and HTML reports surface the count (not a finding; exit 0)

## 1.22.0 — 2026-09-02

### Added

- `--max-file-size N` skips files (and stdin) larger than N mebibytes
- Config key `max_file_size` (0 = unlimited, default 5, max 1024); CLI overrides

## 1.21.0 — 2026-09-01

### Added

- `--only-pattern NAME` runs an allowlist of rules (repeatable; case-insensitive)
- Config key `only_patterns`; combined with `--skip-pattern` an empty set exits 2

## 1.20.0 — 2026-09-01

### Added

- `--list-patterns` prints rule names (no regexes) and exits 0 without scanning
- `--skip-pattern NAME` disables a rule (repeatable; names are case-insensitive)
- Config key `skip_patterns`; skipping every rule exits 2

## 1.19.0 — 2026-09-01

### Added

- `--min-confidence N` hides findings below a detection-confidence floor (0–99)
- Config key `min_confidence`; CLI overrides the file
- This is a report filter, not a detector change (same idea as `--severity`)

## 1.18.0 — 2026-09-01

### Added

- `--quiet` / `-q` suppresses the text report (exit code still 1 on findings)
- Errors and `--output -` are not suppressed
- Config key `quiet`; GitHub Action input `quiet` (default false)

## 1.17.0 — 2026-09-01

### Added

- `--glob` / `--skip-glob` file patterns (`*.env`, `src/*.py`)
- Config keys `glob` and `skip_glob`
- `--exclude` stays a directory *name*; globs do not re-enter `node_modules`

## 1.16.0 — 2026-09-01

### Added

- Built-in formats: SendGrid (`SG.`), Twilio (`SK` + hex), Discord webhooks,
  Azure Storage `AccountKey=`, Shopify (`shpat_` / …), Telegram bots
- New vendor rules are format-locked (entropy does not drop them)

## 1.15.0 — 2026-09-01

### Added

- GitHub composite action (`action.yml`) for `uses: Dryhawell/secret-scanner@v1.15.0`
- Inputs go through env vars (path cannot add extra CLI flags)
- This repository's secret-scan job dogfoods `uses: ./`

## 1.14.0 — 2026-09-01

### Added

- `--stdin` scans a piped buffer in memory (no temp file)
- Interactive TTY is refused (exit 2); same 5 MiB size cap as files
- Mutually exclusive with Git scan flags, `--dashboard`, and `--install-hook`

## 1.13.0 — 2026-08-31

### Added

- Built-in formats: GitLab (`glpat-`), Slack (`xoxb-` / …), npm, Hugging Face (`hf_`),
  OpenAI (`sk-`, not Stripe `sk_`), PyPI (`pypi-`)
- New vendor rules are format-locked (entropy does not drop them)

## 1.12.0 — 2026-08-31

### Added

- `--since REF` scans files in `git diff REF...HEAD` (PR / branch delta)
- Untracked files are not included; unknown refs exit 2
- Mutually exclusive with `--staged`, `--changed`, and `--history`

## 1.11.0 — 2026-08-31

### Added

- Inline `secret-scanner:ignore` on the same line drops findings (counted as allowlist)
- Optional pattern name: `secret-scanner:ignore AWS Access Key ID`
- Marker does not apply to other lines

## 1.10.0 — 2026-08-31

### Added

- `--dashboard` localhost HTML UI (`127.0.0.1` only, no JavaScript)
- `--port` (default 8765) and `--no-browser`
- CSRF token on POST /scan; Host must be loopback
- Working-tree scans from the form; CLI Git flags stay exclusive

## 1.9.0 — 2026-08-31

### Added

- `--jobs` / `-j` worker threads for working-tree and staged/changed scans
- Config key `jobs` (0 = CPU count, default 1, max 32)
- Finding order stays the file-discovery order (not completion order)

## 1.8.0 — 2026-08-31

### Added

- `--history` scans added lines in recent Git commits (`git log -p`)
- `--history-depth` (default 200, max 5000)
- Findings include a `commit` field; location is `sha:path:line`
- Does not rewrite history; rotate leaked credentials

## 1.7.0 — 2026-08-31

### Added

- `--format html` self-contained report (no JS, no source snippets)
- `--output file.html` infers HTML
- HTML-escaped paths and values (XSS-safe for hostile filenames)

## 1.6.0 — 2026-08-31

### Added

- `--format sarif` (SARIF 2.1.0) for GitHub Code Scanning
- `--output file.sarif` infers SARIF
- Reports omit source snippets and plaintext secrets

## 1.5.0 — 2026-08-31

### Added

- `patterns` in the project config: custom regexes that extend the built-in catalog
- YAML list-of-mapping support for those pattern objects
- Compile-time checks: invalid regex, empty-string match, reserved/duplicate names

## 1.4.0 — 2026-08-31

### Added

- `.secret-scanner.json` / `.yml` project config (`--config`)
- Restricted YAML subset parser (stdlib only; no PyYAML)
- Config keys: `severity`, `exclude`, `include_hidden`, `no_color`, `verbose`,
  `format`, `ignore_file`, `baseline`
- CLI flags override file values; unknown keys exit 2

## 1.3.0 — 2026-08-29

### Added

- Committed `hooks/pre-commit` template (scans staged files, blocks on findings)
- `python main.py --install-hook` copies the template into `.git/hooks/pre-commit`
- `--force-hook` overwrites an existing hook

## 1.2.0 — 2026-08-29

### Added

- SHA-256 finding fingerprints (`secret_id`) computed at detection time
- `.secret-scanner-baseline.json` plus `--baseline` / `--update-baseline`
- `baseline_ignored` in scan results and JSON reports

## 1.1.0 — 2026-08-29

### Added

- `.secret-scanner-ignore` path skips and `path | Pattern Name` finding rules
- `--ignore-file` (exit 2 if the explicit file is missing)
- `allowlist_ignored` in scan results and JSON reports

### Changed

- CI product scan uses the ignore file instead of `--exclude tests --severity HIGH`

## 1.0.0 — 2026-08-29

First stable release. Defensive secret scanner for local trees and CI.

### Added

- Directory and file discovery with binary, size, and ignore rules
- Format patterns (AWS, GitHub, Google, Stripe, JWT, PEM, DB URLs, generic assignments)
- Context analysis, placeholder filtering, confidence scoring, Shannon entropy as a support signal
- Masked terminal output and JSON reports (no plaintext secrets)
- File logging without secret values
- `--staged` / `--changed` Git modes
- GitHub Actions: pytest (3.11 / 3.12) and product-code scan
- CLI exit codes: `0` clean, `1` findings, `2` error
- `--version`

### Security

- Detected values are masked in the terminal and JSON
- Logs record type, location, and severity only
- Tests use fake credentials only
