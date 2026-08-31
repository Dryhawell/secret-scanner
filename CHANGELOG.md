# Changelog

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
