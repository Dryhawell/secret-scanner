# Changelog

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
