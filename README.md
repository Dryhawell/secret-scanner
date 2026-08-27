# Secret Scanner

A defensive Python tool that scans a project directory for accidentally
committed secrets such as API keys, tokens, passwords, private keys, and
cloud credentials.

This project is built for **secure coding and secret leakage prevention**.
It is not an offensive security tool.

> Full documentation will be completed before v1.0.0. This README is a
> skeleton created during project initialization.

## Status

Phase 1 — project structure only. Scanning is not implemented yet.

## Authorized / Responsible Use

Scan only repositories and directories you own or have explicit permission
to audit. Do not use this tool to search for credentials in systems you
are not authorized to access.

## Security Considerations

- Detected secret values will be **masked** in terminal output and JSON reports.
- The scanner will never write plaintext secrets to disk by default.
- Tests will use fake placeholder values, never real credentials.
- Secret detection is never 100% accurate (false positives and false negatives
  are expected). Finding a secret is not enough: revoke and rotate it.

## License

MIT
