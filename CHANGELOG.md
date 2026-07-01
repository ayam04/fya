# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0]

### Added

- Authenticated scanning: pass credentials to reach protected surfaces with `--header`, `--cookie`, and `--bearer`.
- Scope controls to keep scans focused and bounded: `--include`, `--exclude`, and `--max-requests`.
- Baseline suppression: record known findings with `--write-baseline` and hide them on later runs with `--baseline`.
- Scan modes and live progress reporting (promoted from 0.2.0) integrated with the new controls.
- New checks: JWT weaknesses, Content-Security-Policy weakness analysis, outdated JavaScript libraries, and `security.txt` / `robots.txt` discovery.
- Optional Playwright-based SPA crawler for JavaScript-rendered applications (install with the `browser` extra).
- SARIF output improvements: stable per-finding fingerprints and inline rule help text.
- Entry-point plugin support so third-party packages can register checks under the `fya.checks` group.
- `py.typed` marker and a mypy configuration for typed downstream use.

### Fixed

- Audit-driven false-positive and robustness fixes:
  - Reflected XSS now reports a calibrated confidence instead of a flat value.
  - SSTI detection uses a baseline request plus a two-factor confirmation before reporting.
  - CSRF detection is aware of `SameSite` cookies and CSRF meta tags.
  - CORS wildcard reporting is more accurate and no longer flags safe reflected origins.
  - Verbose-error detection compares against a baseline to cut noise.
  - sqlmap precedence is honored when both native and external results are available.
  - External tools capture partial output on timeout rather than discarding it.
  - TLS certificate parsing now uses the `cryptography` library for correctness.
  - APK analysis detects implicitly exported components, not just explicitly exported ones.

## [0.2.1]

### Fixed

- Corrected profile gating so passive checks no longer run under stricter profiles unintentionally.
- Hardened HTTP client handling of malformed responses and redirect loops.
- Stabilized report ordering for deterministic output across runs.

## [0.2.0]

### Added

- Scan modes (passive, safe, aggressive) with per-check profile gating.
- Live progress reporting during a scan.
- JSON and Markdown report writers.

### Changed

- Reworked the check registry to auto-discover bundled checks.

## [0.1.0]

### Added

- Initial release: dynamic security scanner for localhost web servers and Android APKs.
- Passive web checks: security headers, server version disclosure, and insecure cookie flags.
- Command-line interface with target parsing for web and APK kinds.
