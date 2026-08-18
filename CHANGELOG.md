# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0]

### Added

- 33 new checks, taking the catalog from 58 to 91. Every new check ships with a positive test and a
  negative test that proves it stays silent on a hardened app.
  - Advanced injection: `web.command_injection` (OS command execution confirmed by an arithmetic
    oracle, not reflection), `web.xxe_injection` (two-stage entity expansion then external file
    read), `web.blind_sql_injection` (boolean differential confirmed across two SQL syntaxes),
    `web.lfi_wrappers` (PHP stream wrappers), `web.json_nosql_operators` (operator injection in
    JSON request bodies).
  - Exposure: `api.actuator_exposure` (Spring Boot actuator endpoints including heap dumps),
    `web.debug_info_pages` (phpinfo, server-status, Werkzeug console and friends),
    `web.backup_files` (editor and backup suffixes, suppressed when the copy matches the live file),
    `api.oidc_misconfig`, `api.soap_wsdl_exposure`.
  - Crypto and tokens: `web.jwt_weak_secret` (offline HMAC test against a built-in wordlist, costs
    the target no requests), `web.jwt_header_injection` (`jku`/`x5u`/`kid` abuse),
    `tls.certificate_strength` (key size, signature algorithm, validity window),
    `web.mixed_content`, `web.serialized_objects` (Java, PHP and ASP.NET ViewState blobs).
  - Infrastructure as code and supply chain: `whitebox.dockerfile_hardening`,
    `whitebox.compose_hardening`, `whitebox.k8s_workload_security`, `whitebox.terraform_exposure`,
    `whitebox.insecure_package_source`, `whitebox.actions_supply_chain` (pwn-request and script
    injection in GitHub Actions).
  - Source analysis: `whitebox.committed_key_material`, `whitebox.weak_crypto_usage`,
    `whitebox.sql_string_building`, `whitebox.auth_verification_disabled`.
  - Android: `apk.network_security_config`, `apk.provider_exposure`, `apk.backup_rules`,
    `apk.deeplink_surface`, `apk.signing_scheme` (v1-only Janus exposure, debug certificates),
    `apk.weak_crypto`, `apk.insecure_tls_code`, `apk.build_hardening`.
- `fya checks` lists the full catalog, with `--only <category>` to filter and `--json` for machine
  output.
- `--only` and `--skip` now accept an individual check id as well as a category, so
  `--only web.ssrf` or `--skip web.backup_files` works.
- A binary `AndroidManifest.xml` decoder, so the new manifest checks run without `androguard`
  installed.

### Changed

- `run_scan()` accepts an `exclude` set, and its `categories` argument now matches either a category
  or a single check id.
- CI gates on `mypy` in addition to `ruff` and the test suite.

### Fixed

- `web.json_nosql_operators` treated any sub-500 status change as evidence of injection, so an API
  that correctly rejected the operator object (a FastAPI/Pydantic 422, a DRF 400) was reported as
  vulnerable. It now requires the response to move toward success and reports a body-only
  differential at low confidence.
- `web.json_nosql_operators` picked its probe field from an unordered set, so whether the check
  fired at all varied with the interpreter hash seed.
- The false-positive control test covered only 8 checks; it now covers 23, including every new
  dynamic check.
- New checks' tests ran the whole battery per test, which made results depend on concurrent load
  and made the suite intermittently red. Each test now scopes its scan to the checks it exercises.
- `base_url()` and `Target.host` could be `None` and were passed on unguarded in the passive, SSRF
  and crawling checks.
- The scanner is now clean under `mypy` (45 modules, 0 errors).

## [0.5.1]

### Added

- A commercial-license notice in the CLI banner and `COMMERCIAL-LICENSE.md`.

## [0.5.0]

### Added

- 16 new attack techniques across the web, API, header and mobile areas.

### Changed

- Dual-licensed under PolyForm Noncommercial 1.0.0; commercial use requires a paid license.
- The website adapts to phones, with a hamburger section menu for the docs.

### Fixed

- 15 bugs found in an audit of the check implementations.

## [0.4.0]

### Added

- Black box, gray box and white box test strategies as switchable modes.
- A bundled Claude skill that performs the same methodology in a session with no package installed.
- A Next.js overview and documentation site, deployed from `web/`.

### Changed

- The package version is single-sourced from `fya/__init__.py`.

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
