# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: developers and small engineering teams who own a web app, an Android
APK, or a source tree and run fya themselves against targets they control,
localhost first. They understand OWASP and CWE, value proof over remediation
theater, and respond to the tool's confidence as much as its evidence.
Secondary: CI pipelines that gate merges on `--fail-on`, and maintainers who
add checks.

## Product Purpose

fya finds holes in the user's app before someone else does. Success is a
developer pointing fya at a target they own and walking away with a report in
which every finding is proven by the exact request that triggered it, mapped
to OWASP / CWE, with the fix in reach. The scans are deliberately
non-destructive.

## Positioning

A scanner that proves each finding, adapts per target, and never floods:
request pacing is self-throttling, profiles are passive / safe / aggressive,
localhost needs no authorization while any remote target requires
`--i-am-authorized`. It orchestrates Nuclei, Nikto, sqlmap, nmap, and testssl
when present instead of reinventing them, and keeps a tiny core (requests +
rich). The full name is "F\*\*\* Your App" and the irreverence is the point:
confidence plus receipts, never corporate hedging.

## Operating Context

Terminal-first CLI (`fya scan <target>`), modes (recon / web / api / mobile /
blackbox / graybox / whitebox / full), profiles, `--only` and `--skip` at
category or check-id granularity, authenticated scans via headers, cookies,
bearer tokens, scope budgets and `--max-requests`, optional SPA crawling,
baseline suppression for CI, five report formats (console, json, sarif,
markdown, html) inferred from the `-o` extension, and `--fail-on` exit codes.
A bundled Claude skill performs the same methodology in-session with no
package installed. The website shows real captured output
(`demo-web-scan.svg`, `demo-apk-scan.svg`, `sample-report.html`) because the
product's promise is proof.

## Capabilities and Constraints

- 91 checks across web passive / active / advanced / secrets / exposure /
  SSRF / crypto / hardening, black box, gray box, white box (source and IaC),
  TLS, API, APK (manifest and DEX), and external-tool integrations; each
  mapped to OWASP Top 10 / MASVS and a CWE.
- Targets: a live web server, an Android APK, or a source directory,
  auto-detected from one command.
- Dual-licensed: PolyForm Noncommercial 1.0.0 for noncommercial and personal
  use; commercial use requires a paid license. Versions before 0.5.0 remain
  MIT.
- Authorized-only: remote scanning requires explicit consent; load, stress,
  and network-chaos testing are out of scope by design.
- Site constraint: every number is traceable to README, CHANGELOG, docs, or a
  real capture. No invented precision.

## Brand Commitments

- Name: fya. Full form "F\*\*\* Your App", the expletive-is-the-brand spelled
  out in the README title; abbreviated on the site.
- Voice (confirmed by user, 2026-08-30): "Unleash it": irreverent, confident,
  wry, zero corporate hedging, still evidence-backed and professional enough
  for commercial licensees.
- Type (confirmed by user, 2026-08-30): the "Wanted" world won the design lab.
  Bricolage Grotesque for display and body, JetBrains Mono held for commands,
  findings, and CWE / OWASP ids. The earlier Schibsted Grotesk candidate was
  rejected as not bold enough.
- Temper (confirmed by user, 2026-08-30): air and space over density.
- Borrows locked in the lab synthesis: corner-bracket evidence plates
  (Variants A) on top of the Wanted poster and stamps (Variant C).
- One visual world across home, docs, and changelog.

## Evidence on Hand

- `web/public/demo-web-scan.svg` and `web/public/demo-apk-scan.svg`: genuine
  Rich captures of real scans.
- `web/public/sample-report.html`: a real self-contained HTML report.
- Repo `README.md`, `CHANGELOG.md`, `docs/checks.md` (the 91-check catalog),
  and `docs/architecture.md`.
- No testimonials, no customers, no invented benchmarks. None may be
  fabricated.

## Product Principles

1. Proof first: every claim the site makes can be checked against a capture,
   the catalog, or the changelog.
2. Non-destructive by default, consent-gated, DoS-shaped activity out of
   scope.
3. Irreverent confidence with receipts: the personality is a feature and is
   never sanitized into generic devtool prose.
4. One tool, three targets, adaptive by design.
5. Mostly free, honestly licensed; commercial use is a paid license and that
   is stated plainly.