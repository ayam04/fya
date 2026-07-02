---
name: fya
description: Use when the user wants to security-test or break an application they own or are authorized to test. Triggers include "scan my app", "pentest my localhost", "break my app", "security test this API", "check my APK for vulnerabilities", "run an OWASP scan", "find security issues in my web app", "black box / gray box / white box test this", "fuzz my inputs", "static analysis of my code", "check this repo for secrets", or pointing Claude at a localhost URL, an .apk file, or a source code directory and asking what is wrong with it. Performs dynamic, non-destructive black/gray-box testing of a running web server or Android .apk, plus white-box static analysis of a source directory, mapped to the OWASP Top 10 and OWASP MASVS, entirely within the session.
---

# fya: break your app, safely, in a session

This skill turns Claude into a dynamic application security scanner. You point it
at a running web app or an Android APK that you own, and Claude figures out what
to test, runs non-destructive probes with its own tools (curl, python, file
reads), and reports findings mapped to the OWASP Top 10 and MASVS with
remediation. It does not need any package installed. If the user would rather run
a battle-tested CLI, the same methodology ships as `pip install fya`
(github.com/ayam04/fya), but this skill is self-contained.

## Authorization gate (do this first, every time, no exceptions)

Security testing without permission can be illegal. Before any probe:

1. Confirm the exact target with the user (a URL, a host:port, or a path to an `.apk`).
2. Decide authorization:
   - `localhost`, `127.0.0.1`, `::1`, and private-range addresses are allowed as the user's own environment.
   - Any other host requires the user to confirm, in this conversation, that they own it or have written authorization to test it. If they cannot, refuse and stop.
3. State the scope back to the user (target, mode, profile) and get a single go-ahead. Then run.

Never run denial-of-service or flooding payloads. Never attempt to damage, delete,
or exfiltrate data. Probes are detection-grade only. Pace requests politely and
back off on errors or timeouts.

## Workflow

Create a todo per step and work through them in order.

1. **Scope and authorize** as above. Pick a mode and profile (see below).
2. **Detect the target kind.** A path ending in `.apk` (or a zip containing an `AndroidManifest.xml`) is a mobile target. A local directory is a source target for white-box analysis. Otherwise it is a web target; a bare host defaults to `http` for localhost and private addresses and `https` otherwise.
3. **Fingerprint** a web target: fetch the base URL, read the `Server`, `X-Powered-By`, and `Set-Cookie` headers, the response content type, and any framework tells in the body. This decides which checks are worth running.
4. **Plan the test matrix.** From the target kind, fingerprint, and profile, list the check families that apply. See `references/checks.md` for the full catalog and its OWASP/CWE mapping. This is the "decide what testing to do" step: do not run mobile checks on a URL or active injection probes in a passive scan.
5. **Execute**, family by family, using the concrete probes in:
   - `references/web.md` for web passive, active, advanced, and hardening checks.
   - `references/tls-api.md` for TLS and API checks.
   - `references/apk.md` for APK static analysis, plus the bundled helper `scripts/apk_scan.py`.
   For a large target, or when the user asks for a thorough scan, fan the families out across subagents (one per area) and merge the results.
6. **Analyze.** De-duplicate findings, then apply the false-positive discipline described in each reference and in `references/report-template.md`: require baselines where noted, respect reflection context, and do not overstate severity. Map every finding to an OWASP or MASVS category and a CWE.
7. **Report** using `references/report-template.md`: a severity summary, then each finding with evidence, a short proof of concept, and remediation. Offer to write the report to a file if the user wants one.

## Modes

A mode selects which families run. The three knowledge-level modes map to the classic
black/gray/white-box taxonomy; see `references/strategies.md` for the techniques and the
"break the app" playbook.

- `recon`: passive, read-only reconnaissance (headers, TLS, cookies, disclosure, fingerprint).
- `web`: web app checks plus TLS and API.
- `api`: API surface plus supporting web checks.
- `mobile`: Android APK static analysis.
- `blackbox`: no internals. Input fuzzing and robustness (malformed, oversized, wrong-type, unicode, null-byte, format-string payloads to find crashes and stack traces) plus the outside-in web and TLS checks.
- `graybox`: partial knowledge. IDOR (change object ids), auth-bypass on protected routes, and API contract probing.
- `whitebox`: source access. Static analysis of a code directory for hardcoded secrets, risky sinks (eval, exec, shell=True, pickle, disabled TLS verification), and, if `semgrep` or `bandit` is installed, their rule findings folded in.
- `full`: everything that applies, at the aggressive profile.
- `auto` (default): everything that applies to the detected target.

Deliberately out of scope: load/stress and network-chaos testing. They are denial-of-service
shaped and break the non-destructive guarantee. If the user wants those, point them to k6,
Locust, or Toxiproxy on infrastructure they own; do not run them here.

## Profiles

A profile sets how hard to probe, independent of the mode.

- `passive`: read-only. No payloads.
- `safe` (default): non-destructive active probes. Reflection, error signatures, CORS.
- `aggressive`: wider crawl, more payload variants, and heavier checks. Still non-destructive.

## Safety rules (non-negotiable)

- Non-destructive only. No writes, deletes, DoS, brute force, or data exfiltration.
- Localhost is allowed; remote targets need explicit authorization confirmed in the conversation.
- Pace requests and back off on 429, 5xx, timeouts, and slow responses.
- Redact secrets and tokens in the report.
- If you are unsure whether an action is destructive, do not run it; describe it instead.

## Reference files

- `references/checks.md` - the full check catalog with OWASP/MASVS and CWE.
- `references/strategies.md` - black/gray/white-box methodology and the break-the-app playbook (fuzzing, boundaries, IDOR, auth bypass, source static analysis).
- `references/web.md` - web passive, active, advanced, and hardening techniques.
- `references/tls-api.md` - TLS and API techniques.
- `references/apk.md` - APK static analysis techniques.
- `references/report-template.md` - severity model, false-positive discipline, and the report format.
- `scripts/apk_scan.py` - dependency-free helper that scans an APK for hardcoded secrets and cleartext URLs.
