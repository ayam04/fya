# Check catalog

This is the full set of checks that ship in `fya/checks/`, grouped by area. Each
row lists the check `name` (its dotted id), the severity range it can emit, the
OWASP Top 10 or OWASP MASVS category it maps to, and the CWE it references.

Severity ranges reflect what a single check can yield across cases. A check that
always emits one severity shows a single value; one that varies by finding shows
a range. Profiles are ordered `passive` < `safe` < `aggressive`; a check runs
only at or above its minimum profile.

## Web passive

Read-only checks. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.security_headers` | info - medium | A05:2021 Security Misconfiguration | CWE-693, CWE-319, CWE-1021, CWE-200 |
| `web.version_disclosure` | low | A05:2021 Security Misconfiguration | CWE-200 |
| `web.insecure_cookies` | low - medium | A05:2021 Security Misconfiguration | CWE-614 |

Notes: `web.security_headers` reports separately on missing
Content-Security-Policy (medium, CWE-693), Strict-Transport-Security (medium,
CWE-319), X-Content-Type-Options (low, CWE-693), clickjacking protection (low,
CWE-1021), and Referrer-Policy (info, CWE-200). `web.insecure_cookies` is medium
when the `HttpOnly` flag is missing, otherwise low.

## Web active

Non-destructive active probes. Minimum profile: `safe`. Crawl scope and payload
sets widen at `aggressive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.reflected_xss` | high | A03:2021 Injection | CWE-79 |
| `web.sql_injection` | high | A03:2021 Injection | CWE-89 |
| `web.open_redirect` | medium | A01:2021 Broken Access Control | CWE-601 |
| `web.path_traversal` | high | A01:2021 Broken Access Control | CWE-22 |
| `web.cors_misconfig` | high | A05:2021 Security Misconfiguration | CWE-942 |
| `web.dangerous_methods` | low - medium | A05:2021 Security Misconfiguration | CWE-650 |
| `web.sensitive_files` | high | A05:2021 Security Misconfiguration | CWE-538 |

Notes: `web.dangerous_methods` is medium when `TRACE` is advertised, otherwise
low. `web.sql_injection` is error-signature based (medium confidence).

## Web advanced

Higher-signal dynamic web checks. Minimum profile: `safe`, except `web.crlf`
which runs at `aggressive`. Payload sets widen at `aggressive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.ssti` | high | A03:2021 Injection | CWE-1336 |
| `web.csrf` | medium | A01:2021 Broken Access Control | CWE-352 |
| `web.host_header` | medium | A05:2021 Security Misconfiguration | CWE-644 |
| `web.crlf` | high | A03:2021 Injection | CWE-93 |

Notes: `web.ssti` confirms server-side template injection by evaluating an
arithmetic payload across common template engines and matching the product in
the response. `web.csrf` flags state-changing POST forms that carry no anti-CSRF
token field. `web.host_header` sends a spoofed Host header and reports when it is
reflected in the body, a redirect, or an absolute link. `web.crlf` injects an
encoded CR LF to detect response header injection.

## TLS

Certificate and protocol checks over a direct TLS socket. Minimum profile:
`passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `tls.certificate` | medium - critical | A02:2021 Cryptographic Failures | CWE-295 |
| `tls.weak_protocol` | medium | A02:2021 Cryptographic Failures | CWE-327 |
| `tls.https_upgrade` | medium | A02:2021 Cryptographic Failures | CWE-319 |

Notes: `tls.certificate` emits critical for an expired certificate, high for a
hostname mismatch, self-signed or untrusted chain, or a not-yet-valid
certificate, and medium when a certificate is expiring within 30 days.
`tls.https_upgrade` applies only when the target scheme is `http` and HTTPS is
reachable on the host.

## API

API surface and error-handling checks. Minimum profile: `safe`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `api.docs_exposure` | medium | A05:2021 Security Misconfiguration | CWE-200 |
| `api.graphql_introspection` | medium | A05:2021 Security Misconfiguration | CWE-200 |
| `api.verbose_errors` | medium | A05:2021 Security Misconfiguration | CWE-209 |
| `api.admin_endpoints` | medium | A05:2021 Security Misconfiguration | CWE-497 |

## APK

Local static analysis of an Android `.apk`. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `apk.hardcoded_secrets` | info, high | MASVS-STORAGE | CWE-798 |
| `apk.cleartext_urls` | low | MASVS-NETWORK | CWE-319 |
| `apk.manifest` | info - high | MASVS-PLATFORM, MASVS-STORAGE, MASVS-NETWORK, MASVS-CODE | CWE-489, CWE-530, CWE-319, CWE-926 |

Notes: `apk.hardcoded_secrets` emits high for a detected secret (AWS access key,
Google API key, private key block, Firebase URL, or Slack token) and info if the
archive cannot be opened. `apk.manifest` requires the optional `androguard`
dependency (the `[apk]` extra); without it, it emits a single info finding
saying analysis was skipped. When available it reports: debuggable build (high,
CWE-489, MASVS-CODE), allowBackup enabled (medium, CWE-530, MASVS-STORAGE),
cleartext traffic permitted or no network security config (medium, CWE-319,
MASVS-NETWORK), exported component without a permission guard (medium, CWE-926,
MASVS-PLATFORM), low minSdkVersion below API 24 (low, MASVS-PLATFORM), and
sensitive permissions requested (low, MASVS-PLATFORM).

## Integrations

Handoff to external tools, only at the `aggressive` profile and only when the
tool is present on `PATH`. Output is normalized into `fya` findings.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `integrations.nuclei` | info - critical | A06:2021 Vulnerable and Outdated Components | (from template) |
| `integrations.nikto` | low - medium | A05:2021 Security Misconfiguration | CWE-16 |
| `integrations.nmap` | info - medium | A05:2021 Security Misconfiguration | CWE-668 |
| `integrations.sqlmap` | high | A03:2021 Injection | CWE-89 |
| `integrations.tls` | medium - high | A02:2021 Cryptographic Failures | CWE-326 |

Notes: `integrations.nuclei` maps the template's reported severity onto the
`fya` scale and does not set a fixed CWE. `integrations.nmap` is medium for a
risky exposed service (FTP, Telnet, SMB) and CWE-668, low for RDP, and info for
any other open port (no CWE). `integrations.sqlmap` only applies when the target
URL carries a query string. `integrations.tls` uses `testssl.sh` if present,
otherwise `sslyze`, and only applies to HTTPS targets.
