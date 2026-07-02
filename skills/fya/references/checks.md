# Check catalog

The families Claude can run, mapped to the OWASP Top 10 (2021) or OWASP MASVS
and a CWE. Use this to plan the test matrix: run only families that fit the
target kind and the chosen profile. Web families need a web target; APK families
need an `.apk`. A check runs only at or above its minimum profile.

## Web passive (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Security headers (CSP, HSTS, X-Content-Type-Options, clickjacking, Referrer-Policy) | info - medium | A05 Security Misconfiguration | CWE-693, 319, 1021, 200 |
| Server and version disclosure | low | A05 Security Misconfiguration | CWE-200 |
| Insecure cookie flags (Secure, HttpOnly, SameSite) | low - medium | A05 Security Misconfiguration | CWE-614 |

## Web active (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Reflected XSS | high (confidence medium) | A03 Injection | CWE-79 |
| SQL injection (error based) | high | A03 Injection | CWE-89 |
| Open redirect | medium | A01 Broken Access Control | CWE-601 |
| Path traversal | high | A01 Broken Access Control | CWE-22 |
| CORS misconfiguration | high | A05 Security Misconfiguration | CWE-942 |
| Dangerous HTTP methods | low - medium | A05 Security Misconfiguration | CWE-650 |
| Sensitive file exposure (.env, .git, backups) | high | A05 Security Misconfiguration | CWE-538 |

## Web advanced (min profile: safe, CRLF at aggressive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Server-side template injection (SSTI) | high | A03 Injection | CWE-1336 |
| Missing CSRF token | medium (confidence low) | A01 Broken Access Control | CWE-352 |
| Host header injection | medium | A05 Security Misconfiguration | CWE-644 |
| CRLF / header injection | high | A03 Injection | CWE-93 |

## Web hardening (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| CSP policy weaknesses (unsafe-inline, unsafe-eval, wildcard, data:) | low - medium | A05 Security Misconfiguration | CWE-693 |
| JWT weak algorithm (none / symmetric) | low - high | A02 Cryptographic Failures | CWE-347 |
| JWT missing expiry | low | A07 Identification and Authentication Failures | CWE-613 |
| JWT sensitive claims | medium | A02 Cryptographic Failures | CWE-522 |
| Outdated JS libraries | info - medium | A06 Vulnerable and Outdated Components | CWE-1104 |
| Missing security.txt | info | A05 Security Misconfiguration | none |
| robots.txt discloses sensitive paths | low | A05 Security Misconfiguration | CWE-200 |

## TLS (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Certificate validity and trust | medium - critical | A02 Cryptographic Failures | CWE-295 |
| Weak protocol versions (TLS 1.0 / 1.1) | medium | A02 Cryptographic Failures | CWE-327 |
| Missing HTTP to HTTPS upgrade | medium | A02 Cryptographic Failures | CWE-319 |

## API (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| OpenAPI / Swagger exposure | medium | A05 Security Misconfiguration | CWE-200 |
| GraphQL introspection enabled | medium | A05 Security Misconfiguration | CWE-200 |
| Verbose error disclosure | medium | A05 Security Misconfiguration | CWE-209 |
| Unauthenticated admin / actuator endpoints | medium | A05 Security Misconfiguration | CWE-497 |

## Black box (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Input fuzzing: malformed input triggers a 5xx | medium | A05 Security Misconfiguration | CWE-20 |
| Input fuzzing: stack trace disclosed on bad input | low | A05 Security Misconfiguration | CWE-209 |

## Gray box (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Insecure direct object reference (IDOR) | medium (confidence low) | A01 Broken Access Control | CWE-639 |
| Protected route reachable without auth | medium (confidence low) | A01 Broken Access Control | CWE-306 |

## White box (source directory)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Hardcoded secrets in source (min profile: passive) | high | A07 Identification and Authentication Failures | CWE-798 |
| Risky code patterns: eval, exec, shell=True, pickle, verify=False (min profile: passive) | low - high | A03 Injection | CWE-95, 78, 502, 295, 79 |
| External static analysis via semgrep or bandit (min profile: safe) | info - high | A06 Vulnerable and Outdated Components | varies |

## APK static (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Hardcoded secrets | high | MASVS-STORAGE | CWE-798 |
| Cleartext HTTP endpoints | low | MASVS-NETWORK | CWE-319 |
| Manifest issues (debuggable, allowBackup, exported, cleartext, minSdk, permissions) | info - high | MASVS-PLATFORM/STORAGE/NETWORK/CODE | CWE-489, 530, 319, 926 |

## External tools (optional, aggressive)

If nuclei, nikto, nmap, sqlmap, or testssl are on PATH, run them and fold their
output into the report. They are accelerators, not required.
