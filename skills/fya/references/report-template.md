# Severity, false-positive discipline, and the report format

## Severity model

- **critical**: remote code execution, full auth bypass, or an exposed secret that grants broad access.
- **high**: injection (XSS, SQLi, SSTI, CRLF), sensitive file or data exposure, or a broken access control that a remote attacker can exploit directly.
- **medium**: misconfigurations that need a condition or chaining (CORS, host header, weak TLS, verbose errors, missing CSRF).
- **low**: hardening gaps and information disclosure with limited direct impact.
- **info**: best-practice notes with no direct security impact.

Also state a **confidence** (low, medium, high): how sure you are the finding is real and exploitable.

## False-positive discipline (do not skip this)

A confident wrong finding costs more than a missed one. Apply these rules, which
come from auditing the checks:

- **Baseline before you judge.** For SQLi, verbose errors, and SSTI, fetch a normal response first and only flag a signal that is absent in the baseline. A digit string or error word already on the page is not a finding.
- **Reflected XSS is medium confidence unless you prove execution.** A reflected marker proves the value was not entity-encoded, not that it executes. Only raise to high if a real breakout (unencoded angle brackets or quotes escaping the surrounding context) lands, and only treat the response as HTML when the content type is actually `text/html`.
- **CORS wildcard plus credentials is not exploitable.** Browsers reject a credentialed response when `Access-Control-Allow-Origin` is `*`. Only a reflected origin (the server echoes your `Origin`) combined with `Access-Control-Allow-Credentials: true` is the high finding.
- **SSTI needs a baseline and two factor pairs.** Inject two different products (for example 7919*6271 and 4133*8017) and require both evaluated results to appear, with the baseline free of them, before flagging.
- **CSRF is low confidence and context-aware.** Do not flag a POST form when the page carries a `<meta name="csrf-token">` or the session cookie is `SameSite=Lax` or `Strict`; those already defend it.
- **sqlmap and tool output**: only trust the tool's real positive banner (sqlmap prints "is vulnerable"), not any line that merely contains "parameter" and "vulnerable".
- Redact secrets and tokens in evidence.

## Report format

Produce this in the chat, and offer to write it to a file. No em-dashes.

```
# Security scan: <target>

Target: <url or apk path>
Kind: <web | apk>   Mode: <mode>   Profile: <profile>
Authorized: <how authorization was established>
Findings: <n critical, n high, n medium, n low, n info>

## Findings

### [HIGH] <title>
- OWASP: <A0x:2021 ...>   CWE: <CWE-xx>   Confidence: <low|medium|high>
- Location: <url or file[:line]>

<one or two sentences: what it is and why it matters>

Proof of concept:
    <the exact request or the observed response signal>

Remediation: <the concrete fix>

(repeat per finding, ordered by severity)

## Notes
<scope covered, what was skipped and why, and any manual follow-up worth doing>
```

Lead with the worst findings. Keep each finding tight: a reader should grasp the
risk, see the proof, and know the fix in a few lines.
