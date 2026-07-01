# Web application checks: manual methodology

This reference tells you how to run every fya web check by hand, inside a session, with common tools. No fya package is required. Every probe here is non-destructive: it reads, reflects, and observes. It never writes, deletes, or mutates server state. Stay inside that discipline.

Ground rule: match what the code does. The payloads, detection signatures, severities, and false-positive guards below are lifted directly from the check sources. Do not invent techniques that contradict them.

## Discovering testable URLs (light same-host crawl)

Before the active checks you need a small set of URLs and their parameters. The code does a light, single-pass crawl of the base page (and any provided seed URLs), extracts links and form actions, keeps only same-host targets, and records query-string parameter names plus form input names. It caps the set at 25 URLs in the SAFE profile and 60 in AGGRESSIVE.

Do the same by hand:

```bash
BASE="https://target.example"
# 1. Fetch the base page body
curl -s "$BASE/" -o /tmp/fya_base.html

# 2. Extract same-host <a href> links (mirrors the _LINK_RE anchor regex)
grep -oiE '<a[^>]+href=["'"'"'][^"'"'"'#>]+' /tmp/fya_base.html \
  | sed -E 's/.*href=["'"'"']//I' \
  | sort -u

# 3. Extract form actions and input names
grep -oiE '<form[^>]*>' /tmp/fya_base.html
grep -oiE '<(input|textarea|select)[^>]+name=["'"'"'][^"'"'"'>]+' /tmp/fya_base.html \
  | sed -E 's/.*name=["'"'"']//I' | sort -u
```

Python fallback that reproduces the crawl (same-host filter, param and form-name collection, cap):

```python
import re, sys
from urllib.parse import urljoin, urlparse, urlsplit, parse_qsl
import requests

BASE = "https://target.example/"
CAP = 25  # 60 for aggressive
host = urlparse(BASE).hostname
LINK = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#>]+)["']""", re.I)
FORM = re.compile(r"<form\b[^>]*?>(.*?)</form>", re.I | re.S)
ACTION = re.compile(r"""\baction\s*=\s*["']([^"'>]*)["']""", re.I)
NAME = re.compile(r"""<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*["']([^"'>]+)["']""", re.I)

def same_host(u):
    p = urlparse(u)
    return (not p.netloc) or p.hostname == host

def params_of(u):
    return [k for k, _ in parse_qsl(urlsplit(u).query, keep_blank_values=True)]

urls = {}
body = requests.get(BASE, timeout=10).text
for href in LINK.findall(body):
    absu = urljoin(BASE, href)
    if absu.startswith(("http://", "https://")) and same_host(absu):
        p = params_of(absu)
        if p: urls.setdefault(absu, set()).update(p)
        elif len(urls) < CAP: urls.setdefault(absu, set())
for fb in FORM.findall(body):
    m = ACTION.search(fb)
    absu = urljoin(BASE, (m.group(1) if m else BASE) or BASE)
    if absu.startswith(("http://", "https://")) and same_host(absu):
        urls.setdefault(absu, set()).update(NAME.findall(fb))
for u, ps in list(urls.items())[:CAP]:
    print(u, sorted(ps))
```

Scope and pacing:
- Only test hosts you are authorized to test. The crawl and every probe stay on the target host by design (the `_same_host` filter). Keep it that way.
- Pace requests. These checks fan out one probe per (URL, parameter). On a large surface that is a lot of requests. Insert a short delay (`--rate` in httpx, or a `sleep` in a loop) and avoid the aggressive profile against production unless you own it.
- Use a stable, identifiable User-Agent so the owner can see it is you.

Throughout, `MARKER` is a fresh random token you generate once per probe (`MARKER=$(openssl rand -hex 6)`). The code uses a unique per-probe marker to keep reflection detection unambiguous.

---

## Passive checks

These read a single base response. No injection, no parameters. Safe to run anywhere you are authorized.

### Missing security headers (`web.security_headers`)

Detects absence of defense-in-depth response headers. Matters because each missing header removes a browser-side mitigation.

```bash
curl -sD - -o /dev/null "https://target.example/"
```

Detection signal: the check fetches the base URL once and inspects the response header set. It flags each of these when absent:

| Header | Severity | CWE |
| --- | --- | --- |
| `content-security-policy` | MEDIUM | CWE-693 |
| `strict-transport-security` | MEDIUM | CWE-319 |
| `x-content-type-options` | LOW | CWE-693 |
| `x-frame-options` | LOW | CWE-1021 |
| `referrer-policy` | INFO | CWE-200 |

False-positive discipline built into the code:
- `x-frame-options` is NOT flagged if the CSP contains a `frame-ancestors` directive (CSP supersedes it). Check the CSP value before reporting.
- `strict-transport-security` is NOT flagged on plaintext HTTP targets (HSTS only applies over HTTPS). Only report it when the scheme is `https`.
- All findings are Confidence HIGH (a header is present or it is not).

Severity: LOW to MEDIUM. OWASP: A05:2021 Security Misconfiguration.

### Server / version disclosure (`web.version_disclosure`)

Detects software and version leaked in response headers, which lets an attacker map the target to known CVEs.

```bash
curl -sD - -o /dev/null "https://target.example/" | grep -iE '^(server|x-powered-by|x-aspnet-version):'
```

Detection signal: for each of `server`, `x-powered-by`, `x-aspnet-version`, the value is flagged only if it contains at least one digit (`any(ch.isdigit())`). A bare `Server: nginx` with no version does not qualify. Evidence is the full header value.

False-positive discipline: the digit requirement is the guard. `Server: cloudflare` is not reported; `Server: nginx/1.18.0` is. Confidence HIGH.

Severity: LOW. OWASP: A05:2021 Security Misconfiguration. CWE-200.

### Insecure cookie flags (`web.insecure_cookies`)

Detects session/auth cookies set without protective attributes, weakening them against theft and CSRF.

```bash
curl -sD - -o /dev/null "https://target.example/" | grep -i '^set-cookie:'
```

Detection signal: for each `Set-Cookie`, the check records missing attributes:
- `Secure` missing is flagged only when the scheme is HTTPS (a Secure flag on plaintext HTTP is meaningless).
- `HttpOnly` missing is always flagged.
- `SameSite` missing is always flagged.

Severity is MEDIUM if `HttpOnly` is among the missing attributes, otherwise LOW. Confidence HIGH. Evidence is redacted to `Set-Cookie: name=...` (the value is never printed).

False-positive discipline: the HTTPS gate on `Secure` is the guard. Read each attribute case-insensitively.

Severity: LOW to MEDIUM. OWASP: A05:2021 Security Misconfiguration. CWE-614.

---

## Active checks

Each of these runs against discovered (URL, parameter) pairs. Generate a fresh marker per probe. Several use a baseline request first to suppress false positives; do not skip the baseline.

### Reflected XSS (`web.reflected_xss`)

Detects user input reflected into HTML without entity-encoding the angle brackets. Matters because unencoded reflection is the precondition for script injection.

Probe (the exact payload shape the code uses, `<fya>MARKER</fya>`):

```bash
MARKER=$(openssl rand -hex 6)
URL="https://target.example/search?q=1"
PARAM="q"
PAYLOAD="<fya>${MARKER}</fya>"
curl -s -G "https://target.example/search" \
  --data-urlencode "${PARAM}=${PAYLOAD}" \
  -D - -o /tmp/xss_body.html
grep -F "$PAYLOAD" /tmp/xss_body.html && echo "REFLECTED UNESCAPED"
```

Detection signal, in order:
1. The response `Content-Type` must be `text/html` or `application/xhtml`. Non-HTML responses are skipped (a reflection in a JSON body is not XSS here).
2. The literal payload `<fya>MARKER</fya>` must appear verbatim in the body. If the angle brackets were entity-encoded to `&lt;fya&gt;`, the literal will not match and nothing is reported.

False-positive discipline: this proves un-encoded reflection, NOT execution. The code deliberately sets Confidence MEDIUM and its description says manual confirmation of the output context is recommended. A reflection inside an HTML attribute or a script string behaves very differently from one in element text. Keep confidence medium and verify the context by hand. Severity HIGH (impact if exploitable is high), confidence MEDIUM.

Severity: HIGH. OWASP: A03:2021 Injection. CWE-79.

### Error-based SQL injection (`web.sql_injection`)

Detects input concatenated into a SQL statement, revealed by a database error signature.

Probe uses a baseline value `1`, then the breaking payload `1'"` (a quote and a double-quote):

```bash
URL="https://target.example/item"
PARAM="id"
# Baseline: benign value, capture normal body
curl -s -G "$URL" --data-urlencode "${PARAM}=1" -o /tmp/sqli_base.txt
# Probe: append quote + double-quote
curl -s -G "$URL" --data-urlencode "${PARAM}=1'\"" -o /tmp/sqli_probe.txt
```

Detection signal: the probe body (lowercased) must contain one of the SQL error signatures AND that signature must NOT already be present in the baseline body. The baseline diff is the false-positive guard. Signatures the code looks for include:

```
you have an error in your sql syntax, warning: mysql, mysql_fetch, mysqli,
unclosed quotation mark, sql syntax, sqlite3.operationalerror, sqlite error,
unrecognized token, near ", psql:, pg_query, postgresql, syntax error at or near,
ora-00933, ora-01756, ora-, odbc, sqlstate
```

Compare by hand:

```bash
for sig in "sql syntax" "unclosed quotation mark" "sqlstate" "ora-" "syntax error at or near" "warning: mysql"; do
  if grep -qi "$sig" /tmp/sqli_probe.txt && ! grep -qi "$sig" /tmp/sqli_base.txt; then
    echo "SQLi signature (probe only): $sig"
  fi
done
```

False-positive discipline: the "present in probe but absent from baseline" rule prevents flagging pages that always mention SQL. Confidence MEDIUM (an error signature is strong but not a confirmed injection). If you want a confirmed verdict, run `sqlmap` and only trust its explicit `is vulnerable` banner, not incidental output:

```bash
sqlmap -u "https://target.example/item?id=1" -p id --batch --level=2 --risk=1
# Only report if sqlmap prints: "parameter 'id' is vulnerable"
```

Severity: HIGH. OWASP: A03:2021 Injection. CWE-89.

### Open redirect (`web.open_redirect`)

Detects a parameter that controls the redirect target without validation, usable for phishing.

The code only tests parameters whose name is in a redirect-name allowlist: `url, next, redirect, redirect_uri, return, returnto, dest, destination, continue, go, target` (SAFE), plus `u, link, out, goto, rurl, forward, callback, checkout_url` (AGGRESSIVE). It uses an out-of-band host `fya-oob.example` and three payload forms.

```bash
MARKER=$(openssl rand -hex 6)
OOB="fya-oob.example"
URL="https://target.example/login"
PARAM="next"
for PAYLOAD in "https://${OOB}/${MARKER}" "//${OOB}/${MARKER}" "\\\\${OOB}\\${MARKER}"; do
  curl -s -o /dev/null -D - -G "$URL" \
    --data-urlencode "${PARAM}=${PAYLOAD}" \
    --max-redirs 0 \
    | grep -iE '^(location|refresh):'
done
```

Note `--max-redirs 0` (do not follow the redirect; the code sets `allow_redirects=False`).

Detection signal: the response status must be a redirect (301, 302, 303, 307, 308) AND the `Location` (or `Refresh`) header must point at the OOB host. Specifically the parsed hostname of `Location` equals `fya-oob.example`, or the string `fya-oob.example` appears in `Location` or `Refresh`. Backslashes are normalized to forward slashes before parsing (that is why the `\\host\` payload is tested).

False-positive discipline: the parameter-name allowlist plus the requirement that the response actually 3xx-redirects to the attacker host is the guard. A parameter that merely echoes the URL in the body is not an open redirect. Confidence HIGH.

Severity: MEDIUM. OWASP: A01:2021 Broken Access Control. CWE-601.

### Path traversal (`web.path_traversal`)

Detects a parameter that reads files from an attacker-controlled path, returning system file contents.

Payloads: SAFE profile tests only `../../../../etc/passwd`; AGGRESSIVE adds the URL-encoded variant and a Windows `win.ini` payload.

```bash
URL="https://target.example/download"
PARAM="file"
for PAYLOAD in "../../../../etc/passwd" "..%2f..%2f..%2f..%2fetc%2fpasswd" "../../../../windows/win.ini"; do
  curl -s -G "$URL" --data-urlencode "${PARAM}=${PAYLOAD}" -o /tmp/trav.txt
  grep -qE 'root:.*:0:0:' /tmp/trav.txt && echo "PASSWD LEAK via $PAYLOAD"
  grep -qiE '\[(fonts|extensions|mci extensions|files)\]' /tmp/trav.txt && echo "WIN.INI LEAK via $PAYLOAD"
done
```

Detection signal: the body must match the passwd signature regex `root:.*:0:0:` OR the win.ini section-header regex `\[(fonts|extensions|mci extensions|files)\]` (case-insensitive). These are content signatures of the actual system files, not just a 200 status.

False-positive discipline: matching real file structure (the `root:...:0:0:` line or an INI section header) is the guard against flagging arbitrary content. Confidence HIGH, and note the payload must be URL-encoded when sent as a query value (`--data-urlencode` handles that; the pre-encoded `%2f` variant tests filters that decode once).

Severity: HIGH. OWASP: A01:2021 Broken Access Control. CWE-22.

### CORS misconfiguration (`web.cors_misconfig`)

Detects a CORS policy that lets a malicious site read authenticated responses.

The code sends an `Origin: https://evil.example` header to the base URL and each discovered URL.

```bash
EVIL="https://evil.example"
curl -sD - -o /dev/null -H "Origin: ${EVIL}" "https://target.example/api/me" \
  | grep -iE '^access-control-allow-(origin|credentials):'
```

Detection signal, two distinct outcomes:
- HIGH / Confidence HIGH: `Access-Control-Allow-Origin` reflects the attacker origin exactly (`https://evil.example`) AND `Access-Control-Allow-Credentials: true`. This is browser-exploitable: a malicious origin can read credentialed responses.
- LOW / Confidence LOW: `Access-Control-Allow-Origin: *` (literal wildcard) AND `Access-Control-Allow-Credentials: true`.

False-positive discipline: the wildcard-plus-credentials case is explicitly NOT browser-exploitable. Browsers reject a credentialed response served under a wildcard origin, so the code files it as LOW / LOW and its description says as much. Only the reflected-exact-origin case is a real, exploitable finding. Do not overstate the wildcard case.

Severity: LOW to HIGH. OWASP: A05:2021 Security Misconfiguration. CWE-942.

### Dangerous HTTP methods (`web.dangerous_methods`)

Detects rarely needed verbs that can enable cross-site tracing or unintended resource modification.

```bash
curl -sD - -o /dev/null -X OPTIONS "https://target.example/" | grep -i '^allow:'
```

Detection signal: the check issues a single `OPTIONS` request and parses the `Allow` header. It intersects the advertised methods with `{TRACE, PUT, DELETE, CONNECT, PATCH}` and reports the intersection. Severity is MEDIUM if `TRACE` is present, otherwise LOW. Confidence MEDIUM (advertised does not always mean actually enabled).

False-positive discipline: this only reads the `Allow` header. It is non-destructive and does NOT actually send a PUT or DELETE. Confidence is MEDIUM precisely because an advertised verb may be rejected on real endpoints. If you want to confirm, do so only against an endpoint you own.

Severity: LOW to MEDIUM. OWASP: A05:2021 Security Misconfiguration. CWE-650.

### Sensitive file exposure (`web.sensitive_files`)

Detects config, VCS metadata, and backups served from the web root, potentially leaking secrets or source.

Paths checked and their content markers:

| Path | Markers |
| --- | --- |
| `/.env` | `=`, `secret`, `key`, `password`, `token`, `api` |
| `/.git/config` | `[core]`, `repositoryformatversion`, `[remote` |
| `/.git/HEAD` | `ref:`, `refs/heads` |
| `/config.json` | `{`, `}` |
| `/backup.zip` | (no markers, any non-empty body) |
| `/.DS_Store` | `Bud1`, null bytes |
| `/docker-compose.yml` | `services:`, `version:`, `image:` |

```bash
for P in /.env /.git/config /.git/HEAD /config.json /backup.zip /.DS_Store /docker-compose.yml; do
  code=$(curl -s -o /tmp/sf.txt -w '%{http_code}' "https://target.example${P}")
  ct=$(curl -sI "https://target.example${P}" | grep -i '^content-type:' | tr -d '\r')
  echo "$P -> $code  $ct  ($(wc -c </tmp/sf.txt) bytes)"
done
```

Detection signal:
1. Status must be exactly 200.
2. If the content-type is `text/html` AND the first 400 bytes contain `<html`, the file is skipped (that is a SPA fallback or error page, not the raw file).
3. The body must be "plausible": either the path has no markers, or at least one marker string is present in the body, or the body is simply non-empty.

False-positive discipline: the HTML-fallback skip (step 2) is the key guard against SPA catch-all routes that return 200 for everything. Confidence MEDIUM. Evidence is byte count and content-type, never the secret contents.

Severity: HIGH. OWASP: A05:2021 Security Misconfiguration. CWE-538.

---

## Advanced checks

### Server-Side Template Injection (`web.ssti`)

Detects user input evaluated by a server-side template engine. This is the most guarded check in the suite; reproduce all three factors or you will report a false positive.

The code uses two factor pairs `(7919, 6271)` and `(4133, 8017)` whose products are `49638449` and `33134261`, and template payloads:
- SAFE: `{{N1*N2}}` (jinja2/twig/django), `${N1*N2}` (freemarker/groovy)
- AGGRESSIVE also: `#{N1*N2}` (thymeleaf/ruby), `<%= N1*N2 %>` (erb/asp)

```bash
URL="https://target.example/greet"
PARAM="name"

# Step 1 BASELINE with a benign value. If either product already appears, ABORT (false positive).
curl -s -G "$URL" --data-urlencode "${PARAM}=fyabaseline" -o /tmp/ssti_base.txt
grep -qE '49638449|33134261' /tmp/ssti_base.txt && echo "PRODUCTS IN BASELINE - do not test this param"

# Step 2 two-factor confirmation for one template family, e.g. jinja2 {{N1*N2}}
curl -s -G "$URL" --data-urlencode "${PARAM}={{7919*6271}}" -o /tmp/ssti_a.txt
curl -s -G "$URL" --data-urlencode "${PARAM}={{4133*8017}}" -o /tmp/ssti_b.txt
```

Detection signal, all three must hold for BOTH factor pairs of a single template family:
1. Baseline body does NOT already contain either product (guards against a page that happens to print those numbers).
2. Probe A body contains `49638449` and probe B body contains `33134261` (the correct product for each pair).
3. The literal payload text (e.g. `{{7919*6271}}`) does NOT appear in the body. If the raw braces echo back, the template was not evaluated, it was just reflected, so it is rejected.

Confirm by hand:

```bash
grep -q 49638449 /tmp/ssti_a.txt && ! grep -q '{{7919\*6271}}' /tmp/ssti_a.txt \
 && grep -q 33134261 /tmp/ssti_b.txt && ! grep -q '{{4133\*8017}}' /tmp/ssti_b.txt \
 && echo "SSTI CONFIRMED (jinja2 family)"
```

False-positive discipline: baseline plus two distinct factor pairs plus the "literal payload absent" rule together mean a hit is server-side arithmetic, not reflection or coincidence. This is why the code sets Confidence HIGH here (unlike XSS). Do not shortcut to one pair.

Severity: HIGH. OWASP: A03:2021 Injection. CWE-1336.

### Cross-Site Request Forgery (`web.csrf`)

Detects state-changing POST forms with no anti-CSRF token.

The code crawls same-host pages, collects forms whose `method` is POST, and for each checks three defenses. A finding is emitted only if ALL three are absent.

```bash
curl -s "https://target.example/account" -D /tmp/csrf_hdr.txt -o /tmp/csrf.html
# Find POST forms
grep -oiE '<form[^>]*method=["'"'"']?post[^>]*>' /tmp/csrf.html
# Token-like hidden inputs in the form (csrf, xsrf, _token, authenticity_token, csrfmiddlewaretoken, nonce)
grep -oiE 'name=["'"'"'](csrf|xsrf|_token|authenticity_token|csrfmiddlewaretoken|nonce)[^"'"'"'>]*' /tmp/csrf.html
# CSRF meta tag
grep -oiE '<meta[^>]+name=["'"'"'][^"'"'"'>]*(csrf|xsrf)[^"'"'"'>]*' /tmp/csrf.html
# SameSite=Lax/Strict on Set-Cookie
grep -iE 'samesite\s*=\s*(lax|strict)' /tmp/csrf_hdr.txt
```

Detection signal: report only when the POST form has (a) no input whose name matches the CSRF-name regex, AND (b) no `<meta name="...csrf...">` tag on the page, AND (c) no `SameSite=Lax` or `SameSite=Strict` on the `Set-Cookie` header. Any one of the three suppresses the finding.

False-positive discipline: this is heuristic and cannot see server-side validation, custom token names, or double-submit patterns. That is exactly why the code sets Confidence LOW. Treat every hit as "needs manual confirmation," not a proven CSRF.

Severity: MEDIUM, Confidence LOW. OWASP: A01:2021 Broken Access Control. CWE-352.

### Host header injection (`web.host_header`)

Detects the application reflecting an unvalidated `Host` header into its output, enabling password-reset poisoning and cache poisoning.

The code sends a spoofed `Host: MARKER.evil.example` and looks for the marker echoed back.

```bash
MARKER=$(openssl rand -hex 6)
SPOOF="${MARKER}.evil.example"
curl -s -D /tmp/hh_hdr.txt -H "Host: ${SPOOF}" --max-redirs 0 \
  "https://target.example/" -o /tmp/hh_body.html
# Reflected in redirect Location?
grep -i "^location:.*${MARKER}" /tmp/hh_hdr.txt
# Reflected in body or in an absolute link?
grep -F "$MARKER" /tmp/hh_body.html
grep -oiE "https?://[^\"'<> ]*${MARKER}[^\"'<> ]*" /tmp/hh_body.html
```

Note `allow_redirects=False` (do not follow), because the code inspects the `Location` header itself.

Detection signal: the marker appears in any of: the response body, the `Location` redirect header, or an absolute `http(s)://...` link in the body. Any one reflection triggers the finding, and the check stops at the first reflected URL.

False-positive discipline: Confidence MEDIUM. Reflection of the Host into content is suspicious but not always exploitable (some frameworks reflect it harmlessly). Confirm whether the reflected value lands in a security-relevant place such as a reset link or a cached response.

Severity: MEDIUM. OWASP: A05:2021 Security Misconfiguration. CWE-644.

### CRLF / HTTP response splitting (`web.crlf`)

Detects a parameter whose value flows unescaped into a response header, letting an attacker emit their own header. AGGRESSIVE profile only.

The payload injects a CR LF then a test header: `safe\r\nFya-Test: MARKER`.

```bash
MARKER=$(openssl rand -hex 6)
URL="https://target.example/redirect"
PARAM="lang"
# Send the raw CRLF payload; --data-urlencode will percent-encode the CR/LF for transport
curl -s -D /tmp/crlf_hdr.txt -o /dev/null -G "$URL" \
  --data-urlencode "${PARAM}=safe
Fya-Test: ${MARKER}"
grep -i "^Fya-Test:.*${MARKER}" /tmp/crlf_hdr.txt && echo "CRLF INJECTION"
```

Detection signal: the response must come back with an actual `Fya-Test` header containing the marker. The code reads `response.headers.get("Fya-Test")`; the server split the response and emitted an attacker-controlled header. This is unambiguous.

False-positive discipline: because the signal is a real injected response header (not body reflection), the code sets Confidence HIGH. There is little to second-guess: either the header materialized or it did not.

Severity: HIGH. OWASP: A03:2021 Injection. CWE-93.

---

## Hardening checks

These evaluate configuration quality. They are passive reads and inform posture rather than proving exploitability.

### Content-Security-Policy weaknesses (`web.csp_weaknesses`)

Detects a CSP that is present but weakened. Only runs when a CSP header actually exists.

```bash
curl -sD - -o /dev/null "https://target.example/" | grep -i '^content-security-policy:'
```

Parse the policy into directives (split on `;`, first token is the directive name) and check, exactly as the code does:

| Condition | Severity |
| --- | --- |
| `script-src` contains `'unsafe-inline'` | MEDIUM |
| `style-src` contains `'unsafe-inline'` | MEDIUM |
| `script-src`, `style-src`, or `default-src` contains `'unsafe-eval'` | MEDIUM |
| `script-src` or `default-src` contains `*` | MEDIUM |
| `script-src` contains a `data:` source | MEDIUM |
| no `object-src` directive | LOW |
| no `base-uri` directive | LOW |
| neither `default-src` nor `script-src` defined | LOW |

Detection signal: substring presence of the exact tokens within the relevant directive value. All findings are Confidence HIGH (the directive text either contains the token or it does not).

False-positive discipline: the guard is that the check runs only when a CSP is present (an absent CSP is the separate `web.security_headers` finding, not a "weakness"). Report the specific directive value as evidence.

Severity: LOW to MEDIUM. OWASP: A05:2021 Security Misconfiguration. CWE-693.

### JWT decode analysis (`web.jwt_*`)

Detects weaknesses in any JWT the application exposes. The code harvests tokens from the base response: every response header value, every cookie value, and the body, matching the pattern `eyJ...` (three base64url segments). It base64url-decodes the header and payload segments (no signature verification, purely a read).

```bash
# Grab candidate JWTs from headers, cookies, and body
curl -s -D /tmp/jwt_hdr.txt "https://target.example/" -o /tmp/jwt_body.txt
grep -hoE 'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*' \
  /tmp/jwt_hdr.txt /tmp/jwt_body.txt

# Decode header and payload of one token (do NOT print the signature)
TOKEN="eyJ...header.eyJ...payload.sig"
b64url() { local s="$1"; local pad=$(( (4 - ${#s} % 4) % 4 )); printf '%s' "${s}$(printf '=%.0s' $(seq 1 $pad))" | tr '_-' '/+' | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$TOKEN")"; echo   # header
b64url "$(cut -d. -f2 <<<"$TOKEN")"; echo   # payload
```

Three findings, matching the three registered checks:
- `web.jwt_weak_algorithm`: header `alg` is `none` (HIGH, Confidence HIGH, CWE-347) or a symmetric alg `HS256/HS384/HS512` (LOW, Confidence MEDIUM, CWE-347).
- `web.jwt_missing_expiry`: payload has no `exp` claim (LOW, Confidence MEDIUM, CWE-613, A07:2021).
- `web.jwt_sensitive_claims`: a payload claim key matches `password|passwd|secret|ssn|credit|card_number|cardnumber|cvv` (MEDIUM, Confidence MEDIUM, CWE-522).

False-positive discipline: this is decode-only analysis. It never verifies the signature or tries to forge tokens. The `alg=none` finding means the token as issued is unsigned (forgeable), not that you forged anything. The symmetric-alg finding is LOW / MEDIUM because HS256 is not itself a vulnerability, only a weaker posture. Always redact the token: print only the first 8 chars of the header segment plus a length, as the code does (`_redact`). Never log full tokens or signatures.

Severity: LOW to HIGH. OWASP: A02:2021 Cryptographic Failures (and A07 for missing expiry). CWE-347 / 613 / 522.

### Outdated front-end libraries (`web.frontend_libraries`)

Detects known-old client-side JS libraries loaded by the page, which ship publicly documented vulnerabilities.

```bash
curl -s "https://target.example/" | grep -oiE '<script[^>]+src=[^ >]+'
```

Detection signal: the check extracts every `<script src=...>`, matches the filename against library signatures (`jquery`, `angularjs`, `bootstrap`, `vue`, `react`, `lodash`, `moment`, `handlebars`), parses a `major.minor.patch` version from the filename, then assesses:

| Library | Flagged when | Severity |
| --- | --- | --- |
| jQuery | major < 3 | MEDIUM |
| AngularJS | any 1.x (end of life) | MEDIUM |
| Bootstrap | major < 4 | LOW |
| Moment.js | any (maintenance mode) | LOW |
| Vue.js | major < 3 | LOW |
| Handlebars | major < 4 | LOW |
| Lodash | < 4.17 | LOW |

If a library is detected but no version parses from the URL, it emits an INFO / Confidence LOW finding (`detected without a resolvable version`, CWE-1035) rather than guessing.

False-positive discipline: version is read from the filename in the script URL only. Bundled or fingerprinted assets (e.g. `app.a1b2c3.js`) will not parse a version and correctly fall to the INFO case instead of a false "outdated" verdict. Confidence MEDIUM on the versioned findings because the filename version may not reflect the actual shipped code.

Severity: INFO to MEDIUM. OWASP: A06:2021 Vulnerable and Outdated Components. CWE-1104 (CWE-1035 for the unresolved-version case).

### security.txt publication (`web.security_txt`)

Detects the absence of a documented vulnerability-reporting channel.

```bash
curl -s -o /tmp/sec.txt -w '%{http_code}\n' "https://target.example/.well-known/security.txt"
curl -s -o /tmp/sec2.txt -w '%{http_code}\n' "https://target.example/security.txt"
grep -E '^(Contact|Policy):' /tmp/sec.txt /tmp/sec2.txt
```

Detection signal: the check fetches `/.well-known/security.txt` then `/security.txt`. If either returns 200 with a body containing `Contact:` or `Policy:`, it is satisfied and emits nothing. Otherwise it emits an INFO finding.

False-positive discipline: the 200-plus-`Contact:`/`Policy:` content check avoids treating a SPA 200 fallback as a valid security.txt. Confidence HIGH (the file is either there and valid or not). This is informational only.

Severity: INFO. OWASP: A05:2021 Security Misconfiguration. CWE: none.

### robots.txt sensitive path disclosure (`web.robots_sensitive_paths`)

Detects `Disallow` entries that advertise the location of restricted areas.

```bash
curl -s "https://target.example/robots.txt"
```

Detection signal: the check fetches `/robots.txt` (must be 200), reads each non-comment `Disallow:` line, and flags the path value if it contains any of the sensitive hints `admin, backup, config, private, internal, api-docs`.

False-positive discipline: only `Disallow:` lines are considered, comments and blank lines are skipped, and only the sensitive-hint substrings trigger a hit. A `Disallow: /images/` is ignored. Confidence MEDIUM (a hinted path is suggestive, but the path may already be access-controlled). The point is that robots.txt should not be used as a hiding mechanism.

Severity: LOW. OWASP: A05:2021 Security Misconfiguration. CWE-200.
