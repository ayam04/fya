# TLS and API checks (manual, non-destructive)

This reference tells you how to reproduce the `fya` TLS and API checks by hand, inside a session, using
common tools (curl, openssl, python). Every probe here is read-only or a single malformed-but-harmless
request. Nothing modifies server state. Ground your conclusions in the same detection signals and
false-positive discipline the check code already encodes: do not upgrade confidence past what the signal
proves.

## Discovering testable URLs and respecting scope

Before probing, build a small list of same-host URLs to test. Do a light crawl, not a spider:

1. Fetch the base page and pull links and form actions on the same host only.

```bash
BASE="https://target.example.com"
HOST=$(printf '%s' "$BASE" | sed -E 's#^https?://([^/]+).*#\1#')

curl -s -L "$BASE" \
  | grep -Eoi '(href|action|src)="[^"]+"' \
  | sed -E 's/^[^"]+"//; s/"$//' \
  | while read -r u; do
      case "$u" in
        http*//"$HOST"*|/*) echo "$u" ;;   # same host or root-relative only
      esac
    done \
  | sort -u
```

2. Resolve root-relative paths against `$BASE`, drop anything off-host, and keep the list short. The
   checks below mostly probe fixed paths (`/openapi.json`, `/graphql`, `/actuator`, and so on) appended
   to the base URL, so you rarely need a deep crawl. Note any `/api` prefix you see, because the verbose
   error check tests both `BASE` and `BASE/api`.

Scope and pacing rules:

- Only test hosts you are authorized to test. Stay on the target host; do not follow cross-host redirects
  into third parties.
- Pace requests. One request at a time with a short pause is enough for these checks. The reference
  implementation uses a 6 second socket timeout for TLS work, so treat 6 seconds as a reasonable ceiling
  per connection.
- These probes are non-destructive by design. The only "attack-shaped" traffic is a malformed JSON body
  and a broken query parameter, neither of which writes data.

---

## TLS checks (category: A02:2021 Cryptographic Failures)

The TLS checks run against port 443, plus the target port if the scheme is HTTPS and the port is
non-standard. Test each HTTPS port you found.

### TLS certificate validity and expiry

What it detects and why it matters: a certificate that fails to validate (hostname mismatch, self-signed
or untrusted issuer, expired, or not-yet-valid) or is close to expiry. If the chain cannot be validated,
clients cannot cryptographically confirm they are talking to the intended server.

The code first tries a fully verified handshake. Only if that fails does it re-connect permissively to
read the presented certificate and classify why validation failed. Reproduce that two-step flow.

Step 1, verified handshake (this is the baseline: if it succeeds, the cert is trusted and you only check
dates):

```bash
HOST=target.example.com
PORT=443

# Verified fetch: -verify_return_error makes openssl exit non-zero on a validation failure.
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
  -verify_return_error 2>&1 | sed -n '/Verify return code/p'
```

- `Verify return code: 0 (ok)` means the chain validated. Go to Step 3 (dates only).
- A non-zero verify code means validation failed. Go to Step 2 to classify.

Step 2, permissive fetch to read the cert and read the failure reason:

```bash
# Read the actual presented cert even though it does not validate.
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>&1 \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  | openssl x509 -noout -subject -issuer -dates

# The verify line tells you which failure class it is:
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>&1 \
  | grep -i 'verify'
```

Detection signals and how the code classifies them (match the openssl verify text to these):

- Hostname mismatch: the verify detail contains `hostname`, `match`, or `ip address mismatch`. openssl
  reports this as a verify failure and the subject/subjectAltName does not cover `$HOST`. Severity HIGH,
  CWE-295.
- Self-signed or untrusted: subject equals issuer (self-signed), or the verify text says
  `self signed` / `self-signed`, or `unable to get local issuer certificate`. Severity HIGH, CWE-295.
- Expired: verify text contains `expired`, or the parsed `notAfter` is in the past. Severity CRITICAL,
  CWE-295.
- Not yet valid: parsed `notBefore` is in the future. Severity HIGH, CWE-295.

Step 3, expiry window (applies whether the cert validated or not, once you have `notAfter`):

```bash
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>&1 \
  | openssl x509 -noout -enddate
# Then: is enddate in the past (CRITICAL expired) or within 30 days (MEDIUM expiring soon)?

# Convenience: openssl can answer "expires within 30 days?" directly.
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>&1 \
  | openssl x509 -noout -checkend 2592000 \
  && echo "cert valid for at least 30 more days" \
  || echo "cert expires within 30 days (or already expired)"
```

- Expired (`notAfter` before now): CRITICAL, CWE-295.
- Expiring within 30 days: MEDIUM (title "TLS certificate expiring soon"), CWE-295. The code uses a
  30-day window (`_EXPIRY_WINDOW_DAYS`).

Python fallback (verified handshake, mirrors `_fetch_verified_cert`):

```bash
python - <<'PY'
import ssl, socket, datetime
host, port = "target.example.com", 443
ctx = ssl.create_default_context()
try:
    with socket.create_connection((host, port), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
            na = cert.get("notAfter")
            exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            print("VERIFIED OK. subject", cert.get("subject"),
                  "notAfter", na, "days_left", days,
                  "(<=30 => expiring soon)" if days <= 30 else "")
except ssl.SSLCertVerificationError as e:
    print("VERIFY FAILED:", e)   # classify: hostname / self-signed / expired
except ssl.SSLError as e:
    print("SSL ERROR:", e)
except (socket.timeout, ConnectionError, OSError) as e:
    print("UNREACHABLE:", e)     # code treats this as no finding
PY
```

False-positive discipline:

- If the host is simply unreachable (timeout, connection refused), that is NOT a finding. The code returns
  silently on `unreachable`. Do not report a TLS problem you could not observe.
- Always do the verified handshake first. A cert that validates cleanly should only ever produce an
  expiry finding, never a mismatch or self-signed finding.
- The failure class comes from the verify text plus the parsed cert, not from guesswork. If you cannot
  read the presented cert and cannot get a specific verify reason, do not invent a category.

Severity: HIGH (mismatch, self-signed, not-yet-valid), CRITICAL (expired), MEDIUM (expiring soon).
Category: A02:2021 Cryptographic Failures. CWE: CWE-295 (Improper Certificate Validation).

### Weak TLS protocol versions

What it detects and why it matters: the server completes a handshake using TLS 1.0 or TLS 1.1, deprecated
protocols with known cryptographic weaknesses that should no longer be accepted.

Probe each legacy version by forcing it and seeing whether the handshake completes. The code disables cert
verification for this test (it cares only about protocol acceptance), so ignore cert errors here.

```bash
HOST=target.example.com
PORT=443

# TLS 1.0
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1 2>&1 \
  | grep -Ei 'Protocol|handshake failure|no protocols available'

# TLS 1.1
echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -tls1_1 2>&1 \
  | grep -Ei 'Protocol|handshake failure|no protocols available'
```

Detection signal: the handshake succeeds under the forced version. In openssl output that shows as a
completed session with, for example, `Protocol  : TLSv1` (or `TLSv1.1`) in the session block, and no
`handshake failure`. That is exactly the code's signal: a successful handshake at that version is the
finding.

If your local openssl is too new to offer `-tls1` / `-tls1_1`, use python to force the exact version
(mirrors `_handshake_succeeds`):

```bash
python - <<'PY'
import ssl, socket
host, port = "target.example.com", 443
for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
    try:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, AttributeError, ssl.SSLError):
        print(label, "not offerable by local ssl"); continue
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                print(label, "HANDSHAKE SUCCEEDED -> finding")
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
        print(label, "refused (good)")
PY
```

False-positive discipline:

- A `handshake failure`, `no protocols available`, or connection error means the server refused that
  version. That is the desired state, not a finding.
- If your own client library cannot even offer TLS 1.0/1.1 (modern OpenSSL builds disable them), you
  cannot test it. Report "could not test", not "not vulnerable" and not "vulnerable".

Severity: MEDIUM. Category: A02:2021 Cryptographic Failures. CWE: CWE-327 (Use of a Broken or Risky
Cryptographic Algorithm).

### Missing HTTP to HTTPS upgrade

What it detects and why it matters: HTTPS is reachable on the host, but plaintext HTTP does not redirect to
it, so traffic can stay in cleartext and is exposed to interception and downgrade.

This check only applies when the target scheme is HTTP. It has a required precondition: HTTPS must be
reachable on port 443 first. If HTTPS is not reachable, there is no finding.

Step 1, confirm HTTPS is reachable (the code's guard, using a permissive handshake):

```bash
HOST=target.example.com
echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>&1 | grep -qi 'CONNECTED' \
  && echo "HTTPS reachable" || echo "HTTPS not reachable -> no finding"
```

Step 2, request the plaintext HTTP root without following redirects and read the status and Location:

```bash
curl -s -i -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  --max-redirs 0 "http://$HOST/"

# Or see the headers directly:
curl -s -D - -o /dev/null "http://$HOST/"   # look at Status line and Location header
```

Detection signal: it is a redirect-to-HTTPS (and therefore NOT a finding) only when the status is one of
301, 302, 303, 307, 308 AND the `Location` header value starts with `https://`. Anything else (a 200 served
over HTTP, a redirect that stays on `http://`, or no Location) is the finding.

False-positive discipline:

- Do not report this if HTTPS on 443 is unreachable. The whole point is that a secure alternative exists
  and is not enforced.
- Use `allow_redirects=false` / `--max-redirs 0`. You must observe the first hop; a client that silently
  follows the redirect will hide whether the upgrade happened.
- A same-scheme redirect (`http://` to `http://`) still counts as missing upgrade. Only an `https://`
  Location clears it.

Severity: MEDIUM. Category: A02:2021 Cryptographic Failures. CWE: CWE-319 (Cleartext Transmission of
Sensitive Information).

---

## API checks (category: A05:2021 Security Misconfiguration)

These probe fixed paths on the base URL. All are GET or a single POST. None write data.

### OpenAPI / Swagger specification exposure

What it detects and why it matters: an API spec or docs UI reachable without authentication, which exposes
the full endpoint surface, parameters, and data models and lowers the effort to enumerate and attack the
API.

Paths the code probes (appended to the base URL): `/openapi.json`, `/swagger.json`, `/api-docs`,
`/v2/api-docs`, `/swagger-ui.html`.

```bash
BASE="https://target.example.com"
for p in /openapi.json /swagger.json /api-docs /v2/api-docs /swagger-ui.html; do
  echo "=== $p ==="
  curl -s -i "$BASE$p" | sed -n '1,20p'
done
```

Detection signal (must be HTTP 200 first, then one of):

- JSON spec: the body parses as a JSON object that contains an `openapi` key, a `swagger` key, or a
  `paths` object. This is the high-confidence case. Quick test:

```bash
curl -s "$BASE/openapi.json" \
  | python -c 'import sys,json; d=json.load(sys.stdin); print("SPEC" if isinstance(d,dict) and ("openapi" in d or "swagger" in d or isinstance(d.get("paths"),dict)) else "not a spec")'
```

- Swagger UI: the path ends in `.html` AND the body (lowercased) contains `swagger`. This is the
  medium-confidence case (a UI page, not the raw spec).

False-positive discipline:

- A 200 alone is not enough. A generic HTML page or a 200 that is not a recognizable spec is not a
  finding. The body must actually parse as a spec (JSON case) or be a Swagger UI page.
- Confidence follows the signal: HIGH for a parsed JSON spec, MEDIUM for a UI page detected only by the
  word `swagger` in HTML.

Severity: MEDIUM. Category: A05:2021 Security Misconfiguration. CWE: CWE-200 (Exposure of Sensitive
Information).

### GraphQL introspection enabled

What it detects and why it matters: a GraphQL endpoint answers introspection queries and returns its full
schema, letting an attacker map every type, query, and mutation and speeding discovery of sensitive
operations.

Paths probed: `/graphql`, `/api/graphql`. Send the minimal introspection query the code uses via POST:

```bash
BASE="https://target.example.com"
for p in /graphql /api/graphql; do
  echo "=== $p ==="
  curl -s -X POST "$BASE$p" \
    -H 'Content-Type: application/json' \
    -d '{"query":"query{__schema{queryType{name}}}"}'
  echo
done
```

Detection signal (all must hold, mirroring the code): status 200, the body contains the literal
`__schema`, the body parses as JSON, and `data.__schema` is a JSON object. A quick strict check:

```bash
curl -s -X POST "$BASE/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{queryType{name}}}"}' \
  | python -c 'import sys,json;
try:
    d=json.load(sys.stdin)
    s=(d.get("data") or {}).get("__schema")
    print("INTROSPECTION ENABLED" if isinstance(s,dict) else "not exposed")
except Exception:
    print("not JSON / not exposed")'
```

False-positive discipline:

- The literal string `__schema` echoed back in an error message is not enough. The code requires
  `data.__schema` to actually be an object, which means introspection genuinely resolved. An error body
  like `{"errors":[{"message":"introspection disabled"}]}` does not match.
- A non-200 status is not a finding.

Severity: MEDIUM. Confidence HIGH. Category: A05:2021 Security Misconfiguration. CWE: CWE-200.

### Verbose error / stack trace disclosure

What it detects and why it matters: a malformed request causes the app to return a stack trace or framework
debug page, leaking internal paths, dependency versions, and query structure that assist further attacks.

This check REQUIRES a baseline to avoid false positives. For each target URL (the code tests both `BASE`
and `BASE/api`), first fetch a normal GET response, then send two malformed probes, and only report a
signature that appears in a probe response but NOT in the baseline.

```bash
BASE="https://target.example.com"
for URL in "$BASE" "$BASE/api"; do
  echo "=== target $URL ==="

  # BASELINE: normal GET. Keep this body to subtract known-good text.
  curl -s "$URL" -o /tmp/fya_baseline.txt

  # Probe 1: malformed JSON body (post_bad_json)
  curl -s -X POST "$URL" \
    -H 'Content-Type: application/json' \
    --data '{not valid json' -o /tmp/fya_probe1.txt

  # Probe 2: broken query parameter (get_broken_param), id=' " [ ] { }
  curl -s -G "$URL" --data-urlencode "id='\"[]{}" -o /tmp/fya_probe2.txt

  echo "-- probe1 diff signatures --"; diff <(cat /tmp/fya_baseline.txt) /tmp/fya_probe1.txt >/dev/null || true
done
```

Detection signals. The code looks for two tiers of signatures:

- Specific signatures (match on presence alone): `Traceback (most recent call last)`,
  `Werkzeug Debugger`, `NullPointerException`.
- Framed signatures (require stack framing to also be present in the body): `at java.`,
  `syntax error at line`. "Stack framing" means one of: a stack-frame pattern like `at Foo.bar(` or
  `at ...(...)`; an absolute file path with an extension (`/var/www/app.py`, `C:\app\Main.java`); two or
  more `at ` frames; or a `line N` reference together with a file path.

Grep the probe output for those, then subtract the baseline:

```bash
SIGS='Traceback \(most recent call last\)|Werkzeug Debugger|NullPointerException|at java\.|syntax error at line'
for f in /tmp/fya_probe1.txt /tmp/fya_probe2.txt; do
  echo "== $f =="
  grep -Eo "$SIGS" "$f" | while read -r sig; do
    # Only a finding if the SAME signature is absent from the baseline.
    grep -qF "$sig" /tmp/fya_baseline.txt && echo "$sig (also in baseline -> IGNORE)" || echo "$sig (NEW -> finding)"
  done
done
```

False-positive discipline:

- The baseline subtraction is mandatory. If the signature already appears in the normal response, it is
  not disclosure caused by your probe. The code explicitly skips any match that is also in the baseline
  body.
- Framed signatures (`at java.`, `syntax error at line`) alone are not enough. They only count when the
  body also shows real stack framing (file path, multiple `at ` frames, or a `line N` plus a path).
  This keeps a stray "at java" in prose from tripping the check.
- Confidence is MEDIUM: a leaked trace is strong evidence of misconfiguration, but the check does not
  attempt to prove exploitability beyond the disclosure itself.
- De-duplicate by signature. Reporting the same stack-trace signature once is enough.

Severity: MEDIUM. Confidence MEDIUM. Category: A05:2021 Security Misconfiguration. CWE: CWE-209
(Generation of Error Message Containing Sensitive Information).

### Unauthenticated admin / actuator / debug / metrics endpoints

What it detects and why it matters: a management, debug, or metrics endpoint responds without
authentication, often exposing configuration, health, environment, and internal state that should not be
publicly reachable.

Paths probed: `/actuator`, `/actuator/health`, `/debug`, `/console`, `/metrics`.

```bash
BASE="https://target.example.com"
for p in /actuator /actuator/health /debug /console /metrics; do
  echo "=== $p ==="
  curl -s -i "$BASE$p" | sed -n '1,15p'
done
```

Detection signal (status must be 200 first, then it "looks like management" if any of these hold, matching
the code):

- the `Content-Type` contains `json`, or
- the path is one of `/actuator`, `/actuator/health`, `/metrics` (these are treated as management by path
  regardless of content type), or
- the response body (lowercased) contains `status`.

```bash
curl -s -i "$BASE/actuator/health" | sed -n '1,15p'
# Finding if: HTTP 200 AND (content-type has json  OR  path in the actuator/metrics set  OR  body has "status")
```

False-positive discipline:

- Confidence is LOW by design. A 200 on `/console` or `/debug` that is not JSON and does not contain
  `status` is not reported. The path-based allowance is limited to the actuator/metrics set; other paths
  need the JSON content type or the `status` keyword.
- A 200 alone is not sufficient; a generic HTML 200 on `/debug` does not qualify unless it carries a
  management signal. Do not over-report: treat these as leads to confirm, given the LOW confidence.
- A non-200 (401, 403, 404, redirect to login) means the endpoint is protected or absent, not a finding.

Severity: MEDIUM. Confidence LOW. Category: A05:2021 Security Misconfiguration. CWE: CWE-497 (Exposure of
Sensitive System Information to an Unauthorized Control Sphere).
