# Testing strategies: black, gray, and white box

How to run the three knowledge-level modes in a session, with the concrete probes and the
finding each produces. All probes are non-destructive: GET-based reflection and error detection,
read-only source scanning. Never send state-changing requests without explicit confirmation.

## Black box (no internals)

You see only inputs and outputs. Two jobs: functional robustness (does malformed input break it)
and the outside-in security checks already in `web.md` and `tls-api.md`.

### Input fuzzing and robustness

For every discovered parameter (query params, form input names), first fetch the URL with its
real value to get a baseline status and body. Skip it if the baseline is already a 5xx. Then send
each payload and compare:

```
oversized:        a 10,000+ character string
null byte:        %00
format string:    %s%s%s%s%s%n
boundary numbers: -1, 9999999999999999999999, 9223372036854775808, 1e309
type confusion:   []   {}   (array/object where a scalar is expected)
unicode edges:    emoji, RTL override (U+202E), zero-width space (U+200B)
metacharacters:   '"`<>{}$;|)(
```

Two findings:
- **Unhandled input (MEDIUM, CWE-20):** a payload returns 5xx while the benign value did not. The
  input is not validated before use; often a symptom of a deeper injection or type bug.
- **Stack trace disclosed (LOW, CWE-209):** a payload makes the response leak a language or
  framework stack trace (Traceback, `at java.`, `goroutine`, `ReferenceError`, etc.) absent from
  the baseline. Verbose errors reveal internals.

### Boundary and edge cases (from the classic playbook)

Numbers: `0, -1, MAX_INT, MAX_INT+1`, floating point. Strings: empty, one char, exactly max-length,
max+1. Dates: Feb 29, 2038 overflow, DST. Collections: empty, one item, 10k items. Uploads: 0-byte,
exact-limit, wrong extension, executable renamed as an image. Report where behavior is wrong or the
app errors, not merely where input is accepted.

## Gray box (partial knowledge: ids, routes, contracts)

### IDOR (CWE-639)

Find a URL with a small numeric object id (`/account?id=1`, `/api/orders/42`). Fetch the original
(200), fetch an out-of-range id (e.g. `2147483647`) and confirm it is rejected (404/403). Then fetch
a neighbour id (`id-1`, `id+1`). If the neighbour returns 200 with different, existing content, it is
a possible IDOR: you can reach a record you did not create. Confirm ownership manually before calling
it confirmed. Fix: enforce a server-side ownership/authorization check; prefer unguessable ids.

### Auth bypass on protected routes (CWE-306)

Request common administrative and management routes unauthenticated: `/admin`, `/administrator`,
`/dashboard`, `/api/admin`, `/actuator`, `/actuator/env`, `/manage`, `/management`, `/debug`,
`/internal`, `/metrics`. A 200 with substantial content and no login redirect or login form is a
finding: the surface is reachable without auth. Fix: deny by default, require auth on all such routes.

### Also gray box

Try admin-only actions as a low-privilege user, tamper with hidden form fields and client-side state,
and replay old or already-used tokens. API contract probing lives in `tls-api.md`.

## White box (source access)

Point at a local code directory. Walk it, skipping `.git`, `node_modules`, virtualenvs, build output,
and vendored code; skip files over ~1.5 MB and non-text extensions.

### Hardcoded secrets (HIGH, CWE-798)

Regex each text file for: AWS keys (`AKIA[0-9A-Z]{16}`), Google keys (`AIza...`), GitHub tokens
(`gh[pousr]_...`), Slack tokens (`xox...`), Stripe live keys (`sk_live_...`), private key blocks
(`-----BEGIN ... PRIVATE KEY-----`), JWTs, and credential assignments
(`password|secret|api_key = "..."`). Ignore obvious placeholders (`your`, `example`, `changeme`, env
lookups). Redact the value in the report; treat any real hit as compromised and rotate it.

### Risky code patterns (severity per sink, A03 Injection)

Grep code (not comments) for: `eval(`, `exec(`, `subprocess(..., shell=True)`, `os.system(`,
`pickle.loads(`, `yaml.load(` without SafeLoader, `verify=False`, `DEBUG=True`, `hashlib.md5/sha1`,
React `dangerouslySetInnerHTML`, `.innerHTML =`, `document.write(`. Report `file:line` with the line
as evidence; these warrant review in context.

### External analyzers

If `semgrep` is on PATH, run `semgrep scan --config auto --json --quiet <dir>` and fold in results.
Else if `bandit` is present, `bandit -r -f json -q <dir>` for Python. Otherwise note that installing
one enables deeper rule-based analysis, and rely on the built-in scans above.

## Extended web, API, mobile, and source techniques

All non-destructive. Every one uses a differential or a specific content signature, never a bare 200,
to keep false positives near zero.

### Client-side secrets and source maps
Fetch the page, collect inline `<script>` bodies and same-origin `<script src>` bundles. Regex bundles
for provider-anchored secrets (AWS `AKIA[0-9A-Z]{16}`, Stripe `sk_live_...`, GitHub `ghp_...`, SendGrid,
private key blocks). Redact and treat live hits as compromised. Demote publishable keys (Stripe `pk_live_`,
Google `AIza`, Firebase config) to low/info. For each `.js` bundle, read its `//# sourceMappingURL=` or
probe `<bundle>.map`; confirm a real map by `json.loads` succeeding with `version` and `sources` keys.

### VCS, config, and directory exposure
First establish a soft-404 baseline: request a random path; if it 200s the server is a catch-all, abort.
Then validate by content, not status: `/.git/index` starts with `DIRC`, `/.git/config` has `[core]` +
`repositoryformatversion`, `/.svn/wc.db` starts with `SQLite format 3\x00`. Probe config/credential files
(`/.env.production`, `/appsettings.json`, `/web.config`, `/.aws/credentials`, `/id_rsa`, `/.kube/config`)
and require a file-type marker. Detect directory listing by two markers together: an "Index of /" heading
and a `../` parent-directory back-link, with a random-directory negative control.

### Advanced CORS
Send a random control Origin first. If it is reflected verbatim, that is blanket reflection (already the
basic CORS check), so stop. Only when the control is not reflected, send crafted origins and require an
exact-match reflection: `https://<marker><host>` (suffix bug), `https://<host>.<marker>.example` (prefix
bug), `https://<marker>.<host>` (arbitrary subdomain), `Origin: null`, and `http://<host>` (scheme
downgrade). High severity only when Access-Control-Allow-Credentials is true.

### SSRF (signature-based)
For parameters that take URLs (by name or value), baseline with a benign in-scope URL, then inject cloud
metadata (`http://169.254.169.254/latest/dynamic/instance-identity/document`) and `file:///etc/passwd`.
Send these with redirects disabled (a redirect to the payload is open-redirect, not SSRF). Confirm only on
a content signature returned inline that is absent from the baseline: AWS metadata tokens
(accountId + instanceId + region) or `/etc/passwd` (`root:.*:0:0:`). Never treat the reflected payload as proof.

### NoSQL / XPath / LDAP / SSI injection
NoSQL: take two distinct random baselines for a param; if stable, send `param[$ne]=<rand>` (brackets raw)
and flag when the response status or normalized length diverges from both baselines, rejecting reflected
`$ne`. XPath/LDAP: inject `'"` / `)(cn=*)` and flag an engine error signature (org.apache.xpath,
javax.naming.NamingException, bad search filter) absent from baseline. SSI: confirm the param reflects a
plain HTML comment, then send `<!--#echo var="DATE_GMT"-->` and flag when the directive is consumed while
the control comment survives.

### Forwarded-header cache poisoning and URL override
Add a unique `?fya_cb=<marker>` cache-buster to every probe so no shared cache entry is poisoned. Baseline
without the header, then send `X-Forwarded-Host: <marker>.evil.example` and flag when the marker appears in
the body, an absolute link, or the redirect Location and was absent from the baseline (high if cache
indicators are present). For URL override, prove the app routes on `X-Original-URL`/`X-Rewrite-URL` with a
four-request corroboration: baseline 2xx, header-to-bogus-path changes the response, the bogus path is
absent directly, and header-to-root reproduces the baseline.

### GraphQL hardening
Gate on a confirmed endpoint (POST `{__typename}` resolves to a string). Then: a mistyped field
(`{ __typenam }`) returning a "Did you mean" suggestion leaks the schema; a two-element query array that
returns two resolved responses proves batching; a resolved `GET ?query={__typename}` proves GET/CSRF-able
execution. Only ever send `__typename`; never a mutation.

### Mobile (APK) and source
WebView: scan `classes*.dex` strings for `addJavascriptInterface` + `setJavaScriptEnabled` (native bridge)
and `setAllowUniversalAccessFromFileURLs`. Manifest: flag http/https BROWSABLE intent-filters without
`android:autoVerify="true"` (hijackable App Links) and exported components guarded by an app-declared
permission whose protectionLevel is not signature. Source (CI): in `.github/workflows/*.yml`, flag
pull_request_target/workflow_run that checks out the untrusted PR head ref (pwn-request), and untrusted
`${{ github.event.* }}` expressions interpolated into a `run:` shell step (script injection).

## Deliberately excluded: load, stress, network chaos

Do not run load/stress tests (k6, JMeter, Locust patterns) or network-chaos tests (latency, packet
loss, disconnects) from this skill. They are denial-of-service shaped and violate the non-destructive
guarantee. If the user wants them, point them to k6, Locust, or Toxiproxy on infrastructure they own,
and stop.
