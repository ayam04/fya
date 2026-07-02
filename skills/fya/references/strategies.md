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

## Deliberately excluded: load, stress, network chaos

Do not run load/stress tests (k6, JMeter, Locust patterns) or network-chaos tests (latency, packet
loss, disconnects) from this skill. They are denial-of-service shaped and violate the non-destructive
guarantee. If the user wants them, point them to k6, Locust, or Toxiproxy on infrastructure they own,
and stop.
