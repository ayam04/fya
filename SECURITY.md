# Security policy

`fya` is an active security scanner. It sends real probes to a running target
and, at higher profiles, hands off to external tools that do the same. This
document explains what `fya` is authorized to do, the safety model built into
the code, and how to report a vulnerability in `fya` itself.

## Responsible use and authorized testing

Only scan systems you own or are explicitly authorized in writing to test.
Unauthorized scanning may be illegal in your jurisdiction. You alone are
responsible for how you use this tool.

Before you run `fya` against anything you do not personally own:

- Get written permission that names the target scope and the testing window.
- Confirm the target is in scope. Do not scan shared infrastructure, third
  party services, or hosts you cannot positively identify as authorized.
- Prefer a staging or non production environment when one exists.
- Coordinate with the owner so your traffic is not mistaken for an attack.

`fya` prints an authorization notice and the reason it allowed or refused each
scan. Read it. If it says a target is out of scope, it is telling you the tool
will not proceed without the explicit flag described below.

## The built-in safety model

Safety is enforced in code, not just in documentation. The relevant pieces:

### Non-destructive by default

Every built-in check is read-oriented or sends benign, self-identifying
probes. `fya` does not attempt to modify, delete, or corrupt target data.
Concrete examples from the shipped checks:

- Injection checks (`web.reflected_xss`, `web.sql_injection`,
  `web.path_traversal`) send a single distinctive marker or a quote character
  and inspect the response. They do not run destructive payloads and do not try
  to extract data at scale.
- The open redirect check points at a non-routable example host
  (`fya-oob.example`) and only reads the `Location` header.
- The CORS, header, cookie, TLS, and API checks read responses and metadata.
- APK checks are fully local static analysis of the `.apk` archive and its
  manifest. Nothing is sent anywhere.

Probes carry an identifying User-Agent (`fya/<version>`) and injection markers
are generated with a random `fya`-prefixed token so their traffic is easy to
recognize in logs.

### Localhost is allowed, remote requires explicit consent

The authorization gate lives in `fya/authorization.py` and `fya/detect.py`:

- Local targets are allowed without any flag. A host counts as local when it is
  `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, any private or loopback IP
  address, or a `.local` name.
- APK analysis is always allowed because it is local file inspection.
- Any target that is not local is refused unless you pass `--i-am-authorized`,
  which is your assertion that you hold written permission to test it.

If a non-local target is supplied without the flag, `fya` refuses to scan and
exits without sending probes.

### Adaptive request pacing, no denial of service

`fya` never floods a target and ships no denial-of-service payloads. The HTTP
client in `fya/http.py` (`AdaptiveHTTP`) is self-throttling:

- Requests are serialized through a monotonic rate gate with a small base
  interval (0.05s) that adapts between that floor and a 3.0s ceiling.
- On any request failure, a slow response (over 2.5s), or a backpressure status
  (`429`, `502`, `503`, `504`), the interval is multiplied up so the tool backs
  off automatically.
- On healthy, fast responses the interval eases back down.
- Retries are capped (total of 2 with backoff) and never raise on status.

The scan engine runs checks concurrently through a bounded thread pool (default
8 workers), but every request they make still passes through the single shared
adaptive gate, so concurrency cannot defeat the pacing. Crawling is bounded by
per-profile caps (25 URLs in `safe`, 60 in `aggressive`).

### Profiles gate how much probing happens

Profiles are ordered `passive` < `safe` < `aggressive` and each check declares a
minimum profile:

- `passive`: read-only. Headers, TLS, cookies, version and file disclosure,
  fingerprinting. No active injection.
- `safe` (default): non-destructive active probes. Reflection, error signatures,
  CORS, redirects, sensitive paths, API surface.
- `aggressive`: heavier probing and handoff to external tools. Still
  non-destructive.

### External tool handoff is opt-in and version-checked

External tools (`nuclei`, `nikto`, `sqlmap`, `nmap`, `testssl.sh`, `sslyze`,
`jadx`, `apkleaks`) are only invoked at the `aggressive` profile and only when
present on `PATH`. Detection can be turned off entirely with `--no-tools`. Each
subprocess runs with a bounded timeout and its output is folded into the normal
report. `fya` passes conservative flags to these tools (for example sqlmap runs
at `--level 1 --risk 1 --batch`).

## Reporting a vulnerability in fya itself

If you find a security bug in `fya` (for example a check that behaves
destructively, a way to bypass the authorization gate, a path that can be made
to attack an unintended host, or unsafe handling of external tool output),
please report it responsibly.

- Open a report at the project issue tracker:
  https://github.com/ayam04/fya/issues
- For a sensitive report you would rather not disclose publicly, mark the issue
  minimal and request a private channel, or contact the maintainer through the
  contact listed on the GitHub profile at https://github.com/ayam04.
- Include the `fya` version (`fya --version`), your OS and Python version, the
  exact command, the target kind and profile, and a minimal reproduction.
- Do not include real secrets, real target data, or credentials in the report.

Please give the maintainer a reasonable window to respond and ship a fix before
any public disclosure. Reports that describe a concrete impact and a clear
reproduction are the most useful.

## Scope of this policy

This policy covers the `fya` code in this repository. It does not cover the
external tools `fya` can hand off to; report issues in those to their
respective projects. It does not authorize any testing on your behalf; the
responsibility for lawful, authorized use remains with the operator.
