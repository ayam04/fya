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
| Advanced CORS bypass (null origin, prefix/suffix match, scheme downgrade) | medium - high | A05 Security Misconfiguration | CWE-942 |
| Dangerous HTTP methods | low - medium | A05 Security Misconfiguration | CWE-650 |
| Sensitive file exposure (.env, .git, backups) | high | A05 Security Misconfiguration | CWE-538 |

## Web advanced (min profile: safe, CRLF at aggressive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Server-side template injection (SSTI) | high | A03 Injection | CWE-1336 |
| Missing CSRF token | medium (confidence low) | A01 Broken Access Control | CWE-352 |
| Host header injection | medium | A05 Security Misconfiguration | CWE-644 |
| CRLF / header injection | high | A03 Injection | CWE-93 |
| Unkeyed forwarded-header cache poisoning (X-Forwarded-Host) | medium - high | A05 Security Misconfiguration | CWE-644 |
| X-Original-URL / X-Rewrite-URL access-control bypass | high | A01 Broken Access Control | CWE-284 |

## Web secrets and files (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Secrets in client-side JavaScript (AWS, Stripe, GitHub, private keys, etc.) | high - critical | A07 Identification and Authentication Failures | CWE-798 |
| Exposed JavaScript source maps | low - medium | A05 Security Misconfiguration | CWE-540 |
| Dumpable version-control repo (.git/.svn/.hg/.bzr) | high | A05 Security Misconfiguration | CWE-527 |
| Exposed config / credential files (.env.*, appsettings, web.config, id_rsa, kubeconfig) | high | A05 Security Misconfiguration | CWE-538 |
| Directory listing enabled | low - medium | A05 Security Misconfiguration | CWE-548 |

## Web SSRF and injection (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| SSRF via cloud metadata and file:// (signature-based) | high - critical | A10 Server-Side Request Forgery | CWE-918 |
| NoSQL injection (MongoDB operator, boolean differential) | high (confidence low - medium) | A03 Injection | CWE-943 |
| XPath / LDAP / SSI injection (error signatures + reflection) | high | A03 Injection | CWE-643, 90, 97 |

## Web hardening (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| CSP policy weaknesses (unsafe-inline, unsafe-eval, wildcard, data:) | low - medium | A05 Security Misconfiguration | CWE-693 |
| JWT weak algorithm (none / symmetric) | low - high | A02 Cryptographic Failures | CWE-347 |
| JWT missing expiry | low | A07 Identification and Authentication Failures | CWE-613 |
| JWT sensitive claims | medium | A02 Cryptographic Failures | CWE-522 |
| Outdated JS libraries | info - medium | A06 Vulnerable and Outdated Components | CWE-1104 |
| Missing COOP / CORP / Permissions-Policy (HTML documents) | info - low | A05 Security Misconfiguration | CWE-693, 1021 |
| Cookie prefix misuse (__Host-/__Secure-) and overly broad Domain | low - medium | A05 Security Misconfiguration | CWE-732 |
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
| GraphQL hardening (field suggestions, batching, GET/CSRF) | medium | A05 Security Misconfiguration | CWE-200, 770, 352 |
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
| Risky code patterns: eval, exec, shell=True, pickle, verify=False (min profile: passive) | low - high | A03 Injection / A02 / A08 | CWE-95, 78, 502, 295, 79 |
| Dangerous GitHub Actions workflows (pwn-request, script injection) (min profile: passive) | high | A08 Software and Data Integrity Failures | CWE-94 |
| External static analysis via semgrep or bandit (min profile: safe) | info - high | A06 Vulnerable and Outdated Components | varies |

## APK static (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Hardcoded secrets | high | MASVS-STORAGE | CWE-798 |
| Cleartext HTTP endpoints | low | MASVS-NETWORK | CWE-319 |
| Manifest issues (debuggable, allowBackup, exported, cleartext, minSdk, permissions) | info - high | MASVS-PLATFORM/STORAGE/NETWORK/CODE | CWE-489, 530, 319, 926 |
| Unverified App Links (http/https without autoVerify) | medium | MASVS-PLATFORM | CWE-927 |
| Exported component guarded by a weak custom permission | high | MASVS-PLATFORM | CWE-280 |
| Insecure WebView (JavaScript bridge, file access) | medium - high | MASVS-PLATFORM | CWE-749 |

## Web injection, advanced (min profile: aggressive; blind SQLi at safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| OS command injection (arithmetic output oracle + time delay) | critical | A03 Injection | CWE-78 |
| Blind SQL injection (boolean / time based) | critical | A03 Injection | CWE-89 |
| XML External Entity (in-band file disclosure) | high | A05 Security Misconfiguration | CWE-611 |
| Local file inclusion via stream wrappers (php://filter, data://) | high | A03 Injection | CWE-98 |
| NoSQL operator injection in JSON bodies | high | A03 Injection | CWE-943 |

How to run each (probe, then the signal that confirms it):

- **OS command injection** — inject shell metacharacters into query params with an
  arithmetic payload, e.g. `;expr 7 \* 191`, `|expr ...`, `$(expr ...)`, backticks,
  `&& expr ...`, using two independent factor pairs. First capture a clean baseline
  body. Confirm execution only when *both* factor pairs return their product (e.g.
  `1337` and `221`) in the response **and** the literal payload text is not reflected
  and the product is not already in the baseline (reflection alone is the negative
  control and must not fire). Fallback: a two-trial time-delay oracle (`;sleep 6`,
  `` `sleep 6` ``, `& ping -n 6 127.0.0.1`) that must beat a zero-delay control by a
  wide margin on both trials.
- **Blind SQL injection** — send numeric and quoted tautology pairs: TRUE
  (`1 AND 1=1`, `' OR '1'='1`) vs FALSE (`1 AND 1=2`, `' AND '1'='2`). Establish a
  stable baseline first; confirm when TRUE responses match the baseline shape while
  FALSE responses diverge (status / length / content). Aggressive adds timing:
  `' AND SLEEP(5)-- -`, ` AND pg_sleep(5)--`, `'; WAITFOR DELAY '0:0:5'--`, each
  measured against a `SLEEP(0)` control and required to exceed it by >4.5s on two
  trials. Targets endpoints that emit no database error text.
- **XXE** — POST XML to candidate endpoints in two steps. Step 1 proves the parser
  expands an internal entity: `<!DOCTYPE r [<!ENTITY e "MARKER">]><r>&e;</r>` and the
  MARKER must be echoed (endpoints that do not parse XML are the negative control and
  are skipped). Step 2 reads a file with a SYSTEM entity
  (`<!ENTITY e SYSTEM "file:///etc/passwd">` or `file:///c:/windows/win.ini`) and
  matches the file signature (`root:.*:0:0:` / `[fonts]`) in the response.
- **LFI via stream wrappers** — test include-style params with
  `php://filter/convert.base64-encode/resource=index.php` (also `/etc/passwd` and the
  param's original value); confirm when a base64 run in the response decodes to PHP
  source or /etc/passwd content. Also `data://text/plain,<marker>`: confirm only when
  the marker is echoed, `data://` itself is not reflected, and the marker was not in
  the baseline.
- **NoSQL operator injection** — replace a scalar JSON field (username, email, id, q,
  ...) with MongoDB operators `{"$ne":null}`, `{"$gt":""}`, `{"$regex":".*"}`. Send
  the scalar baseline twice to confirm the response is stable; report only when the
  operator response moves toward the success shape, or keeps its status code but
  changes materially versus that two-sample baseline.

## Web exposure and misconfiguration (min profile: safe)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Unauthenticated Spring Boot Actuator secret/memory endpoints | medium - high | A05 Security Misconfiguration | CWE-497 |
| Exposed phpinfo / server-status / Werkzeug debug console | medium - high | A05 Security Misconfiguration | CWE-200, 489 |
| Backup and editor-temporary source file exposure | high | A05 Security Misconfiguration | CWE-530 |
| OAuth / OIDC discovery-document misconfiguration | low - high | A02 Cryptographic Failures / A07 | CWE-287, 319, 327, 347 |
| Exposed SOAP WSDL service contract | medium | A05 Security Misconfiguration | CWE-200 |

- **Actuator** — GET Actuator paths under `/actuator` and at the root
  (`env`, `configprops`, `threaddump`, `mappings`, `beans`, `loggers`, `heapdump`).
  Report only content-validated bodies, not a bare HTTP 200: hprof magic bytes for
  `/heapdump`, specific JSON keys for the rest. High for `env`, `configprops`,
  `heapdump`; medium for `threaddump`, `mappings`, `beans`, `loggers`.
- **Debug info pages** — GET a fixed set of diagnostic paths; confirm by the signature
  unique to each page rather than a bare 200. High for phpinfo() output (CWE-200) and
  the Werkzeug interactive debugger (CWE-489); medium for Apache mod_status and
  mod_info (CWE-200).
- **Backup files** — append backup/editor suffixes (`.bak`, `.old`, `~`; aggressive
  adds `.orig`, `.save`, `.swp`, `.tmp`, `.copy`) to crawled and well-known source
  paths. Report a hit only when the body is raw source (or a vim swap file) **and it
  differs from the live file at the same path** — the diff against the live response
  is the negative control against servers that serve the rendered page for any suffix.
- **OIDC misconfig** — GET the discovery document
  (`/.well-known/openid-configuration`). Report: cleartext http endpoints (high,
  CWE-319), `id_token` signing alg `none` (high, CWE-347), implicit flow supported
  (medium, CWE-287), HS256-only signing (medium, CWE-327), no S256 PKCE method (low),
  resource-owner password grant enabled (low, CWE-287).
- **SOAP WSDL** — GET `?wsdl` on common service paths and on any crawled `.asmx`;
  confirm an unauthenticated contract by a `wsdl:definitions` root, a `definitions`
  element in the WSDL namespace, or a `text/xml` body carrying SOAP elements.

## Web crypto and data integrity (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| JWT signed with a crackable HMAC secret (offline) | critical | A02 Cryptographic Failures | CWE-347 |
| JWT jku / x5u / kid header injection surface | low - medium | A02 Cryptographic Failures | CWE-91, 347 |
| Weak certificate key size or signature algorithm | high | A02 Cryptographic Failures | CWE-326, 327 |
| Active mixed content on an HTTPS page | low - high | A05 Security Misconfiguration | CWE-319 |
| Serialized-object blobs in cookies, tokens and hidden fields | low - medium | A08 Software and Data Integrity Failures | CWE-502 |

- **JWT weak secret** — take JWTs the app already exposes and recompute the
  HS256/384/512 signature offline against a short wordlist of common and default
  signing secrets; report when one secret reproduces the token's signature. Fully
  offline — no extra request.
- **JWT header injection** — decode the header of exposed JWTs; report a `jku`/`x5u`
  key URL fetched over plaintext http or hosted outside the target's own registrable
  domain (medium/low), and a `kid` containing path-traversal or SQL/command
  metacharacters (medium).
- **Certificate strength** — fetch the TLS cert on port 443 (and the target port when
  https) and report an RSA/DSA key below 2048 bits or an EC key below 224 bits
  (CWE-326), or a certificate signed with MD5 or SHA-1 (CWE-327). Both at high.
- **Mixed content** — parse the HTTPS landing page and report subresources loaded over
  plaintext `http://`. High for active ones (script, iframe, stylesheet, modulepreload,
  preload with as=script/style/worker/serviceworker/sharedworker/document); low for
  passive ones (images, media, css `url()`, icons, manifests).
- **Serialized objects** — scan cookies, hidden form fields, link query params and JSON
  string values for native serialized formats: Java `rO0AB`/`0xACED`, Ruby Marshal, PHP
  `serialize`, node-serialize function payloads (medium), and an ASP.NET `__VIEWSTATE`
  that decodes to an unencrypted ObjectStateFormatter stream (low; normally
  MAC-protected).

## White box: IaC and supply chain (source directory, min profile: passive)

All checks parse files offline. Every finding drops one severity level (and its
confidence to low) when the file sits under a test/example/fixture path — this
test-path discount is the built-in false-positive control; keep it.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Dockerfile builds a root, floating-tag or secret-baked image | info - high | A05 / A07 / A08 | CWE-250, 494, 732, 798, 829 |
| Kubernetes manifest grants privileged / host-namespace / wildcard-RBAC access | info - critical | A05 Security Misconfiguration | CWE-250, 269, 732, 770 |
| Terraform provisions internet-exposed, public or unencrypted infra | info - high | A01 / A02 / A07 / A09 | CWE-269, 284, 311, 732, 778, 798 |
| docker-compose privileged / docker-socket / exposed-datastore service | info - critical | A05 / A07 | CWE-250, 668, 732, 798, 1188 |
| CI pipeline uses unpinned actions or runs privileged on untrusted input | low - high | A03 / A05 / A07 / A08 / A09 | CWE-94, 269, 494, 522, 532, 732, 798 |
| Dependencies resolved over plaintext or verification-disabled channels | info - high | A02 / A08 | CWE-295, 319, 494 |

- **Dockerfile hardening** — parse Dockerfiles/Containerfiles. Report a final stage
  that never drops root (medium, CWE-250), a base image with no digest or a `:latest`
  tag (low, CWE-829), `ADD` from a remote URL and a `RUN` that pipes a download into a
  shell or disables cert checks (medium, CWE-494), a literal credential in `ENV`/`ARG`
  (high, CWE-798), and `chmod 777` (low, CWE-732).
- **Kubernetes** — read YAML manifests. Critical for a container-runtime socket
  hostPath; high for privileged containers, shared host namespaces, escape-capable
  Linux capabilities, a sensitive hostPath and wildcard RBAC; medium for
  allowPrivilegeEscalation, runAsUser 0 and a ClusterRole reading all secrets; low for
  automountServiceAccountToken. "No resource limits" and "no securityContext" are
  always info. Templated `{{...}}` manifests take the test-path discount.
- **Terraform** — parse `.tf`/`.tfvars` with a brace-matching HCL reader. High for
  security groups opening admin/datastore ports to `0.0.0.0/0` (CWE-284), public object
  storage (CWE-732), a public database (CWE-284), a wildcard IAM policy (CWE-269) and
  hardcoded credentials (CWE-798); medium for an unconditional `Principal:*` policy and
  explicitly disabled encryption (CWE-311); low for disabled audit logging (CWE-778)
  and an unencrypted S3 state backend. "Encryption at rest not declared" is always info.
- **docker-compose** — segment by service. Critical for a Docker-socket mount; high for
  privileged, host pid/ipc/userns, a `/` bind mount, escape-capable `cap_add`,
  unconfined seccomp/AppArmor, a published datastore port, disabled DB auth
  (empty-password/trust) and a hardcoded credential; medium for `network_mode: host`;
  low for `user: root`. `.test`/`.ci`/`.dev`/`.local` compose files take the discount.
- **CI supply chain** — read GitHub Actions, composite actions, CircleCI, GitLab,
  Azure, Bitbucket and Jenkins files. High for an action pinned to a branch (CWE-494),
  `ACTIONS_ALLOW_UNSECURE_COMMANDS` (CWE-94), a `pull_request_target` job on a
  self-hosted runner (CWE-269), a re-evaluated GitLab `CI_COMMIT_*` shell variable
  (CWE-94) and a literal GitLab CI secret (CWE-798); medium for an action pinned to a
  tag, `permissions: write-all` (CWE-732), a logged secret (CWE-532), `curl|sh`
  (CWE-494), `secrets: inherit` (CWE-522) and a `pull_request` job on a self-hosted
  runner; low for a workflow using third-party actions with no permissions block. Here
  a test path lowers confidence only, never severity.
- **Insecure package source** — inspect package-manager config (`.npmrc`, `pip.conf`,
  `pyproject.toml`, `Gemfile`, `pom.xml`, `build.gradle`, `nuget.config`,
  `package.json`, `requirements.txt`, Dockerfiles). High for a plaintext registry/index
  URL (CWE-319), verification disabled outside a Dockerfile (CWE-295) and a dependency
  fetched over http/git (CWE-494); medium for verification disabled inside a Dockerfile,
  an unverified Dockerfile install and an install-hook that fetches remote code. A git
  dependency tracking master/main/HEAD is always info.

## White box: code and secrets (source directory, min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Private keys, credential files and state files committed to the repo | medium - high | A02 Cryptographic Failures | CWE-312 |
| SQL statement assembled by string concatenation or interpolation | low - high | A03 Injection | CWE-89 |
| Signature / certificate / origin verification explicitly disabled in code | medium - high | A01 / A02 | CWE-208, 295, 347, 942 |
| Broken cipher mode, hardcoded IV or non-crypto RNG for security values | low - high | A02 Cryptographic Failures | CWE-326, 327, 329, 336, 338, 916 |

- **Committed key material** — find credential-bearing files by basename (`id_rsa`,
  `*.pem`/`.key`/`.p12`/`.jks`, `.npmrc`, `.netrc`, `.pgpass`, `.dockercfg`, GCP
  service-account JSON, `.env`, `terraform.tfstate`, kubeconfig) that are git-tracked
  or not gitignored, then **confirm each by content, not by name** (the content check is
  the false-positive control). Also report a git remote URL embedding user:password.
  High for private keys, credential/token files, service-account keys, kubeconfigs,
  `.env` literals and a password in a remote URL; medium for a keystore/KeePass
  container recognised only by magic bytes and for `terraform.tfstate`.
- **SQL string building** — scan Python, JS/TS, Java/Kotlin/Scala, PHP, Go and C# for a
  SQL statement built by f-strings, %-formatting, `.format()`, template literals or
  concatenation and handed to a DB driver. Skip calls that use proper placeholders with
  a params argument or a driver-escaped tagged template (the negative control). High
  normally; low (confidence low) under test/fixture/migration/seed/spec paths.
- **Auth verification disabled** — match code that turns verification off: JWT
  `verify=False`, `verify_signature: false`, alg `none`, `ParseUnverified`,
  `SkipClaimsValidation`; TLS off via `rejectUnauthorized`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify`, `CURLOPT_SSL_VERIFY*`,
  `ssl.CERT_NONE`, allow-all hostname verifiers, empty trust managers;
  wildcard/reflected CORS origin combined with credentials; `jwt.verify` with no
  algorithms allowlist; secrets compared with a non-constant-time operator. Test
  harness files are skipped. High for disabled signature/cert/hostname verification
  (CWE-347/295) and credentialed wildcard CORS (CWE-942); medium for `jwt.verify()`
  without an allowlist (CWE-347) and non-constant-time secret comparison (CWE-208).
- **Weak crypto usage** — report ECB mode, broken primitives (DES, 3DES, RC2, RC4,
  Blowfish), Node `crypto.createCipher`, hardcoded/all-zero IVs, a non-crypto RNG
  lexically bound to a token/salt/nonce/session-id/key, `SecureRandom` seeded with a
  constant, and bcrypt/PBKDF2/scrypt work factors below current guidance. High for ECB
  (CWE-327), broken primitives (CWE-327), `createCipher` (CWE-326), a static IV
  (CWE-329), a weak RNG for security values (CWE-338) and a fixed SecureRandom seed
  (CWE-336); medium for a low password-hashing work factor (CWE-916). Each drops one
  level under test/mock/fixture/benchmark paths.

## APK manifest and resources (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Network Security Config trusts user CAs, permits cleartext, or pins nothing | info - high | MASVS-NETWORK | CWE-295, 319 |
| Content provider exposes app-private files | low - high | MASVS-PLATFORM / STORAGE | CWE-22, 266, 926 |
| Backup / data-extraction rules allow full app-data extraction | info - medium | MASVS-STORAGE | CWE-530 |
| Browser-reachable deep links (custom schemes, host-less filters, wildcard paths) | info - high | MASVS-PLATFORM | CWE-939 |
| APK signed v1-only (Janus) or with the debug certificate | info - high | MASVS-CODE | CWE-347, 798 |

- **Network Security Config** — decode `res/xml` network-security-config docs. High
  when trust anchors include certificates `src="user"` (CWE-295); medium when
  `cleartextTrafficPermitted="true"` outside debug-overrides (CWE-319); low when no
  pin-set exists **and** the DEX references neither `CertificatePinner` nor a custom
  `X509TrustManager` (the DEX cross-check is the false-positive control); info for a
  custom bundled trust-anchor source.
- **Provider exposure** — analyse exported `<provider>` declarations. High for
  one-sided read-only/write-only permissions (CWE-926), an authority-wide
  grant-uri-permission (CWE-266) and a FileProvider mapping a whole storage root with
  path `/` or `.` (CWE-22); low for an exported multiprocess provider (CWE-926) and
  bare unrestricted `grantUriPermissions` (CWE-266).
- **Backup rules** — read the application element and referenced backup-rule files.
  Medium when `allowBackup` defaults to true below API 31 with no rules file, and when
  full-backup/data-extraction rules include a whole sharedpref/database domain with no
  matching exclude; low when backup is on for API 31+ with no `dataExtractionRules`;
  info for a custom `backupAgent` (no CWE).
- **Deep-link surface** — enumerate BROWSABLE VIEW intent filters on externally
  reachable activities/aliases. High for an http(s) filter with no `android:host` and
  for a wildcard host with an unrestricted path; medium for a custom scheme matching
  every host/path; low for a custom scheme pinned to a host or path; info for
  `autoVerify` on a non-http(s) filter.
- **Signing scheme** — read `META-INF` signature entries and parse the APK Signing
  Block id table. High for the Android debug certificate (CWE-798) and v1-only signing
  when minSdkVersion < 27 (Janus, CVE-2017-13156, CWE-347); medium for v1-only at API
  27+ and an unsigned archive; info when v2 is present but there is no v3 lineage block.

## APK DEX bytecode (min profile: passive)

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| Certificate or hostname validation disabled in application code | medium - critical | MASVS-NETWORK | CWE-295, 297 |
| Weak or misused cryptography in DEX | low - high | MASVS-CRYPTO | CWE-321, 327, 328, 335 |
| Debug compile, no R8 shrinking/obfuscation, testOnly, or shipped mapping file | info - high | MASVS-RESILIENCE | CWE-489, 540, 656 |

- **Insecure TLS in code** — parse the DEX string, type, method-reference and
  class-definition tables. Critical for `SSLCertificateSocketFactory.getInsecure()`
  (CWE-295); high for an allow-all hostname verifier referenced but not defined by the
  app (CWE-297) and a `WebViewClient` whose `onReceivedSslError` reaches
  `SslErrorHandler.proceed()` (CWE-295); medium for a non-framework class implementing
  `X509TrustManager` (CWE-295).
- **Weak crypto in DEX** — require the matching JCA call in the method-reference table
  before reporting an exact algorithm string (that co-occurrence requirement is the
  false-positive control). High for DES, 3DES, RC4; medium for ECB transformations,
  Blowfish, RC2, bare `Cipher.getInstance("AES")` (all CWE-327), a seeded
  `SecureRandom` (CWE-335) and hardcoded key material passed to `SecretKeySpec`
  (CWE-321); low for MD5/SHA-1 digests (CWE-328). Confidence drops to low when the DEX
  bundles a full crypto provider.
- **Build hardening** — parse the embedded R8/D8 build markers, binary manifest
  attributes and zip entry list. High for a packaged `mapping.txt` (CWE-540); medium
  for a debug-mode compile and `android:testOnly` (CWE-489); low for a D8-only build
  with no R8 obfuscation (CWE-656); info for a marker min-api that disagrees with the
  manifest minSdkVersion (no CWE).

## External tools (optional, aggressive)

If nuclei, nikto, nmap, sqlmap, or testssl are on PATH, run them and fold their
output into the report. They are accelerators, not required.
