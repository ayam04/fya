# Check catalog

This is the full set of **92 checks** that ship in `fya/checks/`, grouped by area.
Each row lists the check `name` (its dotted id), the severity range it can emit,
the OWASP Top 10 or OWASP MASVS category it maps to, and the CWE it references.

Severity ranges reflect what a single check can yield across cases. A check that
always emits one severity shows a single value; one that varies by finding shows a
range. Profiles are ordered `passive` < `safe` < `aggressive`; a check runs
only at or above its minimum profile.

## Web passive

Read-only checks. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.security_headers` | info - medium | A05:2021 Security Misconfiguration | CWE-693, CWE-319, CWE-1021, CWE-200 |
| `web.version_disclosure` | low | A05:2021 Security Misconfiguration | CWE-200 |
| `web.insecure_cookies` | low - medium | A05:2021 Security Misconfiguration | CWE-614 |
| `web.cookie_flags` | low | A05:2021 Security Misconfiguration | CWE-1004, CWE-614 |

Notes: `web.security_headers` reports separately on missing
Content-Security-Policy (medium, CWE-693), Strict-Transport-Security (medium,
CWE-319), X-Content-Type-Options (low, CWE-693), clickjacking protection (low,
CWE-1021), and Referrer-Policy (info, CWE-200). `web.insecure_cookies` is medium
when the `HttpOnly` flag is missing, otherwise low. `web.cookie_flags` reports cookies missing `HttpOnly` (CWE-1004), and on HTTPS targets, cookies missing `Secure` (CWE-614).

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
encoded CR LF to detect response header injection. `web.csrf` runs at Confidence
LOW and skips forms whose page carries a meta csrf-token or a SameSite cookie.
`web.ssti` uses a pre-injection baseline and two distinct factor pairs to avoid
coincidental matches.

## Web advanced injection

Oracle-confirmed injection into the server side of the application. Minimum
profile: `safe` for `web.nosql_injection`, `web.xpath_ldap_ssi_injection`,
`web.ssrf` and `web.blind_sql_injection`; the other four run only at
`aggressive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.nosql_injection` | high | A03:2021 Injection | CWE-943 |
| `web.xpath_ldap_ssi_injection` | high | A03:2021 Injection | CWE-643, CWE-90, CWE-97 |
| `web.ssrf` | high - critical | A10:2021 Server-Side Request Forgery (SSRF) | CWE-918 |
| `web.blind_sql_injection` | critical | A03:2021 Injection | CWE-89 |
| `web.command_injection` | critical | A03:2021 Injection | CWE-78 |
| `web.xxe_injection` | high | A05:2021 Security Misconfiguration | CWE-611 |
| `web.lfi_wrappers` | high | A03:2021 Injection | CWE-98 |
| `web.json_nosql_operators` | high | A03:2021 Injection | CWE-943 |

Notes: `web.ssrf` is critical when the injected URL returns cloud metadata
content, otherwise high. `web.blind_sql_injection` targets endpoints that return
no database error text: it sends numeric and quoted tautology pairs and confirms
that TRUE conditions match a stable baseline while FALSE conditions diverge,
with SLEEP/pg_sleep/WAITFOR timing confirmation added on the `aggressive`
profile. `web.command_injection` injects shell metacharacters into query
parameters and confirms OS command execution when two independent arithmetic
factor pairs each return their product without the payload text being reflected,
falling back to a two-trial time-delay oracle. `web.xxe_injection` first proves
the parser expands an internal entity by echoing a marker, then reads
`/etc/passwd` or `c:/windows/win.ini` through a SYSTEM entity and matches the
file signature. `web.lfi_wrappers` tests include-style parameters with
`php://filter` and `data://` stream wrappers, confirming inclusion when a base64
run in the response decodes to PHP source or `/etc/passwd` content, or when
`data://` content is executed and echoed back. `web.json_nosql_operators`
replaces a scalar field in a JSON request body with MongoDB-style operators
(`$ne`, `$gt`, `$regex`) and reports when the response moves toward the success
shape, or keeps its status but changes materially, relative to a scalar baseline
sent twice.

## Web caching and origin handling

Header-keyed caching and origin-validation probes. Minimum profile: `safe`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.cache_poison_headers` | medium - high | A05:2021 Security Misconfiguration | CWE-644 |
| `web.url_override_headers` | high | A01:2021 Broken Access Control | CWE-284 |
| `web.cors_advanced` | medium - high | A05:2021 Security Misconfiguration | CWE-942 |

Notes: `web.cache_poison_headers` is high when the poisoned response is also
cacheable, otherwise medium. `web.cors_advanced` is high when the reflected
origin is accepted together with credentials, otherwise medium.

## Web exposure and debug surfaces

Unauthenticated retrieval of files, diagnostics and source that should not be
reachable. Minimum profile: `safe`; `web.backup_files` widens its suffix list at
`aggressive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.vcs_exposure` | high | A05:2021 Security Misconfiguration | CWE-527 |
| `web.exposed_config_secrets` | high | A05:2021 Security Misconfiguration | CWE-538 |
| `web.directory_listing` | low - medium | A05:2021 Security Misconfiguration | CWE-548 |
| `web.js_secrets` | info - critical | A07:2021 Identification and Authentication Failures, A05:2021 Security Misconfiguration | CWE-798, CWE-200 |
| `web.source_map_exposure` | low - medium | A05:2021 Security Misconfiguration | CWE-540 |
| `web.debug_info_pages` | medium - high | A05:2021 Security Misconfiguration | CWE-200, CWE-489 |
| `web.backup_files` | high | A05:2021 Security Misconfiguration | CWE-530 |

Notes: `web.directory_listing` is medium when the listed directory looks
sensitive, otherwise low. `web.js_secrets` carries the severity of the matched
credential pattern (up to critical for a live Stripe key or a private key block)
and drops to low or info for internal hostnames and other minor disclosures in
served JavaScript. `web.source_map_exposure` is medium when the source map
actually embeds sources, otherwise low. `web.debug_info_pages` requests a fixed
set of diagnostic paths and reports phpinfo() output (high, CWE-200), the
Werkzeug interactive debugger console (high, CWE-489), and Apache mod_status and
mod_info pages (medium, CWE-200), matching on the signature unique to each page
rather than a bare HTTP 200. `web.backup_files` appends backup and
editor-temporary suffixes (`.bak`, `.old`, `~`, and at `aggressive` also
`.orig`, `.save`, `.swp`, `.tmp`, `.copy`) to crawled and well-known source
paths, and reports a hit only when the body is raw source (or a vim swap file)
and differs from the live file at the same path.

## Web hardening

Passive best-practice and configuration checks. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.csp_weaknesses` | low - medium | A05:2021 Security Misconfiguration | CWE-693 |
| `web.jwt_weak_algorithm` | low - high | A02:2021 Cryptographic Failures | CWE-347 |
| `web.jwt_missing_expiry` | low | A07:2021 Identification and Authentication Failures | CWE-613 |
| `web.jwt_sensitive_claims` | medium | A02:2021 Cryptographic Failures | CWE-522 |
| `web.frontend_libraries` | info - medium | A06:2021 Vulnerable and Outdated Components | CWE-1104 |
| `web.security_txt` | info | A05:2021 Security Misconfiguration | (none) |
| `web.robots_sensitive_paths` | low | A05:2021 Security Misconfiguration | CWE-200 |
| `web.modern_headers` | info - low | A05:2021 Security Misconfiguration | CWE-1021, CWE-693 |
| `web.cookie_scope` | low - medium | A05:2021 Security Misconfiguration | CWE-732 |

Notes: `web.csp_weaknesses` parses an existing Content-Security-Policy and flags
unsafe-inline, unsafe-eval, wildcard and data: sources, and missing object-src or
base-uri (it complements the missing-CSP check in web passive). The `web.jwt_*`
checks passively decode JSON Web Tokens the app exposes without verifying the
signature, flagging the none algorithm, a missing exp claim, and sensitive claims.
`web.frontend_libraries` reads script URLs and flags outdated major versions of
common libraries. `web.security_txt` notes when no security.txt is published, and
`web.robots_sensitive_paths` flags sensitive paths disclosed in robots.txt.
`web.modern_headers` reports a missing or weak Cross-Origin-Opener-Policy (low,
CWE-1021), a missing Cross-Origin-Resource-Policy (info, CWE-1021), and a missing
Permissions-Policy (info, CWE-693). `web.cookie_scope` is medium when a `__Host-`
or `__Secure-` prefixed cookie breaks the rules that prefix promises (so browsers
silently drop it), and low when a cookie is scoped to a broad parent domain
shared with sibling subdomains.

## Web crypto and tokens

Offline analysis of the tokens, certificates and serialized blobs the
application already hands out. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `web.jwt_weak_secret` | critical | A02:2021 Cryptographic Failures | CWE-347 |
| `web.jwt_header_injection` | low - medium | A02:2021 Cryptographic Failures | CWE-347, CWE-91 |
| `web.mixed_content` | low, high | A05:2021 Security Misconfiguration | CWE-319 |
| `web.serialized_objects` | low - medium | A08:2021 Software and Data Integrity Failures | CWE-502 |

Notes: `web.jwt_weak_secret` recomputes the HS256/HS384/HS512 signature of an
exposed token offline against a short list of common and default signing secrets
and reports when one of them reproduces the signature. `web.jwt_header_injection`
is medium when a `jku`/`x5u` key URL is fetched over plaintext http (CWE-347) or
a `kid` value carries path-traversal or SQL/command metacharacters (CWE-91), and
low when `jku`/`x5u` points at a host outside the target's registrable domain.
`web.mixed_content` is high for active subresources on an HTTPS page (script,
iframe, stylesheet, modulepreload, and preload with
`as=script/style/worker/serviceworker/sharedworker/document`) and low for passive
ones (images, media, css `url()`, icons and manifests). `web.serialized_objects`
is medium for Java (`rO0AB` / `0xACED`), Ruby Marshal, PHP `serialize` and
node-serialize function payloads found in cookies, hidden form fields, link query
parameters or JSON string values, and low for an ASP.NET `__VIEWSTATE` that
decodes to an unencrypted ObjectStateFormatter stream (normally MAC-protected).

## Access control and input handling

Authorization and robustness probes against discovered endpoints. Minimum
profile: `safe`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `graybox.idor` | medium | A01:2021 Broken Access Control | CWE-639 |
| `graybox.auth_bypass` | medium | A01:2021 Broken Access Control | CWE-306 |
| `blackbox.input_fuzzing` | low - medium | A05:2021 Security Misconfiguration | CWE-20, CWE-209 |

Notes: the `graybox.*` checks run at Confidence LOW because an unauthenticated
scanner cannot prove ownership of the object it reached. `blackbox.input_fuzzing`
is medium when malformed input breaks the endpoint (CWE-20) and low when it only
produces a verbose error page (CWE-209).

## TLS

Certificate and protocol checks over a direct TLS socket. Minimum profile:
`passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `tls.certificate` | medium - critical | A02:2021 Cryptographic Failures | CWE-295 |
| `tls.weak_protocol` | medium | A02:2021 Cryptographic Failures | CWE-327 |
| `tls.https_upgrade` | medium | A02:2021 Cryptographic Failures | CWE-319 |
| `tls.certificate_strength` | high | A02:2021 Cryptographic Failures | CWE-326, CWE-327 |

Notes: `tls.certificate` emits critical for an expired certificate, high for a
hostname mismatch, self-signed or untrusted chain, or a not-yet-valid
certificate, and medium when a certificate is expiring within 30 days.
`tls.https_upgrade` applies only when the target scheme is `http` and HTTPS is
reachable on the host. `tls.certificate_strength` fetches the certificate on port
443 (and on the target port when the scheme is https) and reports an RSA/DSA key
below 2048 bits or an EC key below 224 bits (CWE-326), and a certificate signed
with MD5 or SHA-1 (CWE-327); both are reported at high.

## API

API surface and error-handling checks. Minimum profile: `safe`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `api.docs_exposure` | medium | A05:2021 Security Misconfiguration | CWE-200 |
| `api.graphql_introspection` | medium | A05:2021 Security Misconfiguration | CWE-200 |
| `api.verbose_errors` | medium | A05:2021 Security Misconfiguration | CWE-209 |
| `api.admin_endpoints` | medium | A05:2021 Security Misconfiguration | CWE-497 |
| `api.graphql_hardening` | medium | A05:2021 Security Misconfiguration, A01:2021 Broken Access Control | CWE-200, CWE-770, CWE-352 |
| `api.actuator_exposure` | medium - high | A05:2021 Security Misconfiguration | CWE-497 |
| `api.oidc_misconfig` | low - high | A02:2021 Cryptographic Failures, A07:2021 Identification and Authentication Failures | CWE-287, CWE-319, CWE-327, CWE-347 |
| `api.soap_wsdl_exposure` | medium | A05:2021 Security Misconfiguration | CWE-200 |

Notes: `api.graphql_hardening` reports field suggestions that leak schema names
(CWE-200), a missing depth or complexity limit (CWE-770), and a GraphQL endpoint
that accepts GET or form-encoded requests and is therefore CSRF-reachable
(CWE-352). `api.actuator_exposure` probes Spring Boot Actuator paths under
`/actuator` and at the root and reports the ones that answer without
authentication with content-validated bodies (hprof magic bytes for `/heapdump`,
specific JSON keys for the rest): high for `/env`, `/configprops` and
`/heapdump`, medium for `/threaddump`, `/mappings`, `/beans` and `/loggers`.
`api.oidc_misconfig` reads the OpenID Connect / OAuth authorization-server
discovery document and emits high for cleartext http endpoints (CWE-319) and
`alg: none` (CWE-347), medium for the implicit flow (CWE-287) and HS256-only
id_token signing (CWE-327), and low for a missing S256 PKCE method and an enabled
resource-owner password grant (CWE-287). `api.soap_wsdl_exposure` requests
`?wsdl` on common service paths and on any crawled `.asmx` endpoint and reports
an unauthenticated contract identified by a `wsdl:definitions` root, a
`definitions` element in the WSDL namespace, or a `text/xml` body containing SOAP
elements.

## White box: source and dependencies

Local analysis of a source tree. Minimum profile: `passive`, except
`whitebox.static_analysis` which runs at `safe`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `whitebox.hardcoded_secrets` | high | A07:2021 Identification and Authentication Failures | CWE-798 |
| `whitebox.dangerous_patterns` | low - high | A03:2021 Injection, A02:2021 Cryptographic Failures, A05:2021 Security Misconfiguration, A08:2021 Software and Data Integrity Failures | CWE-95, CWE-78, CWE-502, CWE-295, CWE-489, CWE-327, CWE-79 |
| `whitebox.static_analysis` | info - high | A06:2021 Vulnerable and Outdated Components, A03:2021 Injection | (from analyzer) |
| `whitebox.cicd_misconfig` | high | A08:2021 Software and Data Integrity Failures, A03:2021 Injection | CWE-94 |

Notes: `whitebox.dangerous_patterns` runs at Confidence LOW and is high for
`eval()`, `exec()`, `shell=True`, `os.system()` and `pickle.load`, medium for
`yaml.load` without a loader, `verify=False` and `dangerouslySetInnerHTML`, and
low for `DEBUG = True`, MD5/SHA-1 hashing, `innerHTML` assignment and
`document.write()`. `whitebox.static_analysis` shells out to `semgrep` or
`bandit` when one is installed, maps the analyzer's own severity onto the `fya`
scale and carries the analyzer's CWE where it reports one; with no analyzer
present it emits a single info finding saying the deeper pass was skipped.

## White box: code and secrets

Offline source analysis for committed credentials and unsafe security-relevant
code. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `whitebox.committed_key_material` | medium - high | A02:2021 Cryptographic Failures | CWE-312 |
| `whitebox.sql_string_building` | low, high | A03:2021 Injection | CWE-89 |
| `whitebox.auth_verification_disabled` | medium - high | A01:2021 Broken Access Control, A02:2021 Cryptographic Failures | CWE-208, CWE-295, CWE-347, CWE-942 |
| `whitebox.weak_crypto_usage` | low - high | A02:2021 Cryptographic Failures | CWE-326, CWE-327, CWE-329, CWE-336, CWE-338, CWE-916 |

Notes: `whitebox.committed_key_material` finds credential-bearing files by
basename (`id_rsa`, `*.pem`/`.key`/`.p12`/`.jks`, `.npmrc`, `.netrc`, `.pgpass`,
`.dockercfg`, GCP service-account JSON, `.env`, `terraform.tfstate`, kubeconfig)
that are git-tracked or not gitignored and confirms each by content rather than
by name; it is high for private keys, credential and token files,
service-account keys, kubeconfigs, `.env` literals and a password embedded in a
git remote URL, and medium for a keystore or KeePass container recognised only by
magic bytes and for `terraform.tfstate`. `whitebox.sql_string_building` reports a
SQL statement built by f-strings, %-formatting, `.format()`, template literals or
concatenation and handed to a database driver in Python, JavaScript/TypeScript,
Java/Kotlin/Scala, PHP, Go or C#, skipping calls that use proper placeholders
with a params argument or a driver-escaped tagged template; it is high normally
and low (Confidence LOW) under a test, fixture, migration, seed or spec path.
`whitebox.auth_verification_disabled` matches code that turns verification off
(JWT `verify=False`, `verify_signature: false`, alg `none`, `ParseUnverified`,
`SkipClaimsValidation`, `rejectUnauthorized`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
`InsecureSkipVerify`, `CURLOPT_SSL_VERIFY*`, `ssl.CERT_NONE`, allow-all hostname
verifiers, empty trust managers, wildcard or reflected CORS origins with
credentials, `jwt.verify` with no algorithms allowlist, and non-constant-time
secret comparison), skipping test harness files: high for disabled signature,
certificate or hostname verification (CWE-347, CWE-295) and credentialed wildcard
CORS (CWE-942), medium for `jwt.verify()` without an algorithms allowlist
(CWE-347) and non-constant-time secret comparison (CWE-208).
`whitebox.weak_crypto_usage` is high for ECB mode and broken primitives such as
DES/3DES/RC2/RC4/Blowfish (CWE-327), Node `crypto.createCipher` (CWE-326), a
hardcoded or all-zero IV (CWE-329), a non-cryptographic RNG lexically bound to a
token, salt, nonce, session id or key (CWE-338) and a constant `SecureRandom`
seed (CWE-336), and medium for a bcrypt/PBKDF2/scrypt work factor below current
guidance (CWE-916); every finding drops one severity level under a test, mock,
fixture or benchmark path.

## White box: infrastructure as code and supply chain

Offline analysis of build, container, orchestration and CI configuration.
Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `whitebox.dockerfile_hardening` | info - high | A05:2021 Security Misconfiguration, A07:2021 Identification and Authentication Failures, A08:2021 Software and Data Integrity Failures | CWE-250, CWE-494, CWE-732, CWE-798, CWE-829 |
| `whitebox.k8s_workload_security` | info - critical | A05:2021 Security Misconfiguration | CWE-250, CWE-269, CWE-732, CWE-770 |
| `whitebox.terraform_exposure` | info - high | A01:2021 Broken Access Control, A02:2021 Cryptographic Failures, A07:2021 Identification and Authentication Failures, A09:2021 Security Logging and Monitoring Failures | CWE-269, CWE-284, CWE-311, CWE-732, CWE-778, CWE-798 |
| `whitebox.compose_hardening` | info - critical | A05:2021 Security Misconfiguration, A07:2021 Identification and Authentication Failures | CWE-250, CWE-668, CWE-732, CWE-798, CWE-1188 |
| `whitebox.actions_supply_chain` | low - high | A03:2021 Injection, A05:2021 Security Misconfiguration, A07:2021 Identification and Authentication Failures, A08:2021 Software and Data Integrity Failures, A09:2021 Security Logging and Monitoring Failures | CWE-94, CWE-269, CWE-494, CWE-522, CWE-532, CWE-732, CWE-798 |
| `whitebox.insecure_package_source` | info - high | A02:2021 Cryptographic Failures, A08:2021 Software and Data Integrity Failures | CWE-295, CWE-319, CWE-494 |

Notes: `whitebox.dockerfile_hardening` parses Dockerfiles and Containerfiles and
is high for a literal credential in `ENV`/`ARG` (CWE-798), medium for a final
stage that never drops root (CWE-250) and for remote `ADD` or an unverified
fetch-and-exec (CWE-494), and low for a floating base image with no digest or a
`:latest` tag (CWE-829) and `chmod 777` (CWE-732); every finding drops one
severity level and its confidence to low under a test, example or fixture path.
`whitebox.k8s_workload_security` is critical for a container-runtime socket
`hostPath`, high for privileged containers, shared host namespaces,
escape-capable capabilities, a sensitive `hostPath` and wildcard RBAC, medium for
`allowPrivilegeEscalation`, `runAsUser: 0` and a ClusterRole that reads all
secrets, and low for an auto-mounted service account token; each drops one level
(and confidence to low) when the manifest is templated with `{{...}}` or sits
under a test path, and the "no resource limits" and "no securityContext" rules
are always emitted at info. `whitebox.terraform_exposure` reads `.tf` and
`.tfvars` with a brace-matching HCL reader and is high for administrative or
datastore ports open to `0.0.0.0/0` (CWE-284), publicly readable object storage
(CWE-732), a publicly accessible database (CWE-284), a wildcard IAM policy
(CWE-269) and hardcoded credentials in variables or tfvars (CWE-798), medium for
an unconditional `Principal: *` resource policy and explicitly disabled
encryption at rest (CWE-311), and low for disabled audit logging (CWE-778) and an
unencrypted S3 state backend; each drops one level under a test path, and
"encryption at rest not declared" is always emitted at info.
`whitebox.compose_hardening` segments docker-compose files by service and is
critical for a Docker socket mount, high for privileged containers, host
pid/ipc/userns, a `/` bind mount, escape-capable `cap_add` entries, unconfined
seccomp/AppArmor, a datastore port published on all interfaces, disabled database
authentication and a hardcoded credential, medium for `network_mode: host`, and
low for `user: root`; each drops one level (and confidence to low) for a
`.test`/`.ci`/`.dev`/`.local` compose file or a test path.
`whitebox.actions_supply_chain` covers GitHub Actions workflows, composite
actions, CircleCI, GitLab, Azure, Bitbucket and Jenkins files: high for an action
pinned to a branch (CWE-494), `ACTIONS_ALLOW_UNSECURE_COMMANDS` (CWE-94), a
`pull_request_target` job on a self-hosted runner (CWE-269), a re-evaluated
GitLab `CI_COMMIT_*` value used as shell source (CWE-94) and a literal secret in
`.gitlab-ci.yml` (CWE-798); medium for an action pinned to a tag,
`permissions: write-all` (CWE-732), a secret echoed to the build log (CWE-532),
`curl | sh` (CWE-494), `secrets: inherit` passed to a foreign workflow (CWE-522)
and a `pull_request` job on a self-hosted runner; and low for a workflow that
uses third-party actions with no `permissions` block. A test path lowers its
confidence only, never its severity. `whitebox.insecure_package_source` inspects
package-manager configuration (`.npmrc`, `pip.conf`, `pyproject.toml`, `Gemfile`,
`pom.xml`, `build.gradle`, `nuget.config`, `package.json`, `requirements.txt`,
Dockerfiles and more) and is high for a plaintext registry, index or mirror URL
(CWE-319), verification disabled outside a Dockerfile (CWE-295) and a dependency
fetched over `http://` or `git://` (CWE-494), and medium for verification
disabled inside a Dockerfile, an unverified Dockerfile install and an install
hook that downloads and executes remote code; each drops one level under a test
path, and a git dependency tracking `master`/`main`/`HEAD` is always emitted at
info.

## APK

Local static analysis of an Android `.apk`. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `apk.hardcoded_secrets` | info, high | MASVS-STORAGE | CWE-798 |
| `apk.cleartext_urls` | low | MASVS-NETWORK | CWE-319 |
| `apk.manifest` | info - high | MASVS-PLATFORM, MASVS-STORAGE, MASVS-NETWORK, MASVS-CODE | CWE-489, CWE-530, CWE-319, CWE-926 |
| `apk.webview_config` | medium - high | MASVS-PLATFORM | CWE-749 |

Notes: `apk.hardcoded_secrets` emits high for a detected secret (AWS access key,
Google API key, private key block, Firebase URL, or Slack token) and info if the
archive cannot be opened. `apk.manifest` requires the optional `androguard`
dependency (the `[apk]` extra); without it, it emits a single info finding
saying analysis was skipped. When available it reports: debuggable build (high,
CWE-489, MASVS-CODE), allowBackup enabled (medium, CWE-530, MASVS-STORAGE),
cleartext traffic permitted or no network security config (medium, CWE-319,
MASVS-NETWORK), exported component without a permission guard (medium, CWE-926,
MASVS-PLATFORM), low minSdkVersion below API 24 (low, MASVS-PLATFORM), and
sensitive permissions requested (low, MASVS-PLATFORM). `apk.webview_config` is
high when a WebView combines JavaScript with a JavaScript-to-native bridge or
file access, and medium for the weaker WebView settings that only widen the
attack surface.

## APK manifest and configuration

Offline parsing of `AndroidManifest.xml`, the `res/xml` documents it references
and the archive's signature blocks. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `apk.network_security_config` | info - high | MASVS-NETWORK | CWE-295, CWE-319 |
| `apk.provider_exposure` | low, high | MASVS-PLATFORM, MASVS-STORAGE | CWE-22, CWE-266, CWE-926 |
| `apk.backup_rules` | info - medium | MASVS-STORAGE | CWE-530 |
| `apk.deeplink_surface` | info - high | MASVS-PLATFORM | CWE-939 |
| `apk.signing_scheme` | info - high | MASVS-CODE | CWE-347, CWE-798 |

Notes: `apk.network_security_config` decodes `res/xml` network-security-config
documents and is high when user-installed CAs are trusted (CWE-295), medium when
`cleartextTrafficPermitted="true"` appears outside `debug-overrides` (CWE-319),
low when nothing in the app pins a certificate (CWE-295, raised only when the DEX
also references neither `CertificatePinner` nor a custom `X509TrustManager`), and
info for a custom bundled trust-anchor source. `apk.provider_exposure` is high
for an exported provider guarding only reads or only writes (CWE-926), an
authority-wide grant-uri-permission entry (CWE-266) and a FileProvider mapping a
whole storage root with path `/` or `.` (CWE-22), and low for an exported
multiprocess provider (CWE-926) and bare unrestricted `grantUriPermissions`
(CWE-266). `apk.backup_rules` is medium when `allowBackup` defaults to true below
API 31 with no rules file and when backup or data-extraction rules include a
whole sharedpref or database domain with no matching exclude, low when backup is
on for API 31+ with no `dataExtractionRules`, and info for a custom `backupAgent`
(which carries no CWE). `apk.deeplink_surface` enumerates BROWSABLE VIEW intent
filters on externally reachable activities and activity-aliases: high for an
http(s) filter that declares no `android:host` and for a wildcard host combined
with an unrestricted path, medium for a custom URI scheme matching every host and
path, low for a custom scheme pinned to a host or path, and info for `autoVerify`
on a non-http(s) filter. `apk.signing_scheme` reads `META-INF` signature entries
and the APK Signing Block id table: high for the Android debug certificate
(CWE-798) and for v1-only JAR signing when `minSdkVersion` is below 27 (Janus,
CVE-2017-13156, CWE-347), medium for v1-only signing at API 27+ and for an
entirely unsigned archive (CWE-347), and info when v2 is present but there is no
v3 lineage block (no CWE).

## APK code and build

Direct parsing of the DEX tables and the embedded build markers, with no
`androguard` dependency. Minimum profile: `passive`.

| Check | Severity | OWASP / MASVS | CWE |
|-------|----------|---------------|-----|
| `apk.insecure_tls_code` | medium - critical | MASVS-NETWORK | CWE-295, CWE-297 |
| `apk.weak_crypto` | low - high | MASVS-CRYPTO | CWE-321, CWE-327, CWE-328, CWE-335 |
| `apk.build_hardening` | info - high | MASVS-RESILIENCE | CWE-489, CWE-540, CWE-656 |

Notes: `apk.insecure_tls_code` parses the DEX string, type, method-reference and
class-definition tables and is critical for
`SSLCertificateSocketFactory.getInsecure()` (CWE-295), high for an allow-all
hostname verifier referenced but not defined by the app (CWE-297) and for a
`WebViewClient` whose `onReceivedSslError` reaches `SslErrorHandler.proceed()`
(CWE-295), and medium for a non-framework class implementing `X509TrustManager`
(CWE-295). `apk.weak_crypto` requires the matching JCA call in the DEX
method-reference table before reporting an exact algorithm string: high for DES,
3DES and RC4; medium for ECB transformations, Blowfish, RC2 and a mode-less
`Cipher.getInstance("AES")` (all CWE-327), `SecureRandom.setSeed` (CWE-335) and
hardcoded key material passed to `SecretKeySpec` (CWE-321); low for MD5/SHA-1
digests (CWE-328). Its confidence drops to low when the dex bundles a full crypto
provider. `apk.build_hardening` parses the R8/D8 build markers, the binary
manifest attributes and the zip entry list: high for a packaged ProGuard/R8
`mapping.txt` (CWE-540), medium for a debug-mode compile and `android:testOnly`
(CWE-489), low for a D8-only build with no R8 shrinking or identifier renaming
(CWE-656), and info for a marker min-api that disagrees with the manifest
`minSdkVersion` (no CWE).

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
