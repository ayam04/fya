"""Content-validated exposure of high-value framework, config and diagnostic endpoints.

Every check in this module probes a small fixed path set (or a well-known document),
guards with :func:`is_catch_all`, and fires only on a signature that is unique to the
exposed artifact -- never on a bare HTTP 200.
"""

from __future__ import annotations

import json
import re
import zlib
from urllib.parse import urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._common import is_catch_all, same_origin_scripts
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover

# --------------------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------------------


def _root(ctx: ScanContext):
    base = ctx.target.base_url()
    return base.rstrip("/") if base else None


def _json_dict(response):
    """Return the response body parsed as a JSON object, or None."""
    text = response.text or ""
    ctype = response.headers.get("content-type", "").lower()
    if "json" not in ctype and not text.lstrip().startswith("{"):
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _is_aggressive(ctx: ScanContext) -> bool:
    return ctx.profile is Profile.AGGRESSIVE


# --------------------------------------------------------------------------------------
# api.actuator_exposure
# --------------------------------------------------------------------------------------

_ACTUATOR_KINDS = {
    "env": (Severity.HIGH, "environment properties and property sources"),
    "configprops": (Severity.HIGH, "resolved configuration-properties beans"),
    "heapdump": (Severity.HIGH, "a full JVM heap dump"),
    "threaddump": (Severity.MEDIUM, "a live JVM thread dump"),
    "mappings": (Severity.MEDIUM, "the complete request-mapping table"),
    "beans": (Severity.MEDIUM, "the Spring application-context bean graph"),
    "loggers": (Severity.MEDIUM, "the runtime logger configuration"),
}

# Spring Boot 2.x/3.x exposes actuators under /actuator; Boot 1.x exposes them at the root.
_ACTUATOR_PATHS = [
    ("/actuator/env", "env"),
    ("/actuator/configprops", "configprops"),
    ("/actuator/heapdump", "heapdump"),
    ("/actuator/threaddump", "threaddump"),
    ("/actuator/mappings", "mappings"),
    ("/actuator/beans", "beans"),
    ("/actuator/loggers", "loggers"),
    ("/env", "env"),
    ("/configprops", "configprops"),
    ("/heapdump", "heapdump"),
    ("/threaddump", "threaddump"),
    ("/mappings", "mappings"),
    ("/beans", "beans"),
]

_HPROF_MAGIC = b"JAVA PROFILE "
_GZIP_MAGIC = b"\x1f\x8b"
_HEAPDUMP_HEAD_BYTES = 4096


def _actuator_env(response) -> str:
    data = _json_dict(response)
    if not data:
        return ""
    for key in ("propertySources", "activeProfiles", "contexts"):
        if key in data:
            return "JSON object with '%s'" % key
    return ""


def _actuator_threaddump(response) -> str:
    body = response.text or ""
    if "java.lang.Thread.State" in body:
        return "thread states in body"
    data = _json_dict(response)
    if data and "threads" in data:
        return "JSON object with 'threads'"
    return ""


def _actuator_mappings(response) -> str:
    if _json_dict(response) is None:
        return ""
    body = response.text or ""
    for key in ("dispatcherServlets", "dispatcherHandlers"):
        if key in body:
            return "JSON object with '%s'" % key
    return ""


def _actuator_beans(response) -> str:
    data = _json_dict(response)
    if not data:
        return ""
    for key in ("beans", "contexts"):
        if key in data:
            return "JSON object with '%s'" % key
    return ""


def _actuator_loggers(response) -> str:
    data = _json_dict(response)
    if data and "levels" in data and "loggers" in data:
        return "JSON object with 'levels' and 'loggers'"
    return ""


_ACTUATOR_VALIDATORS = {
    "env": _actuator_env,
    "configprops": _actuator_env,
    "threaddump": _actuator_threaddump,
    "mappings": _actuator_mappings,
    "beans": _actuator_beans,
    "loggers": _actuator_loggers,
}


def _hprof_label(head: bytes) -> str:
    """Return a label when the first bytes are an hprof dump, plain or gzip-wrapped."""
    if head.startswith(_HPROF_MAGIC):
        return "hprof magic bytes"
    if head.startswith(_GZIP_MAGIC):
        # Boot 1.x serves the dump gzip-wrapped at the application layer, which requests
        # does not transparently decode (no Content-Encoding header).
        try:
            plain = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head, 64)
        except (zlib.error, ValueError):
            return ""
        if plain.startswith(_HPROF_MAGIC):
            return "gzip-wrapped hprof magic bytes"
    return ""


def _heapdump_evidence(ctx: ScanContext, url: str) -> str:
    """Fetch only the first chunk of a candidate heap dump and check its magic bytes.

    The magic bytes are the whole test: a large ``application/octet-stream`` body is any
    binary download (a PDF, an export, a proxied asset) and must never be reported as a
    heap dump. Content-Length is a size sanity check only, and only when the server sends
    one -- a chunked or HTTP/2 response carries none and must still be inspected.
    """
    response = ctx.http.get(url, stream=True)
    if response is None:
        return ""
    try:
        if response.status_code != 200:
            return ""
        raw = response.headers.get("content-length")
        length = None
        if raw is not None:
            try:
                length = int(raw)
            except (TypeError, ValueError):
                length = None
        if length is not None and length <= 1000:
            return ""
        head = b""
        try:
            for chunk in response.iter_content(_HEAPDUMP_HEAD_BYTES):
                head = chunk or b""
                break
        except (OSError, ValueError):
            return ""
        label = _hprof_label(head)
        if not label:
            return ""
        if length is None:
            return "%s, chunked body (no content-length)" % label
        return "%s, content-length %d" % (label, length)
    finally:
        try:
            response.close()
        except OSError:
            pass


@register
class ActuatorExposure(Check):
    name = "api.actuator_exposure"
    title = "Unauthenticated Spring Boot Actuator secret/memory endpoints"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        root = _root(ctx)
        if not root or is_catch_all(ctx):
            return
        emitted = 0
        seen = set()
        for path, kind in _ACTUATOR_PATHS:
            if emitted >= 5:
                break
            if kind in seen:
                continue
            url = root + path
            if kind == "heapdump":
                evidence = _heapdump_evidence(ctx, url)
            else:
                response = ctx.http.get(url)
                if response is None or response.status_code != 200:
                    continue
                try:
                    evidence = _ACTUATOR_VALIDATORS[kind](response)
                except (ValueError, TypeError, AttributeError):
                    evidence = ""
            if not evidence:
                continue
            seen.add(kind)
            emitted += 1
            severity, label = _ACTUATOR_KINDS[kind]
            yield Finding(
                check=self.name,
                title="Exposed Spring Boot Actuator endpoint: %s" % path,
                severity=severity,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-497",
                description=(
                    "The Actuator endpoint %s answered without authentication and returned %s. "
                    "Actuator endpoints of this kind leak environment values and credentials, "
                    "in-memory object graphs, and the internal wiring of the application, which "
                    "is more than enough to plan a targeted attack." % (path, label)
                ),
                remediation=(
                    "Restrict Actuator to a management port that is not publicly reachable, set "
                    "management.endpoints.web.exposure.include to only the endpoints you need "
                    "(health, info), and require authentication for the management context."
                ),
                location=url,
                evidence=evidence,
                references=[
                    "https://cwe.mitre.org/data/definitions/497.html",
                    "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
                ],
            )


# --------------------------------------------------------------------------------------
# web.debug_info_pages
# --------------------------------------------------------------------------------------


def _sig_phpinfo(body: str) -> str:
    if "<title>phpinfo()" in body:
        return "phpinfo() page title"
    if "PHP Version" in body and "Configuration" in body and "System " in body:
        return "PHP Version / Configuration / System table"
    return ""


def _sig_server_status(body: str) -> str:
    if "Apache Server Status" not in body:
        return ""
    for marker in ("Server uptime", "Total accesses"):
        if marker in body:
            return "Apache Server Status page with '%s'" % marker
    return ""


def _sig_server_info(body: str) -> str:
    if "Apache Server Information" in body and "Server Settings" in body:
        return "Apache Server Information page"
    return ""


def _sig_werkzeug(body: str) -> str:
    if "Werkzeug" not in body:
        return ""
    for marker in ("__debugger__", "console-mode", "The Werkzeug debugger"):
        if marker in body:
            return "Werkzeug debugger marker '%s'" % marker
    return ""


_DEBUG_KINDS = {
    "phpinfo": (
        Severity.HIGH,
        "CWE-200",
        "phpinfo() output",
        "phpinfo() dumps the full PHP configuration: loaded extensions, absolute filesystem "
        "paths, environment variables, database credentials passed through the environment, "
        "and the exact PHP build. It is a complete blueprint of the server.",
        "Delete the phpinfo() script from the document root. If it is needed for debugging, "
        "keep it out of production images entirely rather than protecting it by obscurity.",
    ),
    "server-status": (
        Severity.MEDIUM,
        "CWE-200",
        "Apache mod_status output",
        "The Apache mod_status page is reachable without authentication. It lists the URLs "
        "currently being requested, client IP addresses, virtual hosts and server uptime, "
        "which discloses internal endpoints and live traffic to any visitor.",
        "Restrict the /server-status handler to localhost or an admin network with a Require "
        "directive, or disable mod_status in production.",
    ),
    "server-info": (
        Severity.MEDIUM,
        "CWE-200",
        "Apache mod_info output",
        "The Apache mod_info page is reachable without authentication. It publishes the full "
        "server configuration, loaded modules and compiled-in settings, which makes it trivial "
        "to identify exploitable modules and misconfigurations.",
        "Restrict the /server-info handler to localhost or an admin network, or disable "
        "mod_info in production.",
    ),
    "werkzeug": (
        Severity.HIGH,
        "CWE-489",
        "the Werkzeug interactive debugger",
        "The Werkzeug interactive debugger console is exposed. When the debugger PIN is absent "
        "or brute-forced, the console evaluates arbitrary Python in the application process, "
        "which is a direct remote code execution path.",
        "Never run with debug=True or the Werkzeug debugger enabled outside a developer "
        "machine; set FLASK_DEBUG=0 and use a production WSGI server.",
    ),
}

_DEBUG_PROBES = [
    ("/phpinfo.php", "phpinfo", _sig_phpinfo),
    ("/phpinfo", "phpinfo", _sig_phpinfo),
    ("/info.php", "phpinfo", _sig_phpinfo),
    ("/test.php", "phpinfo", _sig_phpinfo),
    ("/i.php", "phpinfo", _sig_phpinfo),
    ("/server-status", "server-status", _sig_server_status),
    ("/server-status?auto", "server-status", _sig_server_status),
    ("/server-info", "server-info", _sig_server_info),
    ("/console", "werkzeug", _sig_werkzeug),
]


@register
class DebugInfoPages(Check):
    name = "web.debug_info_pages"
    title = "Exposed phpinfo / server-status / Werkzeug debug console"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        root = _root(ctx)
        if not root or is_catch_all(ctx):
            return
        emitted = 0
        seen = set()
        for path, kind, signature in _DEBUG_PROBES:
            if emitted >= 4:
                break
            if kind in seen:
                continue
            url = root + path
            response = ctx.http.get(url)
            if response is None or response.status_code != 200:
                continue
            evidence = signature(response.text or "")
            if not evidence:
                continue
            seen.add(kind)
            emitted += 1
            severity, cwe, label, description, remediation = _DEBUG_KINDS[kind]
            yield Finding(
                check=self.name,
                title="Exposed debug page: %s" % path,
                severity=severity,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe=cwe,
                description="%s is served publicly at %s. %s" % (label.capitalize(), path, description),
                remediation=remediation,
                location=url,
                evidence=evidence,
                references=[
                    "https://cwe.mitre.org/data/definitions/%s.html" % cwe.split("-", 1)[1],
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )


# --------------------------------------------------------------------------------------
# web.backup_files
# --------------------------------------------------------------------------------------

_BACKUP_SEEDS = [
    "/index.php",
    "/config.php",
    "/app.py",
    "/settings.py",
    "/web.config",
    "/application.properties",
    "/wp-config.php",
    "/server.js",
    "/database.php",
    "/.env",
]

_BACKUP_SUFFIXES = [".bak", ".old", "~", ".orig", ".save", ".swp", ".tmp", ".copy"]
_BACKUP_SAFE_SUFFIXES = _BACKUP_SUFFIXES[:3]

_SOURCE_EXTENSIONS = (".php", ".py", ".js", ".rb", ".asp", ".aspx", ".env", ".config")

# Anchored signatures only. Bare substrings such as "import ", "def " or "SECRET" also occur
# in prose, changelogs, CSV exports and JSON blobs, which is far too weak to carry a HIGH
# finding; each pattern below has to match the shape of a real statement or assignment.
_SOURCE_PATTERNS = (
    ("PHP open tag", re.compile(r"^[ \t]*<\?php\b", re.MULTILINE)),
    (
        "Python import statement",
        re.compile(r"^[ \t]*(?:from|import)[ \t]+[A-Za-z_][\w.]*", re.MULTILINE),
    ),
    (
        "Python def/class statement",
        re.compile(r"^[ \t]*(?:def|class)[ \t]+[A-Za-z_]\w*[ \t]*[(:]", re.MULTILINE),
    ),
    ("module require() call", re.compile(r"""\brequire[ \t]*\(?[ \t]*['"][\w./@-]+['"]""")),
    ("module.exports assignment", re.compile(r"^[ \t]*module\.exports[ \t]*=", re.MULTILINE)),
    (
        "ASP.NET configuration section",
        re.compile(r"<(?:appSettings|connectionStrings)\b", re.IGNORECASE),
    ),
    (
        "credential assignment",
        re.compile(
            r"""^[ \t]*["']?[\w.\-$\[\]]*"""
            r"""(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)"""
            r"""[\w.\-$\[\]]*["']?[ \t]*[:=][ \t]*\S""",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
)

_SOURCE_SCAN_BYTES = 100_000

_BACKUP_SAFE_PROBES = 30
_BACKUP_AGGRESSIVE_PROBES = 80


def _candidate_source_paths(ctx: ScanContext, cap: int):
    """Same-host script/link paths on the seed pages that look like server-side source."""
    paths = []
    seen = set()
    urls = []
    for url, _params in _discover(ctx, cap, set()):
        urls.append(url)
    for url, _body in same_origin_scripts(ctx, cap=8, max_bytes=1):
        urls.append(url)
    for url in urls:
        try:
            path = urlsplit(url).path or ""
        except ValueError:
            continue
        if not path.startswith("/") or not path.lower().endswith(_SOURCE_EXTENSIONS):
            continue
        if path in seen:
            continue
        seen.add(path)
        paths.append(path)
        if len(paths) >= 10:
            break
    return paths


def _looks_like_raw_source(response, is_swp: bool) -> str:
    ctype = response.headers.get("content-type", "").lower()
    if "text/html" in ctype:
        return ""
    body = response.text or ""
    if not (response.content or b""):
        return ""
    head = body[:200].lstrip()
    # Reject rendered HTML, but keep raw PHP sources, which legitimately start with "<?php".
    if head.startswith("<") and not head.startswith("<?"):
        return ""
    if is_swp and b"b0VIM" in (response.content or b""):
        return "vim swap file signature b0VIM"
    sample = body[:_SOURCE_SCAN_BYTES]
    for label, pattern in _SOURCE_PATTERNS:
        if pattern.search(sample):
            return "raw source signature: %s" % label
    return ""


@register
class BackupFiles(Check):
    name = "web.backup_files"
    title = "Backup and editor-temporary source file exposure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        root = _root(ctx)
        if not root or is_catch_all(ctx):
            return
        aggressive = _is_aggressive(ctx)
        crawl_cap = _AGGRESSIVE_CRAWL_CAP if aggressive else _SAFE_CRAWL_CAP
        discovered = _candidate_source_paths(ctx, crawl_cap)

        bases = []
        for path in discovered + _BACKUP_SEEDS:
            if path not in bases:
                bases.append(path)

        suffixes = _BACKUP_SUFFIXES if aggressive else _BACKUP_SAFE_SUFFIXES
        budget = _BACKUP_AGGRESSIVE_PROBES if aggressive else _BACKUP_SAFE_PROBES

        probes = 0
        emitted = 0
        live_cache = {}
        for path in bases:
            if emitted >= 5 or probes >= budget:
                break
            for suffix in suffixes:
                if emitted >= 5 or probes >= budget:
                    break
                candidate = root + path + suffix
                probes += 1
                response = ctx.http.get(candidate)
                if response is None or response.status_code != 200:
                    continue
                evidence = _looks_like_raw_source(response, suffix == ".swp")
                if not evidence:
                    continue
                if path not in live_cache:
                    live = ctx.http.get(root + path)
                    live_cache[path] = (live.content or b"") if live is not None else None
                baseline = live_cache[path]
                body = response.content or b""
                # No baseline means the live-file probe failed (request budget exhausted or a
                # network error), so the differential that carries this finding was never run.
                # "Cannot confirm" must stay silent rather than degrade to a bare content match.
                if baseline is None or baseline == body:
                    continue
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="Exposed backup of %s" % path,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-530",
                    description=(
                        "%s is served as raw content instead of being executed, and its body "
                        "differs from the live file at %s. Backup and editor-temporary copies of "
                        "server-side files disclose application source, database credentials and "
                        "API keys verbatim. This is a content match, so confirm the body by hand "
                        "before treating the secrets it contains as compromised."
                        % (path + suffix, path)
                    ),
                    remediation=(
                        "Delete backup and editor-temporary files from the document root, block "
                        "the backup suffixes (.bak, .old, ~, .swp, .orig) at the web server, and "
                        "rotate any credential the exposed copy contains."
                    ),
                    location=candidate,
                    evidence=evidence,
                    references=[
                        "https://cwe.mitre.org/data/definitions/530.html",
                        "https://owasp.org/www-community/attacks/Forced_browsing",
                    ],
                )


# --------------------------------------------------------------------------------------
# api.oidc_misconfig
# --------------------------------------------------------------------------------------

_OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


def _string_list(value):
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _oidc_issues(data: dict):
    """Return [(issue_key, severity, cwe, category, title, description, evidence)]."""
    issues = []

    cleartext = []
    for key, value in data.items():
        if not isinstance(value, str) or not isinstance(key, str):
            continue
        if not (key.endswith("_endpoint") or key == "jwks_uri"):
            continue
        if value.lower().startswith("http://"):
            cleartext.append("%s=%s" % (key, value))
    if cleartext:
        issues.append((
            "cleartext",
            Severity.HIGH,
            "CWE-319",
            "A02:2021 Cryptographic Failures",
            "OAuth/OIDC metadata advertises cleartext HTTP endpoints",
            "The provider's own discovery document advertises OAuth endpoints over plain HTTP. "
            "Authorization codes, access tokens and client credentials sent to these URLs travel "
            "unencrypted and can be captured or rewritten by anyone on the network path.",
            "; ".join(cleartext[:4]),
        ))

    response_types = _string_list(data.get("response_types_supported"))
    implicit = [rt for rt in response_types if "token" in rt.split()]
    if implicit:
        issues.append((
            "implicit",
            Severity.MEDIUM,
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "OAuth implicit flow is still supported",
            "The discovery document advertises response types that return an access token "
            "directly in the redirect fragment. The implicit flow exposes tokens to browser "
            "history, referrer headers and any script on the page, and is disallowed by the "
            "OAuth 2.0 Security Best Current Practice.",
            "response_types_supported: " + ", ".join(implicit[:4]),
        ))

    algs = _string_list(data.get("id_token_signing_alg_values_supported"))
    lowered = [a.lower() for a in algs]
    asymmetric = [a for a in algs if a.upper().startswith(("RS", "ES", "PS"))]
    if "none" in lowered:
        issues.append((
            "alg_none",
            Severity.HIGH,
            "CWE-347",
            "A02:2021 Cryptographic Failures",
            "ID tokens accept the 'none' signature algorithm",
            "The provider advertises 'none' as an accepted id_token signing algorithm. A client "
            "that honours the metadata will accept an unsigned identity token, so anyone can mint "
            "an id_token for any subject and impersonate any user.",
            "id_token_signing_alg_values_supported: " + ", ".join(algs[:6]),
        ))
    elif "hs256" in lowered and not asymmetric:
        issues.append((
            "alg_hs256_only",
            Severity.MEDIUM,
            "CWE-327",
            "A02:2021 Cryptographic Failures",
            "ID tokens are only signed with the symmetric HS256 algorithm",
            "HS256 is the only advertised id_token signing algorithm, so every relying party "
            "verifies tokens with a shared client secret. Any client (or anyone who obtains one "
            "client secret) can forge identity tokens for the whole provider.",
            "id_token_signing_alg_values_supported: " + ", ".join(algs[:6]),
        ))

    pkce = data.get("code_challenge_methods_supported")
    pkce_methods = _string_list(pkce)
    if pkce is None or "S256" not in pkce_methods:
        issues.append((
            "no_pkce",
            Severity.LOW,
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "PKCE S256 is not advertised",
            "The discovery document does not advertise the S256 PKCE code-challenge method. "
            "Without PKCE, an authorization code intercepted from a public client (mobile app or "
            "SPA) can be redeemed by the attacker.",
            "code_challenge_methods_supported: %s" % (", ".join(pkce_methods) or "absent"),
        ))

    grants = [g.lower() for g in _string_list(data.get("grant_types_supported"))]
    if "password" in grants:
        issues.append((
            "ropc",
            Severity.LOW,
            "CWE-287",
            "A07:2021 Identification and Authentication Failures",
            "Resource owner password credentials grant is enabled",
            "The password grant is advertised, which requires clients to handle the user's "
            "credentials directly. It defeats multi-factor and federated login and is removed in "
            "OAuth 2.1.",
            "grant_types_supported: password",
        ))

    return issues


@register
class OidcMisconfig(Check):
    name = "api.oidc_misconfig"
    title = "OAuth/OIDC discovery-document misconfiguration"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        root = _root(ctx)
        if not root:
            return
        emitted = 0
        seen = set()
        for path in _OIDC_PATHS:
            if emitted >= 6:
                break
            url = root + path
            response = ctx.http.get(url)
            if response is None or response.status_code != 200:
                continue
            data = _json_dict(response)
            if not data or "issuer" not in data:
                continue
            if "authorization_endpoint" not in data and "token_endpoint" not in data:
                continue
            for issue in _oidc_issues(data):
                if emitted >= 6:
                    break
                key, severity, cwe, category, title, description, evidence = issue
                if key in seen:
                    continue
                seen.add(key)
                emitted += 1
                yield Finding(
                    check=self.name,
                    title=title,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    cwe=cwe,
                    description=description + " The value was read directly from the provider's "
                    "own metadata document at %s." % path,
                    remediation=(
                        "Correct the authorization server configuration so the discovery document "
                        "advertises HTTPS endpoints only, drops the implicit and password grants, "
                        "signs id_tokens with RS256/ES256, and requires PKCE with S256."
                    ),
                    location=url,
                    evidence=evidence,
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc9700",
                        "https://openid.net/specs/openid-connect-discovery-1_0.html",
                    ],
                )


# --------------------------------------------------------------------------------------
# api.soap_wsdl_exposure
# --------------------------------------------------------------------------------------

_WSDL_BASES = ["/", "/service", "/services", "/soap", "/ws"]
_WSDL_QUERIES = ["?wsdl", "?WSDL"]


def _wsdl_match(response):
    """Return (evidence, confidence) when the body is a real WSDL contract."""
    body = response.text or ""
    if "<wsdl:definitions" in body:
        return "wsdl:definitions root element", Confidence.HIGH
    if "<definitions " in body and "schemas.xmlsoap.org/wsdl" in body:
        return "definitions element in the WSDL namespace", Confidence.HIGH
    ctype = response.headers.get("content-type", "").lower()
    if ctype.startswith("text/xml") and "<soap:" in body:
        return "text/xml body containing SOAP elements", Confidence.MEDIUM
    return "", Confidence.MEDIUM


@register
class SoapWsdlExposure(Check):
    name = "api.soap_wsdl_exposure"
    title = "Exposed SOAP WSDL service contract"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def _asmx_paths(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if _is_aggressive(ctx) else _SAFE_CRAWL_CAP
        paths = []
        for url, _params in _discover(ctx, cap, set()):
            try:
                path = urlsplit(url).path or ""
            except ValueError:
                continue
            if path.lower().endswith(".asmx") and path not in paths:
                paths.append(path)
            if len(paths) >= 3:
                break
        return paths

    def run(self, ctx: ScanContext):
        root = _root(ctx)
        if not root or is_catch_all(ctx):
            return
        bases = list(_WSDL_BASES)
        for path in self._asmx_paths(ctx):
            if path not in bases:
                bases.append(path)

        emitted = 0
        for path in bases:
            if emitted >= 3:
                break
            for query in _WSDL_QUERIES:
                url = root + path + query
                response = ctx.http.get(url)
                if response is None or response.status_code != 200:
                    continue
                evidence, confidence = _wsdl_match(response)
                if not evidence:
                    continue
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="Exposed SOAP WSDL at %s" % (path + query),
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-200",
                    description=(
                        "A WSDL service contract is served without authentication at %s. The "
                        "document enumerates every SOAP operation, its message types and the "
                        "endpoint bindings, which hands an attacker the complete API surface "
                        "and the exact request shapes needed to call it." % (path + query)
                    ),
                    remediation=(
                        "Disable WSDL publication in production (for example "
                        "<serviceMetadata httpGetEnabled=\"false\"/> on WCF, or the equivalent "
                        "setting on your SOAP stack), or require authentication for the ?wsdl "
                        "document and distribute the contract out of band."
                    ),
                    location=url,
                    evidence=evidence,
                    references=[
                        "https://cwe.mitre.org/data/definitions/200.html",
                        "https://owasp.org/www-project-web-security-testing-guide/",
                    ],
                )
                break
