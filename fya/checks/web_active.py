from __future__ import annotations

import re
from html import escape
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_LINK_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'>]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*?>.*?</form>", re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"'>]*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*["']([^"'>]+)["']""", re.IGNORECASE)

_SAFE_CRAWL_CAP = 25
_AGGRESSIVE_CRAWL_CAP = 60

_REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "return", "returnto", "dest", "destination", "continue", "go", "target"}
_AGGRESSIVE_REDIRECT_PARAMS = _REDIRECT_PARAMS | {"u", "link", "out", "goto", "rurl", "forward", "callback", "checkout_url"}

_SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysqli",
    "unclosed quotation mark",
    "sql syntax",
    "sqlite3.operationalerror",
    "sqlite error",
    "unrecognized token",
    "near \"",
    "psql:",
    "pg_query",
    "postgresql",
    "syntax error at or near",
    "ora-00933",
    "ora-01756",
    "ora-",
    "odbc",
    "sqlstate",
]

_PASSWD_SIGNATURE = re.compile(r"root:.*:0:0:")
_WIN_INI_SIGNATURE = re.compile(r"\[(?:fonts|extensions|mci extensions|files)\]", re.IGNORECASE)

_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../windows/win.ini",
]

_SENSITIVE_PATHS = [
    ("/.env", "environment secrets file"),
    ("/.git/config", "git repository config"),
    ("/.git/HEAD", "git repository head"),
    ("/config.json", "application config"),
    ("/backup.zip", "backup archive"),
    ("/.DS_Store", "macOS directory index"),
    ("/docker-compose.yml", "docker compose definition"),
]

_SENSITIVE_MARKERS = {
    "/.env": ["=", "secret", "key", "password", "token", "api"],
    "/.git/config": ["[core]", "repositoryformatversion", "[remote"],
    "/.git/HEAD": ["ref:", "refs/heads"],
    "/config.json": ["{", "}"],
    "/.DS_Store": ["Bud1", "\x00\x00\x00"],
    "/docker-compose.yml": ["services:", "version:", "image:"],
}

_DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}


def _same_host(url: str, host: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not parsed.netloc:
        return True
    return parsed.hostname == host


def _params_of(url: str):
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    return [k for k, _ in parse_qsl(query, keep_blank_values=True)]


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    out = []
    for key, val in pairs:
        if key == param:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, val))
    if not replaced:
        out.append((param, value))
    new_query = urlencode(out)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _discover(ctx: ScanContext, cap: int, extra_params: set):
    base = ctx.target.base_url()
    host = ctx.target.host
    urls = {}
    seeds = []
    if base:
        seeds.append(base)
    if ctx.target.url:
        seeds.append(ctx.target.url)
    for extra in ctx.target.metadata.get("seed_urls", []):
        if extra not in seeds:
            seeds.append(extra)

    for seed in seeds:
        response = ctx.http.get(seed)
        if response is None:
            continue
        body = response.text or ""

        for match in _LINK_RE.findall(body):
            absolute = urljoin(seed, match).split("#", 1)[0]
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, host):
                continue
            found = _params_of(absolute)
            if found:
                urls.setdefault(absolute, set()).update(found)
            elif len(urls) < cap:
                urls.setdefault(absolute, set())

        for form_block in _FORM_RE.findall(body):
            action_match = _FORM_ACTION_RE.search(form_block)
            action = action_match.group(1) if action_match else seed
            absolute = urljoin(seed, action or seed)
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, host):
                continue
            names = set(_INPUT_NAME_RE.findall(form_block))
            urls.setdefault(absolute, set()).update(names)

        if len(urls) >= cap:
            break

    for seed in seeds:
        found = _params_of(seed)
        if found:
            urls.setdefault(seed, set()).update(found)

    result = []
    for url, params in urls.items():
        merged = set(params)
        merged.update(extra_params)
        result.append((url, merged))
        if len(result) >= cap:
            break
    return result


@register
class ReflectedXSS(Check):
    name = "web.reflected_xss"
    title = "Reflected cross-site scripting"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        seen = set()
        for url, params in _discover(ctx, cap, set()):
            for param in params:
                if not param:
                    continue
                marker = ctx.http.marker()
                payload = f"<fya>{marker}</fya>"
                probe = _set_param(url, param, payload)
                response = ctx.http.get(probe)
                if response is None:
                    continue
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue
                body = response.text or ""
                if payload in body:
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        continue
                    seen.add(location)
                    yield Finding(
                        check=self.name,
                        title=f"Reflected XSS via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="A03:2021 Injection",
                        cwe="CWE-79",
                        description="A unique probe injected into this parameter was reflected into the HTML "
                        "response without entity-encoding the angle brackets, which may allow script injection "
                        "depending on the output context. Manual confirmation of the reflection context is recommended.",
                        remediation="Contextually encode all user input on output and apply a strict "
                        "Content-Security-Policy. Prefer framework auto-escaping.",
                        location=location,
                        evidence=f"reflected unescaped: {escape(payload)}",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )


@register
class SQLInjectionError(Check):
    name = "web.sql_injection"
    title = "SQL injection (error based)"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        seen = set()
        for url, params in _discover(ctx, cap, set()):
            for param in params:
                if not param:
                    continue
                baseline = ctx.http.get(_set_param(url, param, "1"))
                baseline_body = (baseline.text or "").lower() if baseline is not None else ""
                probe = _set_param(url, param, "1'\"")
                response = ctx.http.get(probe)
                if response is None:
                    continue
                body = (response.text or "").lower()
                matched = next((sig for sig in _SQL_ERROR_SIGNATURES if sig in body and sig not in baseline_body), None)
                if matched:
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        continue
                    seen.add(location)
                    yield Finding(
                        check=self.name,
                        title=f"SQL injection via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="A03:2021 Injection",
                        cwe="CWE-89",
                        description="Appending a quote character to this parameter produced a database error "
                        "signature in the response, indicating input is concatenated into a SQL statement.",
                        remediation="Use parameterized queries or prepared statements. Never build SQL by "
                        "string concatenation and suppress verbose database errors.",
                        location=location,
                        evidence=f"error signature: {matched}",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    )


@register
class OpenRedirect(Check):
    name = "web.open_redirect"
    title = "Open redirect"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        redirect_names = _AGGRESSIVE_REDIRECT_PARAMS if ctx.profile is Profile.AGGRESSIVE else _REDIRECT_PARAMS
        marker = ctx.http.marker()
        oob_host = "fya-oob.example"
        payloads = [
            f"https://{oob_host}/{marker}",
            f"//{oob_host}/{marker}",
            f"\\\\{oob_host}\\{marker}",
        ]
        seen = set()
        for url, params in _discover(ctx, cap, set()):
            candidates = {p for p in params if p and p.lower() in redirect_names}
            for param in candidates:
                hit = None
                for payload in payloads:
                    probe = _set_param(url, param, payload)
                    response = ctx.http.get(probe, allow_redirects=False)
                    if response is None:
                        continue
                    if response.status_code not in (301, 302, 303, 307, 308):
                        continue
                    location_header = response.headers.get("location", "")
                    refresh_header = response.headers.get("refresh", "")
                    redirect_host = ""
                    try:
                        redirect_host = urlparse(location_header.replace("\\", "/")).hostname or ""
                    except ValueError:
                        redirect_host = ""
                    if (
                        redirect_host == oob_host
                        or oob_host in location_header
                        or oob_host in refresh_header
                    ):
                        hit = (payload, location_header or f"Refresh: {refresh_header}")
                        break
                if hit is not None:
                    used_payload, evidence_value = hit
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        continue
                    seen.add(location)
                    yield Finding(
                        check=self.name,
                        title=f"Open redirect via parameter '{param}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="A01:2021 Broken Access Control",
                        cwe="CWE-601",
                        description="This parameter controls the redirect target without validation, so an "
                        "attacker can send victims to an arbitrary external site for phishing.",
                        remediation="Redirect only to a server-side allowlist of paths or hosts. Reject "
                        "absolute external URLs supplied by the client.",
                        location=location,
                        evidence=f"payload: {used_payload}; {evidence_value}",
                        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                    )


@register
class PathTraversal(Check):
    name = "web.path_traversal"
    title = "Path traversal"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        payloads = _TRAVERSAL_PAYLOADS if ctx.profile is Profile.AGGRESSIVE else _TRAVERSAL_PAYLOADS[:1]
        seen = set()
        for url, params in _discover(ctx, cap, set()):
            for param in params:
                if not param:
                    continue
                hit = None
                used = None
                for payload in payloads:
                    response = ctx.http.get(_set_param(url, param, payload))
                    if response is None:
                        continue
                    body = response.text or ""
                    if _PASSWD_SIGNATURE.search(body) or _WIN_INI_SIGNATURE.search(body):
                        hit = body
                        used = payload
                        break
                if hit is not None:
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        continue
                    seen.add(location)
                    yield Finding(
                        check=self.name,
                        title=f"Path traversal via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="A01:2021 Broken Access Control",
                        cwe="CWE-22",
                        description="A directory traversal sequence in this parameter returned the contents of a "
                        "system file, indicating the application reads files from an attacker-controlled path.",
                        remediation="Resolve and canonicalize paths, then confirm they stay within an intended "
                        "base directory. Prefer opaque identifiers over raw filenames.",
                        location=location,
                        evidence=f"payload: {used}",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    )


@register
class CORSMisconfig(Check):
    name = "web.cors_misconfig"
    title = "CORS misconfiguration"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        evil = "https://evil.example"
        seen = set()
        targets = [ctx.target.base_url()]
        for url, _ in _discover(ctx, cap, set()):
            targets.append(url)
        for url in targets:
            if not url or url in seen:
                continue
            seen.add(url)
            response = ctx.http.get(url, headers={"Origin": evil})
            if response is None:
                continue
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "").lower()
            if acao == evil and acac == "true":
                yield Finding(
                    check=self.name,
                    title="CORS reflects arbitrary origin with credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-942",
                    description="The response reflects an attacker-supplied Origin into "
                    "Access-Control-Allow-Origin while also allowing credentials, letting a malicious site "
                    "read authenticated responses.",
                    remediation="Validate Origin against a strict server-side allowlist and never combine a "
                    "wildcard or reflected origin with Access-Control-Allow-Credentials: true.",
                    location=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                )
            elif acao == "*" and acac == "true":
                yield Finding(
                    check=self.name,
                    title="CORS wildcard origin combined with credentials",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-942",
                    description="The response sets Access-Control-Allow-Origin to the literal wildcard along "
                    "with Access-Control-Allow-Credentials: true. Browsers reject credentialed responses under "
                    "a wildcard origin, so this is not directly exploitable but reflects a misconfigured policy.",
                    remediation="Validate Origin against a strict server-side allowlist and never combine a "
                    "wildcard or reflected origin with Access-Control-Allow-Credentials: true.",
                    location=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                )


@register
class DangerousMethods(Check):
    name = "web.dangerous_methods"
    title = "Dangerous HTTP methods"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.request("OPTIONS", base)
        if response is None:
            return
        allow = response.headers.get("allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & _DANGEROUS_METHODS)
        if risky:
            yield Finding(
                check=self.name,
                title=f"Dangerous HTTP methods enabled: {', '.join(risky)}",
                severity=Severity.MEDIUM if "TRACE" in risky else Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-650",
                description="The server advertises HTTP methods in its Allow header that are rarely needed and "
                "can enable cross-site tracing or unintended resource modification.",
                remediation="Disable unused HTTP methods at the application or web server layer and allow only "
                "the verbs each endpoint requires.",
                location=base,
                evidence=f"Allow: {allow}",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            )


@register
class SensitiveFileExposure(Check):
    name = "web.sensitive_files"
    title = "Sensitive file exposure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path, description in _SENSITIVE_PATHS:
            response = ctx.http.get(urljoin(base + "/", path.lstrip("/")))
            if response is None:
                continue
            if response.status_code != 200:
                continue
            body = response.text or ""
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type and "<html" in body[:400].lower():
                continue
            markers = _SENSITIVE_MARKERS.get(path, [])
            plausible = (not markers and bool(body.strip())) or any(m.lower() in body.lower() for m in markers)
            if not plausible:
                continue
            yield Finding(
                check=self.name,
                title=f"Sensitive file exposed: {path}",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-538",
                description=f"The {description} at {path} is served publicly and returned HTTP 200 with "
                "plausible content, potentially leaking secrets, source, or infrastructure details.",
                remediation="Block access to dotfiles, VCS metadata, backups, and config from the web root. "
                "Serve only intended public assets.",
                location=urljoin(base + "/", path.lstrip("/")),
                evidence=f"HTTP 200, {len(body)} bytes, content-type: {content_type or 'unknown'}",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            )
