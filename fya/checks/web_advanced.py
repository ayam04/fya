from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_LINK_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'>]+)["']""", re.IGNORECASE)
_FULL_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_FORM_BODY_RE = re.compile(r"<form\b[^>]*?>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']?\s*(post)\s*["']?""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"'>]*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(
    r"""<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*["']([^"'>]+)["']""",
    re.IGNORECASE,
)
_ABS_LINK_RE = re.compile(r"""https?://[^\s"'<>]+""", re.IGNORECASE)

_CSRF_NAMES = re.compile(
    r"^(csrf|xsrf|_token|authenticity_token|csrfmiddlewaretoken|nonce)",
    re.IGNORECASE,
)

_CSRF_META_RE = re.compile(
    r"""<meta\b[^>]*?\bname\s*=\s*["'][^"'>]*(?:csrf|xsrf)[^"'>]*["']""",
    re.IGNORECASE,
)
_SAMESITE_RE = re.compile(r"""samesite\s*=\s*(lax|strict)""", re.IGNORECASE)

_SAFE_CAP = 20
_AGGRESSIVE_CAP = 50


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
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out), parts.fragment))


def _local_discover(ctx: ScanContext, cap: int):
    base = ctx.target.base_url()
    host = ctx.target.host
    urls: dict = {}
    seeds = []
    if base:
        seeds.append(base)
    if ctx.target.url:
        seeds.append(ctx.target.url)

    for seed in seeds:
        response = ctx.http.get(seed)
        if response is None:
            continue
        body = response.text or ""

        for href in _LINK_RE.findall(body):
            absolute = urljoin(seed, href).split("#", 1)[0]
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, host):
                continue
            found = _params_of(absolute)
            if found:
                urls.setdefault(absolute, set()).update(found)
            elif len(urls) < cap:
                urls.setdefault(absolute, set())

        for form_body in _FULL_FORM_RE.findall(body):
            action_match = _FORM_ACTION_RE.search(form_body)
            action = action_match.group(1) if action_match else seed
            absolute = urljoin(seed, action or seed)
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, host):
                continue
            names = set(_INPUT_NAME_RE.findall(form_body))
            urls.setdefault(absolute, set()).update(names)

        if len(urls) >= cap:
            break

    for seed in seeds:
        found = _params_of(seed)
        if found:
            urls.setdefault(seed, set()).update(found)

    result = []
    for url, params in urls.items():
        result.append((url, params))
        if len(result) >= cap:
            break
    return result


def _collect_post_forms(ctx: ScanContext, cap: int):
    base = ctx.target.base_url()
    host = ctx.target.host
    forms = []
    seeds = []
    if base:
        seeds.append(base)
    if ctx.target.url:
        seeds.append(ctx.target.url)

    visited = set()
    to_visit = list(dict.fromkeys(seeds))

    while to_visit and len(forms) < cap:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        response = ctx.http.get(url)
        if response is None:
            continue
        body = response.text or ""

        for href in _LINK_RE.findall(body):
            absolute = urljoin(url, href).split("#", 1)[0]
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, host):
                continue
            if absolute not in visited:
                to_visit.append(absolute)

        set_cookie = response.headers.get("set-cookie", "") or ""

        for full_form in _FULL_FORM_RE.findall(body):
            if not _FORM_METHOD_RE.search(full_form):
                continue
            action_match = _FORM_ACTION_RE.search(full_form)
            action = action_match.group(1) if action_match else url
            action_url = urljoin(url, action or url)
            input_names = set(_INPUT_NAME_RE.findall(full_form))
            forms.append((action_url, full_form, input_names, body, set_cookie))
            if len(forms) >= cap:
                break

    return forms


_SSTI_SAFE_PAYLOADS = [
    ("{{N1*N2}}", "jinja2/twig/django"),
    ("${N1*N2}", "freemarker/groovy"),
]

_SSTI_AGGRESSIVE_PAYLOADS = [
    ("{{N1*N2}}", "jinja2/twig/django"),
    ("${N1*N2}", "freemarker/groovy"),
    ("#{N1*N2}", "thymeleaf/ruby"),
    ("<%= N1*N2 %>", "erb/asp"),
]


@register
class SSTI(Check):
    name = "web.ssti"
    title = "Server-Side Template Injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CAP
        payload_templates = (
            _SSTI_AGGRESSIVE_PAYLOADS
            if ctx.profile is Profile.AGGRESSIVE
            else _SSTI_SAFE_PAYLOADS
        )
        seen = set()
        discovered = _local_discover(ctx, cap)
        factor_pairs = [(7919, 6271), (4133, 8017)]

        for url, params in discovered:
            for param in params:
                if not param:
                    continue
                baseline = ctx.http.get(_set_param(url, param, "fyabaseline"))
                if baseline is None:
                    continue
                baseline_body = baseline.text or ""
                products = [str(n1 * n2) for n1, n2 in factor_pairs]
                if any(product in baseline_body for product in products):
                    continue
                for template, engine_hint in payload_templates:
                    confirmed = True
                    for (n1, n2), product in zip(factor_pairs, products):
                        payload = template.replace("N1", str(n1)).replace("N2", str(n2))
                        response = ctx.http.get(_set_param(url, param, payload))
                        if response is None:
                            confirmed = False
                            break
                        body = response.text or ""
                        if product not in body or payload in body:
                            confirmed = False
                            break
                    if not confirmed:
                        continue
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        break
                    seen.add(location)
                    sample_n1, sample_n2 = factor_pairs[0]
                    sample_payload = template.replace("N1", str(sample_n1)).replace("N2", str(sample_n2))
                    yield Finding(
                        check=self.name,
                        title=f"Server-Side Template Injection via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="A03:2021 Injection",
                        cwe="CWE-1336",
                        description=(
                            f"Template expressions injected into parameter '{param}' "
                            f"were evaluated by the server. Two distinct products ({products[0]} "
                            f"and {products[1]}) appeared for their respective payloads, were "
                            f"absent from a benign baseline, and the literal payloads did not "
                            f"appear, confirming server-side evaluation. Engine hint: {engine_hint}."
                        ),
                        remediation=(
                            "Never pass user input to template rendering functions. "
                            "Use template variables with auto-escaping and sandboxed "
                            "template engines where dynamic template construction is needed."
                        ),
                        location=location,
                        evidence=f"payload: {sample_payload}, evaluated products: {', '.join(products)} found in response",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
                            "https://cwe.mitre.org/data/definitions/1336.html",
                        ],
                    )
                    break


@register
class CSRF(Check):
    name = "web.csrf"
    title = "Cross-Site Request Forgery"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CAP
        seen = set()
        forms = _collect_post_forms(ctx, cap)

        for action_url, _full_form, input_names, page_body, set_cookie in forms:
            has_token = any(_CSRF_NAMES.match(name) for name in input_names)
            if has_token:
                continue
            if _CSRF_META_RE.search(page_body or ""):
                continue
            if _SAMESITE_RE.search(set_cookie or ""):
                continue
            location = action_url
            if location in seen:
                continue
            seen.add(location)
            yield Finding(
                check=self.name,
                title=f"CSRF: POST form at '{action_url}' has no CSRF token",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="A01:2021 Broken Access Control",
                cwe="CWE-352",
                description=(
                    f"A POST form targeting '{action_url}' contains no hidden input "
                    "whose name matches known CSRF token field names (csrf, xsrf, "
                    "_token, authenticity_token, csrfmiddlewaretoken, nonce). "
                    "Without a token an attacker can forge requests on behalf of authenticated users."
                ),
                remediation=(
                    "Add a secret per-session CSRF token to every state-changing form "
                    "and verify it server-side. Consider the SameSite=Strict cookie attribute "
                    "as a defence-in-depth measure."
                ),
                location=location,
                evidence=f"form inputs found: {', '.join(sorted(input_names)) or 'none'}",
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cwe.mitre.org/data/definitions/352.html",
                ],
            )


@register
class HostHeaderInjection(Check):
    name = "web.host_header"
    title = "Host header injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        cap = _AGGRESSIVE_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CAP
        marker = ctx.http.marker()
        spoofed_host = f"{marker}.evil.example"

        probe_urls = [base]
        for url, _ in _local_discover(ctx, cap):
            probe_urls.append(url)

        seen = set()
        for probe_url in probe_urls:
            if probe_url in seen:
                continue
            seen.add(probe_url)
            response = ctx.http.get(
                probe_url, headers={"Host": spoofed_host}, allow_redirects=False
            )
            if response is None:
                continue
            body = response.text or ""
            location_header = response.headers.get("location", "")
            reflected_in_body = marker in body
            reflected_in_redirect = marker in location_header
            abs_links = _ABS_LINK_RE.findall(body)
            reflected_in_link = any(marker in lnk for lnk in abs_links)

            if reflected_in_body or reflected_in_redirect or reflected_in_link:
                evidence_parts = []
                if reflected_in_body:
                    evidence_parts.append("reflected in response body")
                if reflected_in_redirect:
                    evidence_parts.append(f"reflected in Location: {location_header}")
                if reflected_in_link:
                    matched = next((lnk for lnk in abs_links if marker in lnk), "")
                    evidence_parts.append(f"reflected in absolute link: {matched}")
                yield Finding(
                    check=self.name,
                    title="Host header injection: spoofed Host reflected in response",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-644",
                    description=(
                        "The application reflects the HTTP Host header value into its response "
                        "without validation. An attacker can poison password-reset links, cache "
                        "entries, or absolute URLs by supplying a crafted Host header."
                    ),
                    remediation=(
                        "Maintain a server-side allowlist of valid hostnames. Never use the "
                        "request Host header to construct absolute URLs or links."
                    ),
                    location=probe_url,
                    evidence="; ".join(evidence_parts),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection",
                        "https://cwe.mitre.org/data/definitions/644.html",
                    ],
                )
                return


@register
class CRLFInjection(Check):
    name = "web.crlf"
    title = "CRLF / header injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CAP
        seen = set()
        discovered = _local_discover(ctx, cap)

        for url, params in discovered:
            for param in params:
                if not param:
                    continue
                marker = ctx.http.marker()
                payload = f"safe\r\nFya-Test: {marker}"
                probe = _set_param(url, param, payload)
                response = ctx.http.get(probe)
                if response is None:
                    continue
                injected = response.headers.get("Fya-Test", "")
                if marker in injected:
                    location = f"{url} [param: {param}]"
                    if location in seen:
                        continue
                    seen.add(location)
                    yield Finding(
                        check=self.name,
                        title=f"CRLF injection via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="A03:2021 Injection",
                        cwe="CWE-93",
                        description=(
                            f"A CR LF sequence injected into parameter '{param}' caused "
                            "the server to emit an attacker-controlled response header "
                            f"('Fya-Test: {marker}'). This enables HTTP response splitting, "
                            "cache poisoning, and cookie injection."
                        ),
                        remediation=(
                            "Strip or reject CR (\\r) and LF (\\n) characters from any "
                            "value that flows into response headers. "
                            "Use framework abstractions that handle header encoding."
                        ),
                        location=location,
                        evidence=f"injected header Fya-Test: {marker}",
                        references=[
                            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                            "https://cwe.mitre.org/data/definitions/93.html",
                        ],
                    )
