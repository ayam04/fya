from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_CATEGORY = "A05:2021 Security Misconfiguration"
_CWE = "CWE-693"
_REFERENCES = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "https://owasp.org/www-community/controls/Content_Security_Policy",
]


def _parse(policy: str) -> dict:
    directives: dict = {}
    for part in policy.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        directives[name] = [t.strip() for t in tokens[1:]]
    return directives


@register
class ContentSecurityPolicyWeaknesses(Check):
    name = "web.csp_weaknesses"
    title = "Content-Security-Policy weaknesses"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.get(base)
        if response is None:
            return
        raw = response.headers.get("Content-Security-Policy")
        if not raw:
            return
        directives = _parse(raw)
        script_src = directives.get("script-src")
        style_src = directives.get("style-src")
        default_src = directives.get("default-src")

        if script_src is not None and "'unsafe-inline'" in script_src:
            yield self._finding(
                base,
                "CSP script-src allows 'unsafe-inline'",
                Severity.MEDIUM,
                "The script-src directive permits 'unsafe-inline', which allows inline scripts to "
                "execute and largely defeats CSP as an anti-XSS control.",
                "Remove 'unsafe-inline' from script-src and use nonces or hashes for required inline scripts.",
                f"script-src {' '.join(script_src)}",
            )
        if style_src is not None and "'unsafe-inline'" in style_src:
            yield self._finding(
                base,
                "CSP style-src allows 'unsafe-inline'",
                Severity.MEDIUM,
                "The style-src directive permits 'unsafe-inline', enabling injected inline styles that "
                "can be abused for data exfiltration and UI redressing.",
                "Remove 'unsafe-inline' from style-src and use nonces or hashes for required inline styles.",
                f"style-src {' '.join(style_src)}",
            )
        for directive, values in (("script-src", script_src), ("style-src", style_src), ("default-src", default_src)):
            if values is not None and "'unsafe-eval'" in values:
                yield self._finding(
                    base,
                    f"CSP {directive} allows 'unsafe-eval'",
                    Severity.MEDIUM,
                    f"The {directive} directive permits 'unsafe-eval', allowing string-to-code execution "
                    "via eval and similar sinks that expand the XSS attack surface.",
                    f"Remove 'unsafe-eval' from {directive} and refactor code that relies on dynamic evaluation.",
                    f"{directive} {' '.join(values)}",
                )
        for directive, values in (("script-src", script_src), ("default-src", default_src)):
            if values is not None and "*" in values:
                yield self._finding(
                    base,
                    f"CSP {directive} uses a wildcard source",
                    Severity.MEDIUM,
                    f"The {directive} directive contains a wildcard * source, permitting scripts to load "
                    "from any origin and negating source restriction.",
                    f"Replace the wildcard in {directive} with an explicit allowlist of trusted origins.",
                    f"{directive} {' '.join(values)}",
                )
        if script_src is not None and any(v.lower().startswith("data:") for v in script_src):
            yield self._finding(
                base,
                "CSP script-src allows data: URIs",
                Severity.MEDIUM,
                "The script-src directive allows the data: scheme, letting an attacker inline arbitrary "
                "script payloads that bypass origin restrictions.",
                "Remove data: from script-src so scripts can only load from trusted origins.",
                f"script-src {' '.join(script_src)}",
            )
        if "object-src" not in directives:
            yield self._finding(
                base,
                "CSP missing object-src directive",
                Severity.LOW,
                "No object-src directive is set, so plugin content such as Flash or Java applets is not "
                "restricted and can be abused to bypass the policy.",
                "Add object-src 'none' to block legacy plugin content.",
                f"Content-Security-Policy: {raw}",
            )
        if "base-uri" not in directives:
            yield self._finding(
                base,
                "CSP missing base-uri directive",
                Severity.LOW,
                "No base-uri directive is set, so an injected <base> tag can rewrite relative URLs and "
                "redirect resource loads to an attacker-controlled origin.",
                "Add base-uri 'self' (or 'none') to lock down the document base URL.",
                f"Content-Security-Policy: {raw}",
            )
        if default_src is None and script_src is None:
            yield self._finding(
                base,
                "CSP defines neither default-src nor script-src",
                Severity.LOW,
                "The policy sets neither default-src nor script-src, so script loading is left unrestricted "
                "and the policy provides no XSS mitigation for scripts.",
                "Define a restrictive default-src or an explicit script-src allowlist.",
                f"Content-Security-Policy: {raw}",
            )

    def _finding(self, base, title, severity, description, remediation, evidence) -> Finding:
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=Confidence.HIGH,
            category=_CATEGORY,
            cwe=_CWE,
            description=description,
            remediation=remediation,
            location=base,
            evidence=evidence,
            references=list(_REFERENCES),
        )
