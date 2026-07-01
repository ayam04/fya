from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_HEADERS = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Missing Content-Security-Policy header",
        "No Content-Security-Policy header was returned. CSP is the primary defense-in-depth "
        "control against cross-site scripting and data injection in the browser.",
        "Set a Content-Security-Policy that restricts script and object sources to trusted origins.",
        "A05:2021 Security Misconfiguration",
        "CWE-693",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Missing Strict-Transport-Security (HSTS) header",
        "No HSTS header was returned. Without HSTS, clients can be downgraded to plaintext HTTP "
        "and are exposed to man-in-the-middle attacks.",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses.",
        "A05:2021 Security Misconfiguration",
        "CWE-319",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Responses do not send X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff "
        "content and interpret responses as an unintended type.",
        "Add X-Content-Type-Options: nosniff to all responses.",
        "A05:2021 Security Misconfiguration",
        "CWE-693",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Missing clickjacking protection",
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was found, so the page can be "
        "framed by other origins and is exposed to clickjacking.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors 'none' directive.",
        "A05:2021 Security Misconfiguration",
        "CWE-1021",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Missing Referrer-Policy header",
        "No Referrer-Policy header was returned; full URLs may leak to third parties via the Referer header.",
        "Set Referrer-Policy: no-referrer-when-downgrade or stricter.",
        "A05:2021 Security Misconfiguration",
        "CWE-200",
    ),
}


@register
class SecurityHeaders(Check):
    name = "web.security_headers"
    title = "HTTP security headers"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        present = {k.lower(): v for k, v in response.headers.items()}
        csp = present.get("content-security-policy", "")
        for header, (sev, title, desc, fix, category, cwe) in _HEADERS.items():
            if header == "x-frame-options" and "frame-ancestors" in csp:
                continue
            if header == "strict-transport-security" and ctx.target.scheme != "https":
                continue
            if header not in present:
                yield Finding(
                    check=self.name,
                    title=title,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    category=category,
                    cwe=cwe,
                    description=desc,
                    remediation=fix,
                    location=base,
                    evidence=f"response headers: {sorted(present.keys())}",
                    references=["https://owasp.org/www-project-secure-headers/"],
                )


@register
class ServerDisclosure(Check):
    name = "web.version_disclosure"
    title = "Server version disclosure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = response.headers.get(header)
            if value and any(ch.isdigit() for ch in value):
                yield Finding(
                    check=self.name,
                    title=f"Version disclosed in {header} header",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-200",
                    description=f"The {header} header reveals software and version ({value}), which "
                    "helps an attacker match the target to known CVEs.",
                    remediation=f"Suppress or genericize the {header} header at the server or proxy.",
                    location=base,
                    evidence=f"{header}: {value}",
                    references=["https://owasp.org/www-community/Security_Misconfiguration"],
                )


@register
class InsecureCookies(Check):
    name = "web.insecure_cookies"
    title = "Insecure cookie flags"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        for cookie in response.cookies:
            issues = []
            if ctx.target.scheme == "https" and not cookie.secure:
                issues.append("Secure")
            rest = getattr(cookie, "_rest", {}) or {}
            keys = {k.lower() for k in rest}
            if "httponly" not in keys:
                issues.append("HttpOnly")
            if "samesite" not in keys:
                issues.append("SameSite")
            if issues:
                yield Finding(
                    check=self.name,
                    title=f"Cookie '{cookie.name}' missing flags: {', '.join(issues)}",
                    severity=Severity.MEDIUM if "HttpOnly" in issues else Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-614",
                    description=f"The cookie '{cookie.name}' is set without the {', '.join(issues)} "
                    "attribute(s), weakening protection against theft and cross-site request forgery.",
                    remediation="Set Secure, HttpOnly, and SameSite on session and auth cookies.",
                    location=base,
                    evidence=f"Set-Cookie: {cookie.name}=...",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                )
