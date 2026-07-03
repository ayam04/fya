from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_CATEGORY = "A05:2021 Security Misconfiguration"
_COOP_OK = {"same-origin", "same-origin-allow-popups", "restrict-properties"}


@register
class ModernHeaders(Check):
    name = "web.modern_headers"
    title = "Modern cross-origin and feature headers"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        if "text/html" not in response.headers.get("content-type", "").lower():
            return
        headers = {k.lower(): v for k, v in response.headers.items()}

        coop = headers.get("cross-origin-opener-policy", "").strip().lower()
        if coop not in _COOP_OK:
            yield self._finding(
                base, "Missing or weak Cross-Origin-Opener-Policy", Severity.LOW, "CWE-1021",
                "The document does not set a Cross-Origin-Opener-Policy (or uses unsafe-none), so a "
                "cross-origin opener can retain a reference to this window and mount cross-window attacks "
                "such as tabnabbing and some XS-Leaks.",
                "Set Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups).",
                f"cross-origin-opener-policy: {coop or '(absent)'}",
            )
        if "cross-origin-resource-policy" not in headers:
            yield self._finding(
                base, "Missing Cross-Origin-Resource-Policy", Severity.INFO, "CWE-1021",
                "No Cross-Origin-Resource-Policy header is set, so this resource can be embedded by any "
                "cross-origin document, which contributes to speculative side-channel exposure.",
                "Set Cross-Origin-Resource-Policy: same-origin or same-site where appropriate.",
                "cross-origin-resource-policy: (absent)",
            )
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            yield self._finding(
                base, "Missing Permissions-Policy", Severity.INFO, "CWE-693",
                "No Permissions-Policy (or legacy Feature-Policy) header is set, so powerful browser "
                "features (camera, microphone, geolocation, etc.) are not constrained by policy.",
                "Set a deny-by-default Permissions-Policy that only allows the features the site needs.",
                "permissions-policy: (absent)",
            )

    def _finding(self, base, title, severity, cwe, desc, fix, evidence) -> Finding:
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=Confidence.HIGH,
            category=_CATEGORY,
            cwe=cwe,
            description=desc,
            remediation=fix,
            location=base,
            evidence=evidence,
            references=["https://owasp.org/www-project-secure-headers/"],
        )


@register
class CookieScope(Check):
    name = "web.cookie_scope"
    title = "Cookie prefix and scope"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        host = (ctx.target.host or "").lower()
        seen = set()
        for cookie in response.cookies:
            if cookie.name in seen:
                continue
            seen.add(cookie.name)
            name = cookie.name
            domain_set = bool(getattr(cookie, "domain_specified", False))
            domain = (cookie.domain or "").lstrip(".").lower()

            if name.startswith("__Host-"):
                problems = []
                if not cookie.secure:
                    problems.append("no Secure")
                if domain_set:
                    problems.append("Domain set")
                if cookie.path != "/":
                    problems.append(f"Path={cookie.path}")
                if problems:
                    yield self._finding(
                        base, f"Cookie '{name}' violates __Host- prefix rules ({', '.join(problems)})",
                        Severity.MEDIUM, Confidence.HIGH,
                        f"The cookie '{name}' uses the __Host- prefix but does not meet its requirements "
                        "(Secure, no Domain, Path=/). Browsers reject such cookies, so the intended "
                        "hardening silently does nothing.",
                        "Send __Host- cookies with Secure, Path=/, and no Domain attribute.",
                        f"Set-Cookie: {name} ({', '.join(problems)})",
                    )
            elif name.startswith("__Secure-") and not cookie.secure:
                yield self._finding(
                    base, f"Cookie '{name}' uses __Secure- prefix without Secure",
                    Severity.MEDIUM, Confidence.HIGH,
                    f"The cookie '{name}' uses the __Secure- prefix but is not marked Secure. Browsers "
                    "reject __Secure- cookies without the Secure attribute, so it is silently dropped.",
                    "Add the Secure attribute to __Secure- prefixed cookies.",
                    f"Set-Cookie: {name} (no Secure)",
                )

            if domain_set and domain and domain != host and host.endswith("." + domain):
                yield self._finding(
                    base, f"Cookie '{name}' scoped to broad parent domain",
                    Severity.LOW, Confidence.MEDIUM,
                    f"The cookie '{name}' sets Domain={cookie.domain}, broader than the host {host}. It is "
                    "shared with every sibling subdomain, enabling cookie-tossing from a less-trusted "
                    "subdomain.",
                    "Scope cookies to the exact host (omit Domain) unless cross-subdomain sharing is required.",
                    f"Set-Cookie: {name}; Domain={cookie.domain}",
                )

    def _finding(self, base, title, severity, confidence, desc, fix, evidence) -> Finding:
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=_CATEGORY,
            cwe="CWE-732",
            description=desc,
            remediation=fix,
            location=base,
            evidence=evidence,
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
        )
