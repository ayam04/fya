from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
_SENSITIVE_HINTS = ("admin", "backup", "config", "private", "internal", "api-docs")


@register
class SecurityTxt(Check):
    name = "web.security_txt"
    title = "security.txt publication"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path in _SECURITY_TXT_PATHS:
            response = ctx.http.get(base + path)
            if response is None:
                continue
            if response.status_code != 200:
                continue
            body = response.text or ""
            if "Contact:" in body or "Policy:" in body:
                return
        yield Finding(
            check=self.name,
            title="No security.txt published",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category="A05:2021 Security Misconfiguration",
            cwe=None,
            description="No valid security.txt was found at /.well-known/security.txt or /security.txt. "
            "A security.txt file gives researchers a documented channel to report vulnerabilities.",
            remediation="Publish a security.txt at /.well-known/security.txt with a Contact and Policy field.",
            location=base + _SECURITY_TXT_PATHS[0],
            evidence="checked: " + ", ".join(_SECURITY_TXT_PATHS),
            references=["https://securitytxt.org"],
        )


@register
class RobotsSensitivePaths(Check):
    name = "web.robots_sensitive_paths"
    title = "robots.txt sensitive path disclosure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.get(base + "/robots.txt")
        if response is None:
            return
        if response.status_code != 200:
            return
        body = response.text or ""
        disclosed = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lowered = stripped.lower()
            if not lowered.startswith("disallow:"):
                continue
            value = stripped.split(":", 1)[1].strip()
            if not value:
                continue
            if any(hint in value.lower() for hint in _SENSITIVE_HINTS):
                disclosed.append(value)
        if not disclosed:
            return
        yield Finding(
            check=self.name,
            title="robots.txt discloses sensitive paths",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            category="A05:2021 Security Misconfiguration",
            cwe="CWE-200",
            description="The robots.txt file lists Disallow entries that reference sensitive-looking paths. "
            "These entries advertise the location of restricted areas to anyone reading the file.",
            remediation="Do not rely on robots.txt to hide sensitive paths; enforce access control and remove "
            "sensitive entries from robots.txt.",
            location=base + "/robots.txt",
            evidence="Disallow: " + ", ".join(disclosed),
            references=["https://owasp.org/www-community/attacks/Forced_browsing"],
        )
