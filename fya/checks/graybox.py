from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover, _set_param

_LOGIN_MARKERS = ("type=\"password\"", "type='password'", "sign in", "log in", "login", "authenticate")

_ADMIN_ROUTES = [
    "/admin",
    "/admin/",
    "/administrator",
    "/dashboard",
    "/api/admin",
    "/actuator",
    "/actuator/env",
    "/manage",
    "/management",
    "/debug",
    "/internal",
    "/metrics",
]


def _cap(ctx: ScanContext) -> int:
    return _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP


def _looks_like_login(body: str) -> bool:
    head = body[:1500].lower()
    return any(marker in head for marker in _LOGIN_MARKERS)


@register
class InsecureDirectObjectRef(Check):
    name = "graybox.idor"
    title = "Insecure direct object reference"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen = set()
        for url, _ in _discover(ctx, _cap(ctx), set()):
            query = urlsplit(url).query
            numeric = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True) if v.isdigit() and len(v) <= 8]
            for param, value in numeric:
                if emitted >= 6 or param in ("page", "limit", "offset", "size", "per_page"):
                    continue
                original = ctx.http.get(url)
                if original is None or original.status_code != 200:
                    continue
                base_len = len(original.text or "")
                absent = ctx.http.get(_set_param(url, param, "2147483647"))
                if absent is None or absent.status_code == 200:
                    continue
                current = int(value)
                for neighbor in (current - 1, current + 1):
                    if neighbor < 0 or neighbor == current:
                        continue
                    probe = ctx.http.get(_set_param(url, param, str(neighbor)))
                    if probe is None or probe.status_code != 200:
                        continue
                    body = probe.text or ""
                    if abs(len(body) - base_len) > 24 or (body and body != (original.text or "")):
                        location = f"{url} [param: {param}]"
                        if location in seen:
                            break
                        seen.add(location)
                        emitted += 1
                        yield Finding(
                            check=self.name,
                            title=f"Possible IDOR on parameter '{param}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            category="A01:2021 Broken Access Control",
                            cwe="CWE-639",
                            description="Changing this numeric object id to an adjacent value returned a "
                            "different, existing record, while an out-of-range id was rejected. If the "
                            "neighbouring record belongs to another user and no ownership check is enforced, "
                            "this is an insecure direct object reference. Confirm ownership manually.",
                            remediation="Enforce a server-side authorization check that the authenticated "
                            "principal owns or may access the requested object. Prefer unguessable "
                            "identifiers over sequential ids.",
                            location=location,
                            evidence=f"id {value} (200, {base_len}b) vs id {neighbor} (200, {len(body)}b); id 2147483647 rejected",
                            references=["https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"],
                        )
                        break


@register
class UnauthenticatedAdmin(Check):
    name = "graybox.auth_bypass"
    title = "Protected route reachable without authentication"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        emitted = 0
        for route in _ADMIN_ROUTES:
            if emitted >= 6:
                break
            url = urljoin(base + "/", route.lstrip("/"))
            response = ctx.http.get(url, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if len(body) < 400 or _looks_like_login(body):
                continue
            emitted += 1
            yield Finding(
                check=self.name,
                title=f"Sensitive route served without auth: {route}",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="A01:2021 Broken Access Control",
                cwe="CWE-306",
                description=f"The route {route} returned HTTP 200 with substantial content and no login "
                "redirect for an unauthenticated request. Administrative and management surfaces should "
                "require authentication. Confirm the content is genuinely privileged.",
                remediation="Require authentication and authorization on all administrative, management, and "
                "internal routes. Deny by default and redirect unauthenticated users to login.",
                location=url,
                evidence=f"HTTP 200, {len(body)} bytes, no login markers",
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            )
