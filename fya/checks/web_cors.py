from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover


@register
class CorsAdvanced(Check):
    name = "web.cors_advanced"
    title = "CORS origin-validation bypass"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        host = ctx.target.host or ""
        targets = [ctx.target.base_url()]
        for url, _ in _discover(ctx, cap, set()):
            targets.append(url)

        seen = set()
        checked = 0
        for url in targets:
            if not url or url in seen or checked >= 12:
                continue
            seen.add(url)
            checked += 1

            marker = ctx.http.marker()
            control_origin = f"https://{marker}.example"
            control = ctx.http.get(url, headers={"Origin": control_origin})
            if control is None:
                continue
            acao = control.headers.get("access-control-allow-origin", "")
            if acao == control_origin or acao == "*":
                continue  # blanket reflection / wildcard: owned by web.cors_misconfig

            probes = [
                (f"https://{marker}{host}", "trusts any origin ending with the host (suffix match bug)"),
                (f"https://{host}.{marker}.example", "trusts any origin starting with the host (prefix match bug)"),
                (f"https://{marker}.{host}", "trusts an arbitrary subdomain (dangerous if a subdomain can be taken over)"),
                ("null", "trusts the null origin (sandboxed iframes, redirects, local files)"),
            ]
            if ctx.target.scheme == "https":
                probes.append((f"http://{host}", "trusts the insecure http origin of the same host"))

            for origin, reason in probes:
                resp = ctx.http.get(url, headers={"Origin": origin})
                if resp is None:
                    continue
                got = resp.headers.get("access-control-allow-origin", "")
                creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
                if got != origin:
                    continue
                severity = Severity.HIGH if creds else Severity.MEDIUM
                yield Finding(
                    check=self.name,
                    title=f"CORS bypass: {reason.split(' (')[0]}",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-942",
                    description=f"The server reflected a crafted Origin ({origin}) into "
                    f"Access-Control-Allow-Origin, which means it {reason}. "
                    + ("Because credentials are also allowed, a malicious page can read authenticated "
                       "responses." if creds else "Combined with credentialed endpoints this can leak "
                       "authenticated data."),
                    remediation="Validate Origin against an exact-match server-side allowlist. Never build "
                    "the allowed origin from substring, prefix, or suffix matches, and never reflect null.",
                    location=url,
                    evidence=f"Origin: {origin} -> Access-Control-Allow-Origin: {got}; "
                    f"Access-Control-Allow-Credentials: {creds}",
                    references=["https://portswigger.net/web-security/cors"],
                )
                break
