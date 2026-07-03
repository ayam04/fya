from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_advanced import _ABS_LINK_RE, _local_discover

_CACHE_HINTS = ("age", "x-cache", "cf-cache-status", "x-served-by", "x-varnish")


def _bust(url, token):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True) + [("fya_cb", token)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _cacheable(response) -> bool:
    cc = response.headers.get("cache-control", "").lower()
    if "public" in cc or "s-maxage" in cc or ("max-age" in cc and "no-store" not in cc and "private" not in cc):
        return True
    return any(h in response.headers for h in _CACHE_HINTS)


@register
class CachePoisonHeaders(Check):
    name = "web.cache_poison_headers"
    title = "Unkeyed forwarded headers"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = 12 if ctx.profile is Profile.AGGRESSIVE else 6
        seeds = [ctx.target.base_url()]
        for url, _ in _local_discover(ctx, cap):
            seeds.append(url)

        seen = set()
        emitted = 0
        for seed in seeds:
            if not seed or seed in seen or emitted >= 4:
                continue
            seen.add(seed)
            busted = _bust(seed, ctx.http.marker())
            base = ctx.http.get(busted, allow_redirects=False)
            if base is None:
                continue
            base_body = base.text or ""
            base_loc = base.headers.get("location", "")
            base_links = set(_ABS_LINK_RE.findall(base_body))

            token = ctx.http.marker()
            evil = f"{token}.evil.example"
            probe = ctx.http.get(busted, allow_redirects=False, headers={"X-Forwarded-Host": evil})
            if probe is None:
                continue
            pbody = probe.text or ""
            ploc = probe.headers.get("location", "")
            new_links = [lnk for lnk in _ABS_LINK_RE.findall(pbody) if lnk not in base_links]
            where = ""
            if token in ploc and token not in base_loc:
                where = f"redirect Location: {ploc}"
            elif any(token in lnk for lnk in new_links):
                where = f"absolute link: {next(lnk for lnk in new_links if token in lnk)}"
            elif token in pbody and token not in base_body:
                where = "response body"
            if not where:
                continue
            emitted += 1
            cacheable = _cacheable(probe) or _cacheable(base)
            yield Finding(
                check=self.name,
                title="Unkeyed X-Forwarded-Host reflected into response",
                severity=Severity.HIGH if cacheable else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-644",
                description="A spoofed X-Forwarded-Host header was reflected into the "
                f"{where.split(':')[0]} while absent from a header-free baseline of the same URL. "
                + ("Cache indicators are present, so this is exploitable as web cache poisoning "
                   "affecting other users." if cacheable else "This enables host-header attacks such as "
                   "poisoned password-reset links.")
                + " Probes used a unique cache-buster query so no shared cache entry was affected.",
                remediation="Ignore client-supplied X-Forwarded-* headers unless they come from a trusted "
                "proxy, and never build absolute URLs or cache keys from them.",
                location=seed,
                evidence=f"X-Forwarded-Host: {evil} reflected in {where}",
                references=["https://portswigger.net/web-security/web-cache-poisoning"],
            )


@register
class UrlOverrideHeaders(Check):
    name = "web.url_override_headers"
    title = "URL-override header honoured"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        baseline = ctx.http.get(base, allow_redirects=False)
        if baseline is None or not (200 <= baseline.status_code < 300):
            return
        base_len = len(baseline.text or "")
        tol = max(64, int(0.3 * base_len))

        bogus = "/fya-" + ctx.http.marker() + "-nope"
        direct = ctx.http.get(base.rstrip("/") + bogus, allow_redirects=False)
        if direct is None or direct.status_code == 200:
            return  # cannot confirm the path is absent (catch-all)

        for header in ("X-Original-URL", "X-Rewrite-URL"):
            probe = ctx.http.get(base, allow_redirects=False, headers={header: bogus})
            if probe is None:
                continue
            changed = probe.status_code != baseline.status_code or abs(len(probe.text or "") - base_len) > tol
            if not changed:
                continue
            echo = ctx.http.get(base, allow_redirects=False, headers={header: "/"})
            if echo is None:
                continue
            reproduced = echo.status_code == baseline.status_code and abs(len(echo.text or "") - base_len) <= tol
            if not reproduced:
                continue
            yield Finding(
                check=self.name,
                title=f"Application routes on the {header} header",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="A01:2021 Broken Access Control",
                cwe="CWE-284",
                description=f"The application changed its response based on the {header} header while the "
                "request line was unchanged, and the header path is not directly reachable. Front-end "
                "proxies enforce access control on the request line, so an attacker can pass an allowed "
                "path on the line and a restricted path in this header to bypass those controls.",
                remediation=f"Strip {header} (and X-Original-URL/X-Rewrite-URL) at the edge, or ignore it in "
                "the application so routing and access control use only the real request path.",
                location=base,
                evidence=f"{header}: {bogus} changed the response ({baseline.status_code}/{base_len}b -> "
                f"{probe.status_code}/{len(probe.text or '')}b); direct {bogus} returned {direct.status_code}",
                references=["https://cwe.mitre.org/data/definitions/284.html"],
            )
