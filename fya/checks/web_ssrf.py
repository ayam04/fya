from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._common import is_url_param
from .web_active import (
    _AGGRESSIVE_CRAWL_CAP,
    _PASSWD_SIGNATURE,
    _SAFE_CRAWL_CAP,
    _WIN_INI_SIGNATURE,
    _discover,
    _set_param,
)

_METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]
_FILE_PAYLOADS = ["file:///etc/passwd", "file:///c:/windows/win.ini"]

_AWS_LIST_TOKENS = ("ami-id", "instance-id", "instance-type")
_AWS_IDENT_TOKENS = ("accountid", "instanceid", "region")


def _aws_signature(body_lower: str) -> bool:
    return all(t in body_lower for t in _AWS_LIST_TOKENS) or all(t in body_lower for t in _AWS_IDENT_TOKENS)


@register
class SSRF(Check):
    name = "web.ssrf"
    title = "Server-Side Request Forgery"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        benign = ctx.target.base_url()
        emitted = 0
        seen = set()
        for url, params in _discover(ctx, cap, set()):
            values = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            for param in params:
                if not param or emitted >= 5:
                    continue
                if not is_url_param(param, values.get(param, "")):
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                base = ctx.http.get(_set_param(url, param, benign), allow_redirects=False)
                base_body = (base.text or "").lower() if base is not None else ""

                hit = self._probe(ctx, url, param, base_body)
                if hit is None:
                    continue
                seen.add(location)
                emitted += 1
                kind, payload, evidence = hit
                yield Finding(
                    check=self.name,
                    title=f"SSRF via parameter '{param}' ({kind})",
                    severity=Severity.CRITICAL if kind == "cloud metadata" else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="A10:2021 Server-Side Request Forgery (SSRF)",
                    cwe="CWE-918",
                    description=f"The '{param}' parameter caused the server to fetch an attacker-supplied "
                    f"URL and return {kind} content that a benign request did not. This confirms the server "
                    "makes requests to arbitrary URLs, which can reach cloud metadata, internal services, and "
                    "local files.",
                    remediation="Validate outbound URLs against a strict allowlist, block link-local and "
                    "private ranges and non-http(s) schemes, and disable unused URL fetching.",
                    location=location,
                    evidence=f"payload: {payload}; {evidence}",
                    references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                )

    def _probe(self, ctx, url, param, base_body):
        for payload in _METADATA_PAYLOADS:
            resp = ctx.http.get(_set_param(url, param, payload), allow_redirects=False)
            if resp is None:
                continue
            low = (resp.text or "").lower()
            if _aws_signature(low) and not _aws_signature(base_body):
                return "cloud metadata", payload, "AWS instance metadata returned in response"
        for payload in _FILE_PAYLOADS:
            resp = ctx.http.get(_set_param(url, param, payload), allow_redirects=False)
            if resp is None:
                continue
            body = resp.text or ""
            if _PASSWD_SIGNATURE.search(body) and not _PASSWD_SIGNATURE.search(base_body):
                return "local file", payload, "contents of /etc/passwd returned"
            if _WIN_INI_SIGNATURE.search(body) and not _WIN_INI_SIGNATURE.search(base_body):
                return "local file", payload, "contents of win.ini returned"
        return None
