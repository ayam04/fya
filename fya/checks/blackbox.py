from __future__ import annotations

from html import escape

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover, _set_param

_FUZZ_PAYLOADS = [
    "A" * 10000,
    "%00",
    "%s%s%s%s%s%s%n",
    "-1",
    "9" * 40,
    str(2 ** 63),
    "1e309",
    "[]",
    "{}",
    "\U0001f4a5‮gnp​",
    "'\"`<>{}$;|)(",
]

_STACK_SIGNATURES = [
    "traceback (most recent call last)",
    "werkzeug.exceptions",
    "django.core.exceptions",
    "at org.springframework",
    "at java.base/",
    "java.lang.nullpointerexception",
    "system.web.httpexception",
    "at system.web",
    "node:internal/",
    "at object.<anonymous>",
    "actioncontroller::",
    "goroutine ",
    "runtime error:",
    "panic:",
    "uncaught exception",
    "call to a member function",
    "notice: undefined",
    "fatal error:",
    "referenceerror:",
    "unhandledpromiserejection",
]


def _cap(ctx: ScanContext) -> int:
    return _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP


def _stack_sig(body: str, baseline: str) -> str:
    lowered = body.lower()
    base = baseline.lower()
    for sig in _STACK_SIGNATURES:
        if sig in lowered and sig not in base:
            return sig
    return ""


@register
class InputFuzzing(Check):
    name = "blackbox.input_fuzzing"
    title = "Unhandled input breaks the endpoint"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        payloads = _FUZZ_PAYLOADS if ctx.profile is Profile.AGGRESSIVE else _FUZZ_PAYLOADS[:6]
        emitted = 0
        seen = set()
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 15:
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                base = ctx.http.get(url)
                if base is None:
                    continue
                base_status = base.status_code
                base_body = base.text or ""
                if base_status >= 500:
                    continue
                for payload in payloads:
                    response = ctx.http.get(_set_param(url, param, payload))
                    if response is None:
                        continue
                    ctype = response.headers.get("content-type", "").lower()
                    body = response.text or ""
                    if response.status_code >= 500 and response.status_code != base_status:
                        seen.add(location)
                        emitted += 1
                        yield Finding(
                            check=self.name,
                            title=f"Malformed input to '{param}' triggers a {response.status_code}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category="A05:2021 Security Misconfiguration",
                            cwe="CWE-20",
                            description="A crafted value in this parameter produced a server error while a "
                            "benign value did not, indicating the input is not validated before use. "
                            "Unhandled input often points to deeper injection, type-confusion, or "
                            "resource-exhaustion bugs.",
                            remediation="Validate and normalize input at the trust boundary. Reject values "
                            "outside the expected type, length, and range, and return a handled 4xx rather "
                            "than a 500.",
                            location=location,
                            evidence=f"benign {base_status} -> payload {escape(repr(payload)[:60])} = {response.status_code}",
                            references=["https://owasp.org/www-community/Fuzzing"],
                        )
                        break
                    if "text/html" in ctype or "application/json" in ctype or not ctype:
                        sig = _stack_sig(body, base_body)
                        if sig:
                            seen.add(location)
                            emitted += 1
                            yield Finding(
                                check=self.name,
                                title=f"Stack trace disclosed via '{param}'",
                                severity=Severity.LOW,
                                confidence=Confidence.MEDIUM,
                                category="A05:2021 Security Misconfiguration",
                                cwe="CWE-209",
                                description="A crafted value in this parameter caused the response to leak a "
                                "language or framework stack trace. Verbose errors reveal internal paths, "
                                "libraries, and query structure that aid an attacker.",
                                remediation="Return generic error pages to clients and log details server-side "
                                "only. Disable debug mode in production.",
                                location=location,
                                evidence=f"error signature: {sig}",
                                references=["https://owasp.org/www-community/Improper_Error_Handling"],
                            )
                            break
