from __future__ import annotations

import base64
import json
import re

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)")
_SENSITIVE_RE = re.compile(r"password|passwd|secret|ssn|credit|card_number|cardnumber|cvv", re.IGNORECASE)
_SYMMETRIC = {"HS256", "HS384", "HS512"}


def _b64url_json(segment: str):
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None


def _redact(token: str) -> str:
    parts = token.split(".")
    head = parts[0][:8]
    return f"{head}...<redacted>.<redacted> (len={len(token)})"


def _collect_sources(response):
    sources = []
    for name, value in response.headers.items():
        if value:
            sources.append((f"header:{name}", value))
    for cookie in response.cookies:
        if cookie.value:
            sources.append((f"cookie:{cookie.name}", cookie.value))
    body = response.text or ""
    if body:
        sources.append(("body", body))
    return sources


class _JWTBase(Check):
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def _tokens(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.get(base)
        if response is None:
            return
        seen = set()
        for origin, value in _collect_sources(response):
            for match in _JWT_RE.findall(value):
                if match in seen:
                    continue
                seen.add(match)
                parts = match.split(".")
                if len(parts) != 3:
                    continue
                header = _b64url_json(parts[0])
                payload = _b64url_json(parts[1])
                if not isinstance(header, dict) or not isinstance(payload, dict):
                    continue
                yield base, origin, match, header, payload


@register
class JWTWeakAlgorithm(_JWTBase):
    name = "web.jwt_weak_algorithm"
    title = "JWT algorithm weakness"

    def run(self, ctx: ScanContext):
        for base, origin, token, header, _payload in self._tokens(ctx):
            alg = str(header.get("alg", "")).strip()
            if alg.lower() == "none":
                yield Finding(
                    check=self.name,
                    title="JWT signed with 'none' algorithm",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="A02:2021 Cryptographic Failures",
                    cwe="CWE-347",
                    description="A JSON Web Token exposed by the application declares alg 'none', meaning it "
                    "carries no signature. An attacker can forge arbitrary tokens and claims that the server will accept.",
                    remediation="Reject the 'none' algorithm server-side and pin verification to an explicit allowed "
                    "signing algorithm.",
                    location=base,
                    evidence=f"{origin}: {_redact(token)} header.alg=none",
                    references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"],
                )
            elif alg.upper() in _SYMMETRIC:
                yield Finding(
                    check=self.name,
                    title=f"JWT uses symmetric algorithm {alg.upper()}",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="A02:2021 Cryptographic Failures",
                    cwe="CWE-347",
                    description=f"An exposed JSON Web Token uses the symmetric algorithm {alg.upper()}. Symmetric "
                    "signing relies on a shared secret that both signs and verifies, so a leaked or weak secret lets an "
                    "attacker forge valid tokens.",
                    remediation="Prefer asymmetric signing (RS256/ES256) or ensure the HMAC secret is long and high entropy.",
                    location=base,
                    evidence=f"{origin}: {_redact(token)} header.alg={alg.upper()}",
                    references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"],
                )


@register
class JWTMissingExpiry(_JWTBase):
    name = "web.jwt_missing_expiry"
    title = "JWT missing expiry claim"

    def run(self, ctx: ScanContext):
        for base, origin, token, _header, payload in self._tokens(ctx):
            if "exp" not in payload:
                yield Finding(
                    check=self.name,
                    title="JWT has no expiry (exp) claim",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="A07:2021 Identification and Authentication Failures",
                    cwe="CWE-613",
                    description="An exposed JSON Web Token has no exp claim, so it never expires. A stolen token stays "
                    "valid indefinitely and cannot be aged out.",
                    remediation="Issue short-lived tokens with an exp claim and implement refresh or revocation.",
                    location=base,
                    evidence=f"{origin}: {_redact(token)} payload has no 'exp'",
                    references=["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/"],
                )


@register
class JWTSensitiveClaims(_JWTBase):
    name = "web.jwt_sensitive_claims"
    title = "JWT sensitive claims"

    def run(self, ctx: ScanContext):
        for base, origin, token, _header, payload in self._tokens(ctx):
            hits = sorted({k for k in payload if _SENSITIVE_RE.search(str(k))})
            if hits:
                yield Finding(
                    check=self.name,
                    title="Sensitive data embedded in JWT payload",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="A02:2021 Cryptographic Failures",
                    cwe="CWE-522",
                    description="An exposed JSON Web Token carries sensitive-looking claims in its payload. JWT payloads "
                    "are only base64url encoded, not encrypted, so anyone who observes the token can read these values.",
                    remediation="Never store credentials or sensitive personal data in JWT claims; keep them server-side "
                    "and reference by opaque identifier.",
                    location=base,
                    evidence=f"{origin}: {_redact(token)} suspicious claim keys={hits}",
                    references=["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/"],
                )
