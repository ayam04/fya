from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._common import same_origin_scripts

_PLACEHOLDER = re.compile(r"(?i)(your|example|changeme|placeholder|xxxx|dummy|sample|redacted|<[a-z]|\{\{|\$\{|process\.env|import\.meta)")

_HIGH_SECRETS = [
    ("AWS access key id", re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}"), Severity.HIGH),
    ("Stripe secret key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{24,}"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"), Severity.HIGH),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z]{10,48}"), Severity.HIGH),
    ("SendGrid API key", re.compile(r"SG\.[\w-]{22}\.[\w-]{43}"), Severity.HIGH),
    ("Google OAuth client secret", re.compile(r"GOCSPX-[\w-]{28}"), Severity.HIGH),
    ("Mapbox secret token", re.compile(r"sk\.eyJ[\w-]{20,}\.[\w-]{20,}"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Twilio account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), Severity.MEDIUM),
]

_PUBLISHABLE = [
    ("Google API key (browser)", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe publishable key", re.compile(r"pk_live_[0-9A-Za-z]{24,}")),
    ("Mapbox public token", re.compile(r"pk\.eyJ[\w-]{20,}\.[\w-]{20,}")),
]

_GENERIC = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]"""
)

_FIREBASE = re.compile(r"[a-z0-9-]+\.(?:firebaseio\.com|firebaseapp\.com)", re.IGNORECASE)

_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


def _redact(token: str) -> str:
    return token[:6] + "..." if len(token) > 12 else token[:3] + "..."


@register
class ClientSideSecrets(Check):
    name = "web.js_secrets"
    title = "Secrets in client-side JavaScript"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        seen = set()
        emitted = 0
        firebase_flagged = False
        for url, body in same_origin_scripts(ctx):
            if emitted >= 25:
                break
            for label, pattern, severity in _HIGH_SECRETS:
                for match in pattern.finditer(body):
                    token = match.group(0)
                    key = (label, _redact(token))
                    if key in seen:
                        continue
                    seen.add(key)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title=f"{label} exposed in client-side script",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category="A07:2021 Identification and Authentication Failures",
                        cwe="CWE-798",
                        description=f"A value matching a {label} was served in JavaScript at {url}. "
                        "Anything shipped to the browser is readable by any visitor; a real credential "
                        "here should be treated as compromised.",
                        remediation="Move the secret server-side, rotate it, and never embed private "
                        "credentials in client-delivered code.",
                        location=url,
                        evidence=f"{label}: {_redact(token)}",
                        references=["https://cwe.mitre.org/data/definitions/798.html"],
                    )
                    break
            for match in _GENERIC.finditer(body):
                line_start = body.rfind("\n", 0, match.start()) + 1
                line = body[line_start:body.find("\n", match.start()) if body.find("\n", match.start()) > 0 else match.end() + 80]
                if _PLACEHOLDER.search(line) or "integrity=" in line.lower():
                    continue
                value = match.group(2)
                key = ("credential", _redact(value))
                if key in seen:
                    continue
                seen.add(key)
                emitted += 1
                yield Finding(
                    check=self.name,
                    title=f"Hardcoded {match.group(1).lower()} in client-side script",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    category="A07:2021 Identification and Authentication Failures",
                    cwe="CWE-798",
                    description=f"A credential-looking assignment was served in JavaScript at {url}. "
                    "Confirm whether this is a live secret; if so it is exposed to every visitor.",
                    remediation="Keep secrets server-side; expose only public, scoped tokens to the browser.",
                    location=url,
                    evidence=f"{match.group(1)}: {_redact(value)}",
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                )
                break
            for label, pattern in _PUBLISHABLE:
                match = pattern.search(body)
                if match and (label, "pub") not in seen:
                    seen.add((label, "pub"))
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title=f"{label} in client-side script",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        category="A05:2021 Security Misconfiguration",
                        cwe="CWE-200",
                        description=f"A {label} is present in client-side code at {url}. These keys are "
                        "designed to be public, but unrestricted keys can be abused, so confirm domain "
                        "or referrer restrictions are in place.",
                        remediation="Apply HTTP referrer, domain, or scope restrictions to the key.",
                        location=url,
                        evidence=f"{label}: {_redact(match.group(0))}",
                        references=["https://cwe.mitre.org/data/definitions/200.html"],
                    )
            if not firebase_flagged and "apiKey" in body:
                fb = _FIREBASE.search(body)
                if fb:
                    firebase_flagged = True
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title="Firebase configuration exposed in client-side script",
                        severity=Severity.INFO,
                        confidence=Confidence.LOW,
                        category="A05:2021 Security Misconfiguration",
                        cwe="CWE-200",
                        description=f"A Firebase config (apiKey plus {fb.group(0)}) is present in client code at "
                        f"{url}. This is expected for Firebase, but security depends entirely on Firebase "
                        "Security Rules, so confirm the database and storage rules are not world-readable.",
                        remediation="Lock down Firebase Security Rules; the client config being public is by design.",
                        location=url,
                        evidence=f"apiKey + {fb.group(0)}",
                        references=["https://firebase.google.com/docs/rules"],
                    )


@register
class SourceMapExposure(Check):
    name = "web.source_map_exposure"
    title = "Exposed JavaScript source maps"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        seen = set()
        emitted = 0
        for url, body in same_origin_scripts(ctx):
            if emitted >= 10:
                break
            if not urlsplit(url).path.endswith(".js"):
                continue
            candidates = []
            comment = _MAP_COMMENT.search(body)
            if comment and not comment.group(1).startswith("data:"):
                candidates.append(urljoin(url, comment.group(1)))
            candidates.append(url + ".map")
            for map_url in candidates:
                if map_url in seen:
                    continue
                seen.add(map_url)
                resp = ctx.http.get(map_url)
                if resp is None or resp.status_code != 200:
                    continue
                ctype = resp.headers.get("content-type", "").lower()
                text = resp.text or ""
                if "text/html" in ctype or text[:20].lstrip().startswith("<"):
                    continue
                try:
                    data = json.loads(text)
                except (ValueError, TypeError):
                    continue
                if not isinstance(data, dict) or "version" not in data or "sources" not in data:
                    continue
                sources = data.get("sources") or []
                has_content = bool(data.get("sourcesContent"))
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="JavaScript source map exposed",
                    severity=Severity.MEDIUM if has_content else Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-540",
                    description=f"A Source Map v3 is publicly served at {map_url}, referencing "
                    f"{len(sources) if isinstance(sources, list) else 0} original source file(s)"
                    + (" including inlined original source" if has_content else "")
                    + ". Source maps reveal un-minified code, comments, and internal structure.",
                    remediation="Do not deploy .map files to production, or restrict access to them.",
                    location=map_url,
                    evidence=f"version={data.get('version')}, sources={len(sources) if isinstance(sources, list) else 0}",
                    references=["https://cwe.mitre.org/data/definitions/540.html"],
                )
                break
