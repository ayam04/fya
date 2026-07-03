from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

_SIGNATURES = (
    ("jquery", re.compile(r"jquery(?![a-z])", re.IGNORECASE)),
    ("angularjs", re.compile(r"angular(?:\.min)?\.js|angularjs|angular-", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap(?![a-z])", re.IGNORECASE)),
    ("vue", re.compile(r"vue(?:\.runtime)?(?:\.global|\.esm|\.common)?(?![a-z])", re.IGNORECASE)),
    ("react", re.compile(r"react(?:-dom)?(?![a-z])", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash(?![a-z])", re.IGNORECASE)),
    ("moment", re.compile(r"moment(?![a-z])", re.IGNORECASE)),
    ("handlebars", re.compile(r"handlebars(?![a-z])", re.IGNORECASE)),
)

_LABELS = {
    "jquery": "jQuery",
    "angularjs": "AngularJS",
    "bootstrap": "Bootstrap",
    "vue": "Vue.js",
    "react": "React",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "handlebars": "Handlebars",
}

_CATEGORY = "A06:2021 Vulnerable and Outdated Components"
_CWE = "CWE-1104"
_REFERENCES = ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]


def _extract_srcs(body: str) -> list:
    out = []
    for match in _SCRIPT_SRC.finditer(body):
        value = match.group(1).strip("\"'")
        if value:
            out.append(value)
    return out


def _detect_lib(url: str):
    name = urlsplit(url).path.rsplit("/", 1)[-1] or url
    for lib, pattern in _SIGNATURES:
        if pattern.search(url):
            return lib, name
    return None, name


def _parse_version(text: str):
    match = _VERSION.search(text)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    return major, minor, patch, match.group(0)


def _assess(lib: str, version):
    major, minor, patch, raw = version
    if lib == "jquery" and major < 3:
        return (
            Severity.MEDIUM,
            f"jQuery {raw} is outdated and carries known XSS vulnerabilities",
            "Upgrade to the latest jQuery 3.x release.",
        )
    if lib == "angularjs":
        return (
            Severity.MEDIUM,
            f"AngularJS {raw} is end-of-life and no longer receives security fixes",
            "Migrate off AngularJS 1.x to a supported framework.",
        )
    if lib == "bootstrap" and major < 4:
        return (
            Severity.LOW,
            f"Bootstrap {raw} is outdated and bundles a vulnerable jQuery-era codebase",
            "Upgrade to a supported Bootstrap major version (5.x).",
        )
    if lib == "moment":
        return (
            Severity.LOW,
            f"Moment.js {raw} is in maintenance mode and deprecated by its authors",
            "Replace Moment.js with a maintained alternative such as Luxon or date-fns.",
        )
    if lib == "vue" and major < 3:
        return (
            Severity.LOW,
            f"Vue.js {raw} is a legacy major version past active support",
            "Upgrade to Vue 3.x.",
        )
    if lib == "handlebars" and major < 4:
        return (
            Severity.LOW,
            f"Handlebars {raw} is outdated and affected by prototype pollution issues",
            "Upgrade to the latest Handlebars 4.x release.",
        )
    if lib == "lodash" and (major < 4 or (major == 4 and minor < 17) or (major == 4 and minor == 17 and patch < 21)):
        return (
            Severity.LOW,
            f"Lodash {raw} is outdated and affected by prototype pollution issues",
            "Upgrade to Lodash 4.17.21 or later.",
        )
    return None


@register
class FrontEndLibraries(Check):
    name = "web.frontend_libraries"
    title = "Outdated front-end libraries"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.get(base)
        if response is None:
            return
        body = response.text or ""
        seen_versions = set()
        info_emitted = set()
        for src in _extract_srcs(body):
            absolute = urljoin(base, src)
            lib, filename = _detect_lib(src)
            if not lib:
                continue
            label = _LABELS[lib]
            version = _parse_version(urlsplit(src).path) or _parse_version(urlsplit(src).query)
            if version is None:
                if lib in info_emitted:
                    continue
                info_emitted.add(lib)
                yield Finding(
                    check=self.name,
                    title=f"{label} detected without a resolvable version",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    category=_CATEGORY,
                    cwe="CWE-1035",
                    description=f"A {label} script reference was found but no version could be parsed "
                    "from the URL, so its patch level and known-vulnerability exposure cannot be confirmed.",
                    remediation=f"Confirm the deployed {label} version and keep it on a supported release.",
                    location=absolute,
                    evidence=f"script src: {src}",
                    references=_REFERENCES,
                )
                continue
            assessment = _assess(lib, version)
            if assessment is None:
                continue
            key = (lib, version[3])
            if key in seen_versions:
                continue
            seen_versions.add(key)
            severity, title, fix = assessment
            yield Finding(
                check=self.name,
                title=title,
                severity=severity,
                confidence=Confidence.MEDIUM,
                category=_CATEGORY,
                cwe=_CWE,
                description=f"The page loads {label} version {version[3]} from a client-side script. "
                "Outdated front-end components ship with publicly documented vulnerabilities that "
                "attackers can target directly in the browser.",
                remediation=fix,
                location=absolute,
                evidence=f"script src: {src}",
                references=_REFERENCES,
            )
