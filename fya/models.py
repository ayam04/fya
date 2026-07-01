from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TargetKind(str, Enum):
    WEB = "web"
    APK = "apk"


class Profile(str, Enum):
    PASSIVE = "passive"
    SAFE = "safe"
    AGGRESSIVE = "aggressive"


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

_PROFILE_ORDER = [Profile.PASSIVE, Profile.SAFE, Profile.AGGRESSIVE]


def severity_rank(sev: Severity) -> int:
    return _SEVERITY_ORDER.index(sev)


def profile_rank(profile: Profile) -> int:
    return _PROFILE_ORDER.index(profile)


def now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Target:
    raw: str
    kind: TargetKind
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    apk_path: Optional[str] = None
    fingerprint: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def label(self) -> str:
        if self.kind is TargetKind.APK:
            return self.apk_path or self.raw
        return self.url or self.raw

    def base_url(self) -> Optional[str]:
        if self.kind is not TargetKind.WEB or not self.host:
            return None
        netloc = self.host
        default = (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        )
        if self.port and not default:
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"


@dataclass
class Finding:
    check: str
    title: str
    severity: Severity
    description: str
    target: str = ""
    confidence: Confidence = Confidence.MEDIUM
    category: str = ""
    cwe: Optional[str] = None
    remediation: str = ""
    evidence: str = ""
    location: str = ""
    references: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def key(self) -> str:
        raw = "|".join([self.check, self.title, self.target, self.location])
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "location": self.location,
            "target": self.target,
            "references": list(self.references),
            "extra": dict(self.extra),
            "id": self.key(),
        }


@dataclass
class ScanContext:
    target: Target
    profile: Profile
    http: Any = None
    options: dict = field(default_factory=dict)
    tools: dict = field(default_factory=dict)
    log: Any = None

    def emit_log(self, message: str) -> None:
        if callable(self.log):
            self.log(message)


@dataclass
class ScanResult:
    target: Target
    profile: Profile
    findings: list = field(default_factory=list)
    started_at: datetime = field(default_factory=now)
    finished_at: Optional[datetime] = None
    checks_run: list = field(default_factory=list)
    tool_versions: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def counts(self) -> dict:
        out = {s.value: 0 for s in Severity}
        for finding in self.findings:
            out[finding.severity.value] += 1
        return out

    def sorted_findings(self) -> list:
        return sorted(
            self.findings,
            key=lambda f: (severity_rank(f.severity), f.title),
            reverse=True,
        )

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=severity_rank)

    def duration_seconds(self) -> float:
        end = self.finished_at or now()
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "target": {
                "label": self.target.label(),
                "kind": self.target.kind.value,
                "url": self.target.url,
                "host": self.target.host,
                "port": self.target.port,
                "apk_path": self.target.apk_path,
                "fingerprint": self.target.fingerprint,
            },
            "profile": self.profile.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at or now()).isoformat(),
            "duration_seconds": round(self.duration_seconds(), 2),
            "checks_run": list(self.checks_run),
            "tool_versions": dict(self.tool_versions),
            "counts": self.counts(),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
