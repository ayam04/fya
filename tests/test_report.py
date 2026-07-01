from __future__ import annotations

import json

from fya.models import (
    Confidence,
    Finding,
    Profile,
    ScanResult,
    Severity,
    Target,
    TargetKind,
)
from fya.report import to_html, to_json, to_sarif


def _make_result() -> ScanResult:
    target = Target(
        raw="http://localhost:8080",
        kind=TargetKind.WEB,
        scheme="http",
        host="localhost",
        port=8080,
        url="http://localhost:8080",
    )
    result = ScanResult(target=target, profile=Profile.SAFE)
    result.checks_run = ["web.security_headers"]
    result.findings.append(
        Finding(
            check="web.security_headers",
            title="Missing Content-Security-Policy header",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="A05:2021 Security Misconfiguration",
            description="No CSP header was returned.",
            target=target.label(),
            location=target.label(),
        )
    )
    return result


def test_to_json_has_findings_key():
    result = _make_result()
    parsed = json.loads(to_json(result))
    assert "findings" in parsed
    assert isinstance(parsed["findings"], list)


def test_to_sarif_driver_name():
    result = _make_result()
    parsed = json.loads(to_sarif(result))
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "fya"


def test_to_html_contains_target_and_html():
    result = _make_result()
    html_out = to_html(result)
    assert "<html" in html_out
    assert result.target.label() in html_out
