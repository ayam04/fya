from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def test_web_scan_findings(live_server):
    target = detect_target(live_server)
    result = run_scan(target, profile=Profile.SAFE, detect_external=False)

    assert result.findings

    titles = " || ".join(f"{f.title} :: {f.category}" for f in result.findings)

    assert "Content-Security-Policy" in titles

    assert any("cookie" in f.title.lower() for f in result.findings)

    active_markers = ("open redirect", "sql injection", "reflected xss", "cors")
    assert any(
        marker in f.title.lower() for f in result.findings for marker in active_markers
    )

    for f in result.findings:
        assert f.target
        assert f.severity
