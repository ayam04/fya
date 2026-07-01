from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def test_web_advanced_checks(live_server):
    target = detect_target(live_server)
    result = run_scan(target, profile=Profile.AGGRESSIVE, detect_external=False)

    check_names = {f.check for f in result.findings}

    assert "web.ssti" in check_names, (
        f"web.ssti not found; checks present: {sorted(check_names)}"
    )
    assert "web.csrf" in check_names, (
        f"web.csrf not found; checks present: {sorted(check_names)}"
    )
    assert "web.host_header" in check_names, (
        f"web.host_header not found; checks present: {sorted(check_names)}"
    )
    assert "web.crlf" in check_names, (
        f"web.crlf not found; checks present: {sorted(check_names)}"
    )
