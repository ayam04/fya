from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def test_apk_scan_secret_and_cleartext(fake_apk):
    target = detect_target(fake_apk)
    result = run_scan(target, profile=Profile.SAFE, detect_external=False)

    assert result.findings

    assert any(
        f.check == "apk.hardcoded_secrets" and "AWS" in f.title for f in result.findings
    )

    assert any(f.check == "apk.cleartext_urls" for f in result.findings)

    for f in result.findings:
        assert f.target
        assert f.severity
