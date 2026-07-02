from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile, TargetKind


def _titles(result):
    return " || ".join(f"{f.check} :: {f.title}" for f in result.findings)


def test_blackbox_detects_unhandled_input(live_server):
    target = detect_target(live_server)
    result = run_scan(target, profile=Profile.AGGRESSIVE, detect_external=False, categories={"blackbox"})
    assert any(f.check == "blackbox.input_fuzzing" for f in result.findings), _titles(result)


def test_graybox_finds_idor_and_admin(live_server):
    target = detect_target(live_server)
    result = run_scan(target, profile=Profile.SAFE, detect_external=False, categories={"graybox"})
    checks = {f.check for f in result.findings}
    assert "graybox.idor" in checks, _titles(result)
    assert "graybox.auth_bypass" in checks, _titles(result)


def test_source_directory_is_detected(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    target = detect_target(str(tmp_path))
    assert target.kind is TargetKind.SOURCE
    assert target.source_path


def test_whitebox_finds_secrets_and_risky_code(tmp_path):
    (tmp_path / "settings.py").write_text(
        "AWS = 'AKIAIOSFODNN7EXAMPLE'\n"
        "import subprocess\n"
        "subprocess.run(cmd, shell=True)\n"
        "requests.get(url, verify=False)\n"
    )
    (tmp_path / "config.env").write_text("API_KEY=\"not-a-real-secret\"\n")
    target = detect_target(str(tmp_path))
    result = run_scan(target, profile=Profile.SAFE, detect_external=False)

    checks = {f.check for f in result.findings}
    assert "whitebox.hardcoded_secrets" in checks, _titles(result)
    assert "whitebox.dangerous_patterns" in checks, _titles(result)
    assert any("AWS" in f.title for f in result.findings)


def test_whitebox_ignores_vendor_dirs(tmp_path):
    vendor = tmp_path / "node_modules" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "leak.js").write_text("const k = 'AKIAIOSFODNN7EXAMPLE'\n")
    target = detect_target(str(tmp_path))
    result = run_scan(target, profile=Profile.SAFE, detect_external=False)
    assert not any(f.check == "whitebox.hardcoded_secrets" for f in result.findings)
