from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def _scan_workflow(tmp_path, name, content):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(content)
    result = run_scan(detect_target(str(tmp_path)), profile=Profile.PASSIVE, detect_external=False)
    return [f for f in result.findings if f.check == "whitebox.cicd_misconfig"]


def test_pwn_request_fires(tmp_path):
    content = (
        "on:\n  pull_request_target:\n"
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: npm install && npm test\n"
    )
    findings = _scan_workflow(tmp_path, "ci.yml", content)
    assert any("pwn-request" in f.title.lower() for f in findings)


def test_script_injection_fires(tmp_path):
    content = (
        "on: issues\njobs:\n  a:\n    steps:\n"
        '      - run: echo "Issue: ${{ github.event.issue.title }}"\n'
    )
    findings = _scan_workflow(tmp_path, "triage.yml", content)
    assert any("script injection" in f.title.lower() for f in findings)


def test_clean_workflow_is_silent(tmp_path):
    content = (
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        '      - run: echo "building ${{ github.sha }}"\n'
    )
    assert not _scan_workflow(tmp_path, "ok.yml", content)
