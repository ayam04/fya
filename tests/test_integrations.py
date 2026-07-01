from __future__ import annotations

import subprocess

from fya.checks import integrations
from fya.models import Profile, ScanContext, Severity, Target, TargetKind


def _web_ctx(tools, url="http://target.example/app?id=1", host="target.example", scheme="http", port=80):
    target = Target(
        raw=url,
        kind=TargetKind.WEB,
        scheme=scheme,
        host=host,
        port=port,
        url=url,
    )
    return ScanContext(target=target, profile=Profile.AGGRESSIVE, tools=tools)


def _tools(name):
    return {name: {"path": name, "version": "test"}}


def _fake_run(payload_out, payload_err="", code=0):
    def _runner(args, timeout=120.0, input_text=None):
        return code, payload_out, payload_err

    return _runner


def test_nuclei_jsonl_maps_to_findings(monkeypatch):
    jsonl = (
        '{"template-id":"exposed-panel","matched-at":"http://target.example/admin",'
        '"info":{"name":"Exposed Admin Panel","severity":"high"}}\n'
        '{"template-id":"tech-detect","matched-at":"http://target.example/",'
        '"info":{"name":"Tech Detect","severity":"low"}}\n'
    )
    monkeypatch.setattr(integrations, "run_tool", _fake_run(jsonl))
    ctx = _web_ctx(_tools("nuclei"))
    findings = list(integrations.NucleiScan().run(ctx))
    assert len(findings) == 2
    by_sev = {f.severity for f in findings}
    assert Severity.HIGH in by_sev
    assert Severity.LOW in by_sev
    high = next(f for f in findings if f.severity is Severity.HIGH)
    assert "Exposed Admin Panel" in high.title
    assert high.location == "http://target.example/admin"


def test_nuclei_malformed_lines_do_not_raise(monkeypatch):
    monkeypatch.setattr(integrations, "run_tool", _fake_run("not json\n\n{bad}\n"))
    ctx = _web_ctx(_tools("nuclei"))
    findings = list(integrations.NucleiScan().run(ctx))
    assert findings == []


def test_nuclei_empty_output_no_findings(monkeypatch):
    monkeypatch.setattr(integrations, "run_tool", _fake_run(""))
    ctx = _web_ctx(_tools("nuclei"))
    assert list(integrations.NucleiScan().run(ctx)) == []


def test_nmap_open_ports_and_risky_port(monkeypatch):
    xml = (
        '<?xml version="1.0"?>'
        "<nmaprun><host>"
        '<ports>'
        '<port protocol="tcp" portid="80">'
        '<state state="open"/><service name="http"/></port>'
        '<port protocol="tcp" portid="445">'
        '<state state="open"/><service name="microsoft-ds"/></port>'
        '<port protocol="tcp" portid="8080">'
        '<state state="closed"/><service name="http-proxy"/></port>'
        "</ports></host></nmaprun>"
    )
    monkeypatch.setattr(integrations, "run_tool", _fake_run(xml))
    ctx = _web_ctx(_tools("nmap"))
    findings = list(integrations.NmapScan().run(ctx))
    assert len(findings) == 2
    risky = next(f for f in findings if "445" in f.location)
    assert risky.severity is Severity.MEDIUM
    assert "SMB" in risky.title
    assert risky.cwe == "CWE-668"
    normal = next(f for f in findings if "80/" in f.location and "445" not in f.location)
    assert normal.severity is Severity.INFO


def test_nmap_malformed_xml_no_findings(monkeypatch):
    monkeypatch.setattr(integrations, "run_tool", _fake_run("<not-xml"))
    ctx = _web_ctx(_tools("nmap"))
    assert list(integrations.NmapScan().run(ctx)) == []


def test_nmap_empty_output_no_findings(monkeypatch):
    monkeypatch.setattr(integrations, "run_tool", _fake_run(""))
    ctx = _web_ctx(_tools("nmap"))
    assert list(integrations.NmapScan().run(ctx)) == []


def test_sqlmap_not_injectable_yields_no_finding(monkeypatch):
    out = (
        "[INFO] testing connection to the target URL\n"
        "[INFO] testing if GET parameter 'id' is dynamic\n"
        "[INFO] heuristic did not flag the parameter as injectable\n"
        "[WARNING] the target does not appear to be vulnerable\n"
    )
    combined = out.lower()
    assert "parameter" in combined and "vulnerable" in combined
    assert "is vulnerable" not in combined
    monkeypatch.setattr(integrations, "run_tool", _fake_run(out))
    ctx = _web_ctx(_tools("sqlmap"))
    findings = list(integrations.SqlmapScan().run(ctx))
    assert findings == []


def test_sqlmap_vulnerable_yields_high_finding(monkeypatch):
    out = (
        "[INFO] testing connection to the target URL\n"
        "[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing?\n"
    )
    monkeypatch.setattr(integrations, "run_tool", _fake_run(out))
    ctx = _web_ctx(_tools("sqlmap"))
    findings = list(integrations.SqlmapScan().run(ctx))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cwe == "CWE-89"


def test_sqlmap_empty_output_no_finding(monkeypatch):
    monkeypatch.setattr(integrations, "run_tool", _fake_run("", ""))
    ctx = _web_ctx(_tools("sqlmap"))
    assert list(integrations.SqlmapScan().run(ctx)) == []


def test_tools_run_returns_partial_stdout_on_timeout(monkeypatch):
    from fya import tools

    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="slow", timeout=1, output="partial stdout here")

    monkeypatch.setattr(tools.subprocess, "run", _raise)
    code, out, err = tools.run(["slow"], timeout=1)
    assert code is None
    assert out == "partial stdout here"
