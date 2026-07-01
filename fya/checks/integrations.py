from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ..tools import run as run_tool

_NUCLEI_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_RISKY_PORTS = {
    21: (Severity.MEDIUM, "FTP"),
    23: (Severity.MEDIUM, "Telnet"),
    445: (Severity.MEDIUM, "SMB"),
    3389: (Severity.LOW, "RDP"),
}


def _tool_path(ctx, name):
    entry = ctx.tools.get(name)
    if not entry:
        return None
    return entry.get("path") or name


def _snippet(text, limit=400):
    if not text:
        return ""
    return text.strip()[:limit]


@register
class NucleiScan(Check):
    name = "integrations.nuclei"
    title = "Nuclei template scan"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        path = _tool_path(ctx, "nuclei")
        if not path:
            return
        base = ctx.target.base_url()
        if not base:
            return
        args = [
            path,
            "-u",
            base,
            "-jsonl",
            "-silent",
            "-severity",
            "low,medium,high,critical",
        ]
        try:
            code, out, err = run_tool(args, timeout=300)
        except Exception:
            return
        if not out:
            return
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                continue
            try:
                info = record.get("info", {}) if isinstance(record, dict) else {}
                template_id = record.get("template-id") or record.get("templateID") or "nuclei"
                matched = record.get("matched-at") or record.get("matched") or base
                raw_sev = str(info.get("severity", "info")).lower()
                severity = _NUCLEI_SEVERITY.get(raw_sev, Severity.INFO)
                display = info.get("name") or template_id
                references = info.get("reference") or []
                if isinstance(references, str):
                    references = [references]
            except (AttributeError, TypeError):
                continue
            yield Finding(
                check=self.name,
                title=f"Nuclei: {display}",
                severity=severity,
                confidence=Confidence.HIGH,
                category="A06:2021 Vulnerable and Outdated Components",
                cwe=None,
                description=(
                    f"The nuclei template '{template_id}' matched against {matched}. "
                    f"Reported severity is {raw_sev}."
                ),
                remediation="Review the matched template and remediate the underlying issue it flags.",
                location=str(matched),
                evidence=f"template-id: {template_id}",
                references=list(references),
                extra={"tool": "nuclei", "raw": _snippet(line)},
            )


@register
class NiktoScan(Check):
    name = "integrations.nikto"
    title = "Nikto web server scan"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        path = _tool_path(ctx, "nikto")
        if not path:
            return
        base = ctx.target.base_url()
        if not base:
            return
        args = [path, "-h", base, "-Format", "json", "-output", "-", "-nointeractive"]
        try:
            code, out, err = run_tool(args, timeout=300)
        except Exception:
            return
        if not out:
            return
        try:
            data = json.loads(out)
        except (ValueError, TypeError):
            start = out.find("{")
            if start < 0:
                return
            try:
                data = json.loads(out[start:])
            except (ValueError, TypeError):
                return
        vulns = []
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities") or []
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("vulnerabilities"):
                    vulns.extend(item["vulnerabilities"])
        if not isinstance(vulns, list):
            return
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            message = vuln.get("msg") or vuln.get("message") or ""
            if not message:
                continue
            url = vuln.get("url") or base
            osvdb = vuln.get("OSVDB") or vuln.get("id") or ""
            severity = Severity.MEDIUM if osvdb and str(osvdb) not in ("0", "") else Severity.LOW
            yield Finding(
                check=self.name,
                title=f"Nikto finding: {message[:80]}",
                severity=severity,
                confidence=Confidence.MEDIUM,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-16",
                description=f"Nikto reported: {message}",
                remediation="Review the nikto finding and harden the affected web server configuration.",
                location=str(url),
                evidence=_snippet(message, 200),
                references=["https://github.com/sullo/nikto"],
                extra={"tool": "nikto", "raw": _snippet(json.dumps(vuln))},
            )


@register
class NmapScan(Check):
    name = "integrations.nmap"
    title = "Nmap port scan"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        path = _tool_path(ctx, "nmap")
        if not path:
            return
        host = ctx.target.host
        if not host:
            return
        args = [path, "-Pn", "-T4", "--top-ports", "100", host, "-oX", "-"]
        try:
            code, out, err = run_tool(args, timeout=300)
        except Exception:
            return
        if not out:
            return
        try:
            root = ET.fromstring(out)
        except ET.ParseError:
            return
        try:
            for port in root.iter("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid")
                try:
                    number = int(portid)
                except (TypeError, ValueError):
                    number = None
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else ""
                protocol = port.get("protocol", "tcp")
                location = f"{host}:{portid}/{protocol}"
                if number in _RISKY_PORTS:
                    sev, label = _RISKY_PORTS[number]
                    yield Finding(
                        check=self.name,
                        title=f"Risky service exposed: {label} on port {portid}",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        category="A05:2021 Security Misconfiguration",
                        cwe="CWE-668",
                        description=(
                            f"Port {portid}/{protocol} ({label}) is open on {host}. "
                            "This service is commonly high-risk if exposed to untrusted networks."
                        ),
                        remediation=f"Restrict access to {label} or disable it if it is not required.",
                        location=location,
                        evidence=f"open port {portid} service={service}",
                        references=["https://nmap.org/book/man.html"],
                        extra={"tool": "nmap", "raw": _snippet(f"{portid}/{protocol} {service}")},
                    )
                else:
                    yield Finding(
                        check=self.name,
                        title=f"Open port {portid}/{protocol}",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        category="A05:2021 Security Misconfiguration",
                        cwe=None,
                        description=(
                            f"Port {portid}/{protocol} is open on {host} "
                            f"(service {service or 'unknown'})."
                        ),
                        remediation="Confirm this port is intended to be reachable and firewall it otherwise.",
                        location=location,
                        evidence=f"open port {portid} service={service}",
                        references=["https://nmap.org/book/man.html"],
                        extra={"tool": "nmap", "raw": _snippet(f"{portid}/{protocol} {service}")},
                    )
        except (AttributeError, TypeError):
            return


@register
class SqlmapScan(Check):
    name = "integrations.sqlmap"
    title = "sqlmap injection probe"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def applies(self, ctx: ScanContext) -> bool:
        if not super().applies(ctx):
            return False
        url = ctx.target.url or ""
        return "?" in url and bool(url.split("?", 1)[1])

    def run(self, ctx: ScanContext):
        path = _tool_path(ctx, "sqlmap")
        if not path:
            return
        url = ctx.target.url
        if not url or "?" not in url:
            return
        args = [
            path,
            "-u",
            url,
            "--batch",
            "--level",
            "1",
            "--risk",
            "1",
            "--flush-session",
            "--disable-coloring",
        ]
        try:
            code, out, err = run_tool(args, timeout=180)
        except Exception:
            return
        combined = (out or "") + "\n" + (err or "")
        if not combined.strip():
            return
        lowered = combined.lower()
        if "is vulnerable" not in lowered:
            return
        evidence_line = ""
        for line in combined.splitlines():
            if "is vulnerable" in line.lower():
                evidence_line = line.strip()
                break
        yield Finding(
            check=self.name,
            title="SQL injection confirmed by sqlmap",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="A03:2021 Injection",
            cwe="CWE-89",
            description=(
                "sqlmap reported that a parameter on the target URL is vulnerable to SQL injection. "
                "This allows an attacker to manipulate database queries."
            ),
            remediation="Use parameterized queries or prepared statements for all database access.",
            location=url,
            evidence=_snippet(evidence_line or "sqlmap reported the target as vulnerable", 300),
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            extra={"tool": "sqlmap", "raw": _snippet(evidence_line)},
        )


@register
class TlsScan(Check):
    name = "integrations.tls"
    title = "TLS configuration scan"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def applies(self, ctx: ScanContext) -> bool:
        if not super().applies(ctx):
            return False
        return ctx.target.scheme == "https"

    def run(self, ctx: ScanContext):
        host = ctx.target.host
        if not host:
            return
        port = ctx.target.port or 443
        endpoint = f"{host}:{port}"
        testssl = _tool_path(ctx, "testssl.sh")
        sslyze = _tool_path(ctx, "sslyze")
        if testssl:
            yield from self._run_testssl(testssl, endpoint)
        elif sslyze:
            yield from self._run_sslyze(sslyze, host, port)

    def _run_testssl(self, path, endpoint):
        args = [path, "--jsonfile", "-", "--quiet", "--warnings", "off", endpoint]
        try:
            code, out, err = run_tool(args, timeout=300)
        except Exception:
            return
        if not out:
            return
        try:
            records = json.loads(out)
        except (ValueError, TypeError):
            return
        if not isinstance(records, list):
            return
        for record in records:
            if not isinstance(record, dict):
                continue
            raw_sev = str(record.get("severity", "")).upper()
            if raw_sev not in ("HIGH", "CRITICAL", "MEDIUM", "WARN"):
                continue
            finding_id = record.get("id") or "tls"
            detail = record.get("finding") or ""
            if raw_sev in ("HIGH", "CRITICAL"):
                severity = Severity.HIGH
            elif raw_sev == "MEDIUM":
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            yield Finding(
                check=self.name,
                title=f"TLS issue: {finding_id}",
                severity=severity,
                confidence=Confidence.HIGH,
                category="A02:2021 Cryptographic Failures",
                cwe="CWE-326",
                description=f"testssl.sh flagged '{finding_id}': {detail}",
                remediation="Reconfigure TLS to disable weak protocols, ciphers, and known vulnerabilities.",
                location=endpoint,
                evidence=_snippet(f"{finding_id}: {detail}", 300),
                references=["https://testssl.sh/"],
                extra={"tool": "testssl.sh", "raw": _snippet(json.dumps(record))},
            )

    def _run_sslyze(self, path, host, port):
        args = [path, "--json_out", "-", f"{host}:{port}"]
        try:
            code, out, err = run_tool(args, timeout=300)
        except Exception:
            return
        if not out:
            return
        try:
            data = json.loads(out)
        except (ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        server_scans = data.get("server_scan_results") or []
        if not isinstance(server_scans, list):
            return
        for scan in server_scans:
            if not isinstance(scan, dict):
                continue
            results = scan.get("scan_result") or {}
            if not isinstance(results, dict):
                continue
            for protocol in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites"):
                block = results.get(protocol) or {}
                accepted = self._accepted_ciphers(block)
                if accepted:
                    yield Finding(
                        check=self.name,
                        title=f"Weak protocol enabled: {protocol}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="A02:2021 Cryptographic Failures",
                        cwe="CWE-326",
                        description=(
                            f"The server at {host}:{port} accepts connections over {protocol}, "
                            "an obsolete and insecure protocol."
                        ),
                        remediation="Disable SSLv2 and SSLv3; require TLS 1.2 or higher.",
                        location=f"{host}:{port}",
                        evidence=_snippet(f"{protocol} accepted ciphers: {accepted}", 300),
                        references=["https://github.com/nabla-c0d3/sslyze"],
                        extra={"tool": "sslyze", "raw": _snippet(f"{protocol}:{accepted}")},
                    )

    def _accepted_ciphers(self, block):
        try:
            result = block.get("result") or {}
            accepted = result.get("accepted_cipher_suites") or []
            return len(accepted)
        except (AttributeError, TypeError):
            return 0
