from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    ".next", "out", "vendor", ".idea", ".vscode", "coverage", ".pytest_cache", "target",
    ".mypy_cache", ".tox", ".gradle", "bin", "obj", ".terraform", "Pods", ".dart_tool",
}
_TEXT_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".go", ".php", ".cs", ".env",
    ".yml", ".yaml", ".json", ".xml", ".properties", ".sh", ".bash", ".ini", ".cfg",
    ".toml", ".conf", ".html", ".vue", ".kt", ".swift", ".c", ".cpp", ".h", ".sql",
    ".tf", ".gradle", ".rs", ".scala", ".pl", ".ps1", ".txt", ".md",
}
_CODE_EXT = _TEXT_EXT - {".txt", ".md", ".json", ".yml", ".yaml", ".xml", ".properties", ".ini", ".cfg", ".toml", ".conf"}

_MAX_FILE_BYTES = 1_500_000
_MAX_FILES = 6000
_MAX_PER_CHECK = 40

_SECRET_PATTERNS = {
    "AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "GitHub token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "Stripe secret key": re.compile(r"sk_live_[0-9A-Za-z]{20,}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "JSON web token": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Hardcoded credential assignment": re.compile(
        r"(?i)(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
    ),
}

_PLACEHOLDER = re.compile(r"(?i)(your|example|changeme|placeholder|xxxx|dummy|test|sample|\{\{|<|\$\{|env|process\.)")

_INJECTION = "A03:2021 Injection"
_CRYPTO = "A02:2021 Cryptographic Failures"
_INTEGRITY = "A08:2021 Software and Data Integrity Failures"
_MISCONFIG = "A05:2021 Security Misconfiguration"

_DANGEROUS_PATTERNS = [
    (re.compile(r"\beval\s*\("), "Use of eval()", Severity.HIGH, "CWE-95", _INJECTION,
     "Avoid eval on any input. Use safe parsers or explicit dispatch tables."),
    (re.compile(r"\bexec\s*\("), "Use of exec()", Severity.HIGH, "CWE-95", _INJECTION,
     "Avoid dynamic code execution. Refactor to call functions directly."),
    (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "Subprocess with shell=True", Severity.HIGH, "CWE-78", _INJECTION,
     "Pass an argument list and shell=False so input is never interpreted by a shell."),
    (re.compile(r"os\.system\s*\("), "os.system() call", Severity.HIGH, "CWE-78", _INJECTION,
     "Use subprocess with an argument list instead of os.system."),
    (re.compile(r"\bpickle\.loads?\s*\("), "Insecure deserialization (pickle)", Severity.HIGH, "CWE-502", _INTEGRITY,
     "Never unpickle untrusted data. Use JSON or a schema-validated format."),
    (re.compile(r"yaml\.load\s*\((?![^)]*Loader)"), "yaml.load without SafeLoader", Severity.MEDIUM, "CWE-502", _INTEGRITY,
     "Use yaml.safe_load, or pass Loader=SafeLoader."),
    (re.compile(r"verify\s*=\s*False"), "TLS certificate verification disabled", Severity.MEDIUM, "CWE-295", _CRYPTO,
     "Never disable TLS verification. Fix the trust store instead."),
    (re.compile(r"\bDEBUG\s*=\s*True"), "Debug mode enabled", Severity.LOW, "CWE-489", _MISCONFIG,
     "Ensure debug is disabled in production builds."),
    (re.compile(r"hashlib\.md5\s*\(|hashlib\.sha1\s*\("), "Weak hash function", Severity.LOW, "CWE-327", _CRYPTO,
     "Use SHA-256 or stronger; for passwords use bcrypt, scrypt, or argon2."),
    (re.compile(r"dangerouslySetInnerHTML"), "React dangerouslySetInnerHTML", Severity.MEDIUM, "CWE-79", _INJECTION,
     "Sanitize HTML before injecting, or render as text."),
    (re.compile(r"\.innerHTML\s*=(?!=)"), "Direct innerHTML assignment", Severity.LOW, "CWE-79", _INJECTION,
     "Use textContent or a sanitizer to avoid DOM XSS."),
    (re.compile(r"document\.write\s*\("), "document.write()", Severity.LOW, "CWE-79", _INJECTION,
     "Avoid document.write; build DOM nodes safely instead."),
]

_REF = ["https://owasp.org/www-project-web-security-testing-guide/"]


def _walk(root: str, extensions):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS and not d.startswith(".")]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in extensions and name != ".env":
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
                with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            except OSError:
                continue
            yield os.path.relpath(full, root), text
            count += 1
            if count >= _MAX_FILES:
                return


@register
class SourceSecrets(Check):
    name = "whitebox.hardcoded_secrets"
    title = "Hardcoded secrets in source"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root:
            return
        emitted = 0
        for rel, text in _walk(root, _TEXT_EXT):
            if emitted >= _MAX_PER_CHECK:
                break
            for lineno, line in enumerate(text.splitlines(), 1):
                if len(line) > 600:
                    continue
                for label, pattern in _SECRET_PATTERNS.items():
                    match = pattern.search(line)
                    if not match:
                        continue
                    token = match.group(0)
                    if label == "Hardcoded credential assignment" and _PLACEHOLDER.search(line):
                        continue
                    redacted = token[:6] + "..." if len(token) > 12 else token
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title=f"{label} in {rel}",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="A07:2021 Identification and Authentication Failures",
                        cwe="CWE-798",
                        description=f"A value matching {label} is committed in source at {rel}:{lineno}. "
                        "Secrets in a repository are exposed to anyone with read access and to history "
                        "forever, and should be treated as compromised.",
                        remediation="Remove the secret, rotate it, and load runtime secrets from environment "
                        "variables or a secrets manager. Add a pre-commit secret scanner.",
                        location=f"{rel}:{lineno}",
                        evidence=f"{label}: {redacted}",
                        references=_REF,
                    )
                    break


@register
class DangerousPatterns(Check):
    name = "whitebox.dangerous_patterns"
    title = "Risky code patterns"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root:
            return
        emitted = 0
        for rel, text in _walk(root, _CODE_EXT):
            if emitted >= _MAX_PER_CHECK:
                break
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                if len(line) > 600 or stripped.startswith(("#", "//", "*", "/*")):
                    continue
                for pattern, title, severity, cwe, category, remediation in _DANGEROUS_PATTERNS:
                    if pattern.search(line):
                        emitted += 1
                        yield Finding(
                            check=self.name,
                            title=f"{title} in {rel}",
                            severity=severity,
                            confidence=Confidence.LOW,
                            category=category,
                            cwe=cwe,
                            description=f"{title} at {rel}:{lineno}. This construct is a common source of "
                            "security bugs and warrants review in context.",
                            remediation=remediation,
                            location=f"{rel}:{lineno}",
                            evidence=stripped[:160],
                            references=_REF,
                        )
                        break


@register
class StaticAnalysis(Check):
    name = "whitebox.static_analysis"
    title = "External static analyzer"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root:
            return
        if shutil.which("semgrep"):
            yield from self._semgrep(root)
        elif shutil.which("bandit"):
            yield from self._bandit(root)
        else:
            yield Finding(
                check=self.name,
                title="Deeper static analysis skipped (no analyzer installed)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="A06:2021 Vulnerable and Outdated Components",
                description="fya ran its built-in secret and risky-pattern scans. Install semgrep or bandit "
                "on PATH to fold rule-based static analysis into this report.",
                remediation="pip install semgrep (or bandit for Python), then re-run.",
                location=root,
            )

    def _semgrep(self, root: str):
        try:
            proc = subprocess.run(
                ["semgrep", "scan", "--config", "auto", "--json", "--quiet", "--timeout", "45", root],
                capture_output=True, text=True, timeout=240,
            )
            data = json.loads(proc.stdout or "{}")
        except (OSError, ValueError, subprocess.SubprocessError):
            return
        sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        for item in (data.get("results") or [])[:_MAX_PER_CHECK]:
            extra = item.get("extra", {})
            rel = os.path.relpath(item.get("path", root), root)
            line = item.get("start", {}).get("line", "")
            yield Finding(
                check=self.name,
                title=f"semgrep: {item.get('check_id', 'finding').split('.')[-1]}",
                severity=sev_map.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW),
                confidence=Confidence.MEDIUM,
                category="A06:2021 Vulnerable and Outdated Components",
                description=(extra.get("message") or "semgrep rule match.").strip()[:600],
                remediation="Review the flagged rule and remediate per semgrep guidance.",
                location=f"{rel}:{line}",
                evidence=(item.get("check_id") or "")[:200],
                references=["https://semgrep.dev/r"],
            )

    def _bandit(self, root: str):
        try:
            proc = subprocess.run(
                ["bandit", "-r", "-f", "json", "-q", root],
                capture_output=True, text=True, timeout=240,
            )
            data = json.loads(proc.stdout or "{}")
        except (OSError, ValueError, subprocess.SubprocessError):
            return
        sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        for item in (data.get("results") or [])[:_MAX_PER_CHECK]:
            rel = os.path.relpath(item.get("filename", root), root)
            yield Finding(
                check=self.name,
                title=f"bandit: {item.get('test_id', '')} {item.get('test_name', '')}".strip(),
                severity=sev_map.get(str(item.get("issue_severity", "LOW")).upper(), Severity.LOW),
                confidence=Confidence.MEDIUM,
                category="A03:2021 Injection",
                cwe=(item.get("issue_cwe") or {}).get("id") and f"CWE-{item['issue_cwe']['id']}" or None,
                description=(item.get("issue_text") or "bandit finding.").strip()[:600],
                remediation="Review the flagged issue per bandit guidance.",
                location=f"{rel}:{item.get('line_number', '')}",
                evidence=(item.get("code") or "").strip()[:200],
                references=["https://bandit.readthedocs.io/"],
            )


_PWN_TRIGGER = re.compile(r"\b(pull_request_target|workflow_run)\b")
_CHECKOUT = re.compile(r"uses:\s*actions/checkout")
_UNTRUSTED_REF = re.compile(r"ref:\s*\$\{\{\s*[^}]*(github\.event\.pull_request\.head|github\.head_ref)")
_INJECT_EXPR = re.compile(
    r"\$\{\{\s*[^}]*(github\.event\.(?:issue|pull_request|comment|review|discussion)\.[a-z_.]*(?:title|body|label|ref_name)"
    r"|github\.head_ref)[^}]*\}\}"
)


@register
class CicdMisconfig(Check):
    name = "whitebox.cicd_misconfig"
    title = "Dangerous CI workflow patterns"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root:
            return
        wf_dir = os.path.join(root, ".github", "workflows")
        if not os.path.isdir(wf_dir):
            return
        emitted = 0
        for name in sorted(os.listdir(wf_dir)):
            if emitted >= _MAX_PER_CHECK or not name.lower().endswith((".yml", ".yaml")):
                continue
            path = os.path.join(wf_dir, name)
            try:
                if os.path.getsize(path) > _MAX_FILE_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)

            if _PWN_TRIGGER.search(text) and _CHECKOUT.search(text) and _UNTRUSTED_REF.search(text):
                emitted += 1
                yield Finding(
                    check=self.name,
                    title=f"GitHub Actions pwn-request in {rel}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="A08:2021 Software and Data Integrity Failures",
                    cwe="CWE-94",
                    description=f"{rel} runs on pull_request_target/workflow_run and checks out the "
                    "untrusted PR head ref, so code from a fork PR executes with repository secrets and a "
                    "write-scoped token. This is the classic pwn-request supply-chain vulnerability.",
                    remediation="Do not check out untrusted PR code in a privileged workflow; split into an "
                    "untrusted build (pull_request) and a privileged step that only consumes artifacts.",
                    location=rel,
                    evidence="pull_request_target/workflow_run + checkout of untrusted head ref",
                    references=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
                )
                continue

            for match in _INJECT_EXPR.finditer(text):
                window = text[max(0, match.start() - 200):match.start()]
                if "run:" not in window:
                    continue
                emitted += 1
                yield Finding(
                    check=self.name,
                    title=f"GitHub Actions script injection in {rel}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="A03:2021 Injection",
                    cwe="CWE-94",
                    description=f"{rel} interpolates an attacker-controllable expression "
                    f"({match.group(0)[:80]}) directly into a shell 'run:' step. An attacker who controls "
                    "that field (PR title, issue body, branch name, etc.) can inject shell commands into the "
                    "runner.",
                    remediation="Pass untrusted values through an intermediate env: variable and reference "
                    "\"$VAR\" in the script, rather than interpolating ${{ ... }} directly into run:.",
                    location=rel,
                    evidence=match.group(0)[:160],
                    references=["https://securitylab.github.com/resources/github-actions-untrusted-input/"],
                )
                break

