from __future__ import annotations

import re

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._common import is_catch_all

_HEX40 = re.compile(r"^[0-9a-f]{40}\b")
_REFLOG = re.compile(r"^[0-9a-f]{40} [0-9a-f]{40} ")
_ENV_SECRET = re.compile(r"(?im)^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API[_-]?KEY|TOKEN|DB_|PRIVATE)[A-Z0-9_]*\s*=\s*\S+")


def _not_html(resp) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    head = (resp.text or "")[:80].lstrip().lower()
    return "text/html" not in ctype and not head.startswith(("<!doctype", "<html"))


def _git_head(content, text):
    return text.startswith("ref: refs/") or bool(_HEX40.match(text.strip()))


def _git_config(content, text):
    low = text.lower()
    return "[core]" in low and "repositoryformatversion" in low


_VCS_PATHS = [
    ("/.git/index", lambda c, t: c[:4] == b"DIRC", "git repository index"),
    ("/.git/HEAD", _git_head, "git HEAD reference"),
    ("/.git/config", _git_config, "git repository config"),
    ("/.git/logs/HEAD", lambda c, t: bool(_REFLOG.match(t)), "git reflog"),
    ("/.svn/wc.db", lambda c, t: c[:16] == b"SQLite format 3\x00", "svn working copy database"),
    ("/.hg/requires", lambda c, t: any(m in t for m in ("revlogv1", "dotencode", "store")), "mercurial requirements"),
    ("/.bzr/branch-format", lambda c, t: "Bazaar" in t, "bazaar branch format"),
]

_CONFIG_PATHS = [
    ("/.env.local", lambda t: bool(_ENV_SECRET.search(t)), "environment secrets"),
    ("/.env.production", lambda t: bool(_ENV_SECRET.search(t)), "environment secrets"),
    ("/.env.backup", lambda t: bool(_ENV_SECRET.search(t)), "environment secrets"),
    ("/appsettings.json", lambda t: "ConnectionStrings" in t or '"Jwt"' in t, ".NET app settings"),
    ("/web.config", lambda t: "<configuration" in t.lower() and ("connectionstrings" in t.lower() or "appsettings" in t.lower()), "IIS web.config"),
    ("/.aws/credentials", lambda t: "aws_secret_access_key" in t.lower(), "AWS credentials"),
    ("/.npmrc", lambda t: "_authToken=" in t or "_auth=" in t, "npm auth token"),
    ("/id_rsa", lambda t: "PRIVATE KEY-----" in t, "SSH private key"),
    ("/.kube/config", lambda t: "apiVersion" in t and ("clusters" in t or "users" in t), "kubeconfig"),
    ("/wp-config.php.bak", lambda t: "<?php" in t and "DB_PASSWORD" in t, "WordPress config backup"),
    ("/wp-config.php~", lambda t: "<?php" in t and "DB_PASSWORD" in t, "WordPress config backup"),
]

_LISTING_HEADINGS = ("<title>index of ", "index of /", "directory listing for", "[to parent directory]")
_LISTING_BACKLINKS = ('href="../"', "href='../'", ">parent directory<", "[to parent directory]", ">../</a>")
_LISTING_DIRS = ["/uploads/", "/files/", "/backup/", "/backups/", "/old/", "/includes/", "/images/", "/static/", "/assets/", "/data/"]
_SENSITIVE_DIRS = {"/uploads/", "/backup/", "/backups/", "/old/", "/includes/", "/data/"}


@register
class VcsExposure(Check):
    name = "web.vcs_exposure"
    title = "Exposed version-control repository"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base or is_catch_all(ctx):
            return
        root = base.rstrip("/")
        for path, validator, label in _VCS_PATHS:
            resp = ctx.http.get(root + path)
            if resp is None or resp.status_code != 200:
                continue
            content = resp.content or b""
            text = resp.text or ""
            try:
                ok = validator(content, text)
            except (ValueError, TypeError):
                ok = False
            if not ok:
                continue
            yield Finding(
                check=self.name,
                title=f"Exposed version-control metadata: {path}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-527",
                description=f"The {label} at {path} is publicly served and returned valid VCS content. "
                "An exposed repository can be downloaded to recover full source code, history, and secrets.",
                remediation="Block access to VCS metadata directories (.git, .svn, .hg, .bzr) at the web "
                "server, and do not deploy them to production.",
                location=root + path,
                evidence=f"valid {label} content at {path}",
                references=["https://cwe.mitre.org/data/definitions/527.html"],
            )


@register
class ExposedConfigSecrets(Check):
    name = "web.exposed_config_secrets"
    title = "Exposed configuration or credential file"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base or is_catch_all(ctx):
            return
        root = base.rstrip("/")
        emitted = 0
        for path, validator, label in _CONFIG_PATHS:
            if emitted >= 8:
                break
            resp = ctx.http.get(root + path)
            if resp is None or resp.status_code != 200 or not _not_html(resp):
                continue
            text = resp.text or ""
            try:
                if not validator(text):
                    continue
            except (ValueError, TypeError):
                continue
            emitted += 1
            yield Finding(
                check=self.name,
                title=f"Exposed {label}: {path}",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-538",
                description=f"The {label} at {path} is served publicly and contains content matching its "
                "expected sensitive format. This can leak credentials, connection strings, or private keys.",
                remediation="Remove the file from the web root or block access to it, and rotate any exposed "
                "secret.",
                location=root + path,
                evidence=f"HTTP 200 with {label} markers",
                references=["https://cwe.mitre.org/data/definitions/538.html"],
            )


@register
class DirectoryListing(Check):
    name = "web.directory_listing"
    title = "Directory listing enabled"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def _lists(self, resp) -> bool:
        if resp is None or resp.status_code != 200:
            return False
        low = (resp.text or "").lower()
        return any(h in low for h in _LISTING_HEADINGS) and any(b in low for b in _LISTING_BACKLINKS)

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        root = base.rstrip("/")
        control = ctx.http.get(root + "/" + ctx.http.marker() + "-nodir/")
        if self._lists(control):
            return
        for path in _LISTING_DIRS:
            resp = ctx.http.get(root + path)
            if not self._lists(resp):
                continue
            sensitive = path in _SENSITIVE_DIRS
            yield Finding(
                check=self.name,
                title=f"Directory listing enabled at {path}",
                severity=Severity.MEDIUM if sensitive else Severity.LOW,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-548",
                description=f"The directory {path} returns an auto-generated index listing its contents. "
                "This exposes file names and structure, and can reveal backups, uploads, or source that "
                "were not meant to be discoverable.",
                remediation="Disable auto-indexing (Apache Options -Indexes, nginx autoindex off) and serve "
                "an explicit index or 403 for directories.",
                location=root + path,
                evidence="autoindex heading and parent-directory back-link present",
                references=["https://cwe.mitre.org/data/definitions/548.html"],
            )
