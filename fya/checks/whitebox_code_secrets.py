"""Source-tree checks: committed credential material and multi-language dangerous patterns.

Everything here is an offline filesystem read of ``ctx.target.source_path``. SOURCE scans have
``ctx.http is None``, so no network call is made from this module.
"""

from __future__ import annotations

import base64
import fnmatch
import os
import re
import shutil
import subprocess
from typing import Iterator, List, Optional, Tuple

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .whitebox import _CODE_EXT, _IGNORE_DIRS, _MAX_FILE_BYTES, _walk

_CAP = 15
_PER_FILE = 3
_MAX_VISIT = 40000
_READ_LIMIT = 400_000
_MAX_LINES = 4000

_CRYPTO_CAT = "A02:2021 Cryptographic Failures"
_INJECTION_CAT = "A03:2021 Injection"
_ACCESS_CAT = "A01:2021 Broken Access Control"

_REF_STORAGE = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/312.html",
]
_REF_SQLI = [
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
]
_REF_VERIFY = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
]
_REF_CRYPTO = [
    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
]

_LOWER_SEVERITY = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
    Severity.INFO: Severity.INFO,
}


# --------------------------------------------------------------------------------------
# shared line handling: comment stripping + joined multi-line windows
# --------------------------------------------------------------------------------------

_COMMENT_PREFIXES = ("#", "//", "*", "/*", "--", "<!--", '"""', "'''")

_PATH_DOWNGRADE = re.compile(
    r"(?i)(^|[\\/])(tests?|__tests__|fixtures?|migrations?|seeds?|seeders?|specs?)([\\/]|$)"
)
_MOCKY_PATH = re.compile(
    r"(?i)(^|[\\/])(tests?|__tests__|mocks?|fixtures?|benchmarks?|specs?)([\\/]|$)"
)
# Anchored to real test-file naming conventions. An unanchored substring match would swallow
# high-value auth filenames such as introspection ("spec"), attestation ("test") or latest.
_TEST_BASENAME = re.compile(
    r"(?i)^(?:test_|tests?[-_.]|conftest\b|mock_|spec_)"
    r"|[-_.](?:test|tests|spec|specs|e2e|mock|mocks|bench|benchmark)(?:\.|$)"
    r"|(?-i:Test|Tests|Spec|IT)\.(?:java|kt|scala|cs)$"
)
_GO_TEST_TAG = re.compile(r"//\s*(\+build|go:build)\s+[^\n]*\btest\b")


def _visible_lines(text: str) -> List[Tuple[int, str]]:
    """Return (lineno, line) with comment-prefixed and absurdly long lines blanked out."""
    out: List[Tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines()[:_MAX_LINES], 1):
        if len(line) > 600 or line.strip().startswith(_COMMENT_PREFIXES):
            out.append((lineno, ""))
            continue
        out.append((lineno, line))
    return out


def _window_lines(text: str, size: int) -> Iterator[Tuple[int, List[str]]]:
    """Yield (lineno, [line, ...]) sliding over comment-stripped source lines.

    Callers that need to reason about what is bound on a *single* line (rather than merely
    co-present in the window) must use this instead of the joined form.
    """
    lines = _visible_lines(text)
    for idx, (lineno, line) in enumerate(lines):
        if not line.strip():
            continue
        yield lineno, [item[1] for item in lines[idx:idx + size]]


def _windows(text: str, size: int) -> Iterator[Tuple[int, str]]:
    """Yield (lineno, joined-window) sliding over comment-stripped source lines."""
    for lineno, chunk in _window_lines(text, size):
        yield lineno, " ".join(chunk)


def _is_downgraded_path(rel: str) -> bool:
    return bool(_PATH_DOWNGRADE.search(rel))


def _is_mocky(rel: str) -> bool:
    base = os.path.basename(rel)
    return bool(_MOCKY_PATH.search(rel) or _TEST_BASENAME.search(base))


def _skip_verification_file(rel: str, text: str) -> bool:
    """Disabling verification in a test harness is the dominant FP; drop those files."""
    base = os.path.basename(rel)
    if _TEST_BASENAME.search(base) or base.endswith("_test.go"):
        return True
    if rel.lower().endswith(".go"):
        head = "\n".join(text.splitlines()[:5])
        if _GO_TEST_TAG.search(head):
            return True
    return False


# --------------------------------------------------------------------------------------
# whitebox.committed_key_material
# --------------------------------------------------------------------------------------

_ID_KEY = re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)$")
_KEYISH_EXT = re.compile(r"(?i)\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)$")
_BINARY_STORE_EXT = re.compile(r"(?i)\.(p12|pfx|jks|keystore|kdbx)$")
_ENV_FILE = re.compile(r"^\.env(\..+)?$")
_ENV_TEMPLATE = re.compile(r"(?i)\.(example|sample|template|dist|tpl)$")
_TFSTATE = re.compile(r"^terraform\.tfstate(\.backup)?$")
_GCP_JSON = re.compile(
    r"(?i)^(?:.*(?:service[-_]?account|gcp[-_]?key).*|[a-z0-9][a-z0-9-]*-[0-9a-f]{12})\.json$"
)
_INI_CRED_NAMES = {".pypirc", ".my.cnf", "credentials"}

_PEM_PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
_NPM_TOKEN = re.compile(r"(?im)^[^\n]*?(_authToken|_password|_auth)\s*=\s*(\S{8,})\s*$")
_PASSWORD_ASSIGN = re.compile(r"(?im)\bpassword\s*[=:]\s*(\S{6,})")
_PASSWORD_SPACED = re.compile(r"(?im)\bpassword\s+(\S{6,})")
_AWS_SECRET = re.compile(
    r"(?im)^\s*aws_(?:secret_access_key|access_key_id|session_token)\s*=\s*(\S{8,})\s*$"
)
_PGPASS_LINE = re.compile(r"(?m)^[^:#\n]*:[^:\n]*:[^:\n]*:[^:\n]*:\S{4,}\s*$")
_DOCKER_AUTH = re.compile(r"\"auth\"\s*:\s*\"([A-Za-z0-9+/=_-]{8,})\"")
_SA_TYPE = re.compile(r"\"type\"\s*:\s*\"service_account\"")
_SA_KEY = re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN")
_ENV_SECRET = re.compile(
    r"(?im)^\s*(?:export\s+)?"
    r"([A-Za-z0-9_]*(?:PASS|SECRET|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|DSN)[A-Za-z0-9_]*)"
    r"\s*=\s*(\S{8,})"
)
_KUBE_CRED = re.compile(r"(?m)^\s*-?\s*(client-key-data|token|password)\s*:\s*\S{8,}")
_TFSTATE_MARKER = re.compile(r"\"terraform_version\"")
_GIT_URL_CRED = re.compile(r"(?im)^\s*url\s*=\s*(https?)://([^:@/\s]+):([^@/\s]+)@")
_PLACEHOLDER_VALUE = re.compile(r"^[\"']?(?:\$\{|<|\$\(|%[A-Za-z_]+%|\$[A-Z_]+\b)")
# Mirrors whitebox._PLACEHOLDER: the canonical dev-default / "fill me in" vocabulary that
# dominates committed .env files and credential templates.
_PLACEHOLDER_WORD = re.compile(
    r"(?i)(your|example|exemple|changeme|change[-_]me|change[-_]this|placeholder|todo|fixme"
    r"|xxxx|dummy|sample|replace[-_]?(?:me|this)?|redacted|insert[-_]?here|goes[-_]?here"
    r"|[-_]here\b|not[-_]?set|to[-_]?be[-_]?set|dev[-_]only|localhost|in[-_]production)"
)
# All-lowercase english-ish words joined by - or _, e.g. "changeme-in-production", "super-secret".
_WORDY_VALUE = re.compile(r"^[\"']?[a-z]+(?:[-_][a-z]+)+[\"']?$")
# Short, single-token, alphabetic values ("postgres", "admin", "secret") carry no entropy.
_LOW_ENTROPY_VALUE = re.compile(r"^[\"']?[A-Za-z]{1,11}[\"']?$")
_WORD_TOKEN = re.compile(r"[A-Za-z]{3,}")

_KIND_LABEL = {
    "pemkey": "Private key file",
    "store": "Keystore / credential database",
    "npmrc": "npm registry auth token",
    "inicred": "Credential file",
    "netrc": "netrc credentials",
    "pgpass": "PostgreSQL password file",
    "docker": "Docker registry credentials",
    "gcp": "GCP service-account key",
    "env": "Environment file with literal secret values",
    "tfstate": "Terraform state file",
    "kube": "Kubeconfig with embedded credentials",
}


def _classify(name: str, rel_posix: str) -> Optional[str]:
    """Map a basename to a credential-material kind, or None."""
    lower = name.lower()
    if _ID_KEY.match(lower):
        return "pemkey"
    if _BINARY_STORE_EXT.search(lower):
        return "store"
    if _KEYISH_EXT.search(lower):
        return "pemkey"
    if lower == ".npmrc":
        return "npmrc"
    if lower in _INI_CRED_NAMES:
        return "inicred"
    if lower in (".netrc", "_netrc"):
        return "netrc"
    if lower == ".pgpass":
        return "pgpass"
    if lower == ".dockercfg":
        return "docker"
    if lower == "config.json" and "/.docker/" in "/" + rel_posix.lower():
        return "docker"
    if _TFSTATE.match(lower):
        return "tfstate"
    if lower == "kubeconfig" or lower.endswith(".kubeconfig"):
        return "kube"
    if lower.endswith(".json") and _GCP_JSON.match(lower):
        return "gcp"
    if _ENV_FILE.match(name) and not _ENV_TEMPLATE.search(lower):
        return "env"
    return None


def _read_bytes(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as handle:
            return handle.read(_READ_LIMIT)
    except OSError:
        return None


def _read_text(path: str) -> Optional[str]:
    raw = _read_bytes(path)
    if raw is None:
        return None
    return raw.decode("utf-8", "ignore")


def _echoes_key(value: str, key: Optional[str]) -> bool:
    """True for dev defaults that just repeat the variable name (POSTGRES_PASSWORD=postgres)."""
    if not key:
        return False
    flat = re.sub(r"[^a-z0-9]", "", value.lower())
    if not flat:
        return False
    key_lower = key.lower()
    if flat == re.sub(r"[^a-z0-9]", "", key_lower):
        return True
    return flat in {token.lower() for token in _WORD_TOKEN.findall(key_lower)}


def _live_value(value: str, key: Optional[str] = None) -> bool:
    """True when the literal looks like a real credential rather than a template/dev default.

    Placeholder syntax (``${VAR}``, ``<fill-me>``), the usual "changeme"/"your-token-here"
    vocabulary, values that merely echo the variable name, hyphenated english-word strings and
    short alphabetic tokens are all rejected: reporting those as committed secrets is the
    dominant false positive for this check.
    """
    value = value.strip()
    if not value or _PLACEHOLDER_VALUE.match(value):
        return False
    if _PLACEHOLDER_WORD.search(value):
        return False
    if _WORDY_VALUE.match(value) or _LOW_ENTROPY_VALUE.match(value):
        return False
    return not _echoes_key(value, key)


def _password_marker(text: str, label: str) -> Optional[str]:
    for pattern in (_PASSWORD_ASSIGN, _PASSWORD_SPACED):
        match = pattern.search(text)
        if match and _live_value(match.group(1), "password"):
            return "{0}: password line with a literal value".format(label)
    return None


def _docker_marker(text: str, require_auths: bool) -> Optional[str]:
    if require_auths and '"auths"' not in text:
        return None
    for match in _DOCKER_AUTH.finditer(text):
        blob = match.group(1)
        blob += "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(blob).decode("utf-8", "ignore")
        except (ValueError, TypeError):
            continue
        user, sep, secret = decoded.partition(":")
        if sep and secret.strip() and user.strip():
            return '"auth" entry decodes to {0}:<redacted>'.format(user[:24])
    return None


def _confirm(kind: str, path: str) -> Optional[Tuple[Severity, str, Confidence]]:
    """Content-confirm a candidate. Never report on filename alone.

    Returns (severity, evidence marker, confidence). Confidence is HIGH only where the file
    format itself is unambiguous (a PEM private key, a keystore magic, a decoded registry
    auth blob); anything resting purely on "this looks like a literal value" is MEDIUM.
    """
    raw = _read_bytes(path)
    if not raw:
        return None
    if kind == "store":
        if raw.startswith(b"\xfe\xed\xfe\xed"):
            return Severity.MEDIUM, "JKS keystore magic 0xFEEDFEED", Confidence.HIGH
        if raw.startswith(b"\x30\x82"):
            return Severity.MEDIUM, "PKCS#12 DER header 0x3082", Confidence.HIGH
        if raw.startswith(b"\x03\xd9\xa2\x9a"):
            return Severity.MEDIUM, "KeePass KDBX magic 0x03D9A29A", Confidence.HIGH
        match = _PEM_PRIVATE.search(raw.decode("utf-8", "ignore"))
        return (Severity.HIGH, match.group(0), Confidence.HIGH) if match else None

    text = raw.decode("utf-8", "ignore")

    if kind == "pemkey":
        match = _PEM_PRIVATE.search(text)
        return (Severity.HIGH, match.group(0), Confidence.HIGH) if match else None
    if kind == "npmrc":
        match = _NPM_TOKEN.search(text)
        if match and _live_value(match.group(2), match.group(1)):
            return (
                Severity.HIGH,
                "{0}=<redacted registry token>".format(match.group(1)),
                Confidence.MEDIUM,
            )
        return None
    if kind == "inicred":
        match = _AWS_SECRET.search(text)
        if match and _live_value(match.group(1), "aws"):
            return Severity.HIGH, "aws_* credential line with a literal value", Confidence.MEDIUM
        marker = _password_marker(text, "credential file")
        return (Severity.HIGH, marker, Confidence.MEDIUM) if marker else None
    if kind == "netrc":
        marker = _password_marker(text, "netrc")
        return (Severity.HIGH, marker, Confidence.MEDIUM) if marker else None
    if kind == "pgpass":
        if _PGPASS_LINE.search(text):
            return Severity.HIGH, "host:port:db:user:<redacted> pgpass entry", Confidence.MEDIUM
        return None
    if kind == "docker":
        marker = _docker_marker(text, require_auths=not path.lower().endswith(".dockercfg"))
        return (Severity.HIGH, marker, Confidence.HIGH) if marker else None
    if kind == "gcp":
        if _SA_TYPE.search(text) and _SA_KEY.search(text):
            return (
                Severity.HIGH,
                '"type": "service_account" + "private_key": "-----BEGIN',
                Confidence.HIGH,
            )
        return None
    if kind == "env":
        for match in _ENV_SECRET.finditer(text):
            if _live_value(match.group(2), match.group(1)):
                return (
                    Severity.HIGH,
                    "{0}=<redacted literal value>".format(match.group(1)),
                    Confidence.MEDIUM,
                )
        return None
    if kind == "tfstate":
        if _TFSTATE_MARKER.search(text):
            return Severity.MEDIUM, '"terraform_version" state document', Confidence.MEDIUM
        return None
    if kind == "kube":
        match = _KUBE_CRED.search(text)
        if match:
            return (
                Severity.HIGH,
                "kubeconfig {0}: <redacted>".format(match.group(1)),
                Confidence.MEDIUM,
            )
        return None
    return None


def _walk_named(root: str) -> Iterator[Tuple[str, str, str]]:
    """Yield (relpath, kind, fullpath) for credential-material candidates, selected by basename.

    Unlike ``whitebox._walk`` this prunes only ``_IGNORE_DIRS`` (which keeps ``.git`` out) so
    dot-directories such as ``.ssh``/``.aws``/``.docker`` are still visited.
    """
    visited = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
        for name in filenames:
            visited += 1
            if visited > _MAX_VISIT:
                return
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            kind = _classify(name, rel.replace(os.sep, "/"))
            if kind is None:
                continue
            try:
                if os.path.getsize(full) > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield rel, kind, full


def _tracked_files(root: str) -> Optional[set]:
    """Set of git-tracked repo-relative posix paths, or None when git cannot answer."""
    if not os.path.isdir(os.path.join(root, ".git")):
        return None
    if not shutil.which("git"):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            capture_output=True,
            timeout=20,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    listing = (proc.stdout or b"").decode("utf-8", "ignore")
    return {entry for entry in listing.split("\0") if entry}


def _gitignore_patterns(root: str) -> List[str]:
    patterns: List[str] = []
    try:
        with open(os.path.join(root, ".gitignore"), "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                entry = line.strip()
                if not entry or entry.startswith(("#", "!")):
                    continue
                patterns.append(entry.strip("/"))
    except OSError:
        return []
    return patterns[:400]


def _is_ignored(rel_posix: str, patterns: List[str]) -> bool:
    parts = rel_posix.split("/")
    base = parts[-1]
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(rel_posix, pattern + "/*"):
                return True
            continue
        if fnmatch.fnmatch(base, pattern) or pattern in parts[:-1]:
            return True
    return False


@register
class CommittedKeyMaterial(Check):
    name = "whitebox.committed_key_material"
    title = "Private keys, credential files and state files committed to the repo"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        tracked = _tracked_files(root)
        ignored = _gitignore_patterns(root) if tracked is None else []
        emitted = 0

        for rel, kind, full in _walk_named(root):
            if emitted >= _CAP:
                return
            rel_posix = rel.replace(os.sep, "/")
            if tracked is not None:
                if rel_posix not in tracked:
                    continue
            elif ignored and _is_ignored(rel_posix, ignored):
                continue
            confirmed = _confirm(kind, full)
            if not confirmed:
                continue
            severity, marker, confidence = confirmed
            label = _KIND_LABEL.get(kind, "Credential material")
            emitted += 1
            yield Finding(
                check=self.name,
                title="{0} committed at {1}".format(label, rel_posix),
                severity=severity,
                confidence=confidence,
                category=_CRYPTO_CAT,
                cwe="CWE-312",
                description="{0} is present at {1} and its contents match committed credential "
                "material rather than a template reference or a public certificate. Anything "
                "committed to a repository is readable by everyone with repo access and stays in "
                "git history after deletion, so this material should be treated as exposed{2}.".format(
                    label,
                    rel_posix,
                    ". Confidence is MEDIUM because the value is recognised by shape alone, so "
                    "confirm it is a live credential and not an unrecognised dev default before "
                    "rewriting history" if confidence is Confidence.MEDIUM else "",
                ),
                remediation="Remove the file from the working tree and from history (git filter-repo "
                "or BFG), rotate the key/credential it contains, and add the path to .gitignore. "
                "Load runtime credentials from environment variables or a secrets manager instead.",
                location=rel_posix,
                evidence=marker[:200],
                references=_REF_STORAGE,
            )

        if emitted >= _CAP:
            return
        git_config = os.path.join(root, ".git", "config")
        if not os.path.isfile(git_config):
            return
        text = _read_text(git_config) or ""
        match = _GIT_URL_CRED.search(text)
        if not match:
            return
        yield Finding(
            check=self.name,
            title="Git remote URL embeds a username and password",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=_CRYPTO_CAT,
            cwe="CWE-312",
            description="A remote in .git/config is configured as "
            "{0}://<user>:<password>@... so a live credential (often a personal access token) is "
            "stored in cleartext in the checkout and is echoed by any command that prints the "
            "remote URL.".format(match.group(1)),
            remediation="Rewrite the remote without inline credentials "
            "(git remote set-url origin https://host/org/repo.git), rotate the token, and use a "
            "credential helper or SSH key for authentication.",
            location=".git/config",
            evidence="url = {0}://{1}:<redacted>@...".format(match.group(1), match.group(2)[:24]),
            references=_REF_STORAGE,
        )


# --------------------------------------------------------------------------------------
# whitebox.sql_string_building
# --------------------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".py": "py",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".vue": "js",
    ".java": "java",
    ".kt": "java",
    ".scala": "java",
    ".php": "php",
    ".go": "go",
    ".cs": "cs",
}

_SQL_VERB = re.compile(
    r"(?i)\b(SELECT\s|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|WHERE\s|ORDER\s+BY"
    r"|UNION\s+(?:ALL\s+)?SELECT)"
)
# Correct parameterisation: any paramstyle placeholder (format %s, pyformat %(name)s, qmark ?,
# named :name, numeric $1) closing its string and followed by a params tuple/list/dict.
_PARAM_SAFE = re.compile(
    r"(?:%s|%\(\w+\)s|\?|:\w+|\$\d+)[^\"'\n]{0,60}[\"'][^)\n]{0,40},\s*[\(\[\{]"
)
# Tagged templates are escaped by the driver; these are the dominant JS false positives.
_TAGGED_SAFE = re.compile(r"\$queryRaw`|\$executeRaw`|\bsql`|\bslonik\b")

_PY_DRIVER = re.compile(r"\.(?:execute|executemany|raw|read_sql)\s*\(")
_PY_SQL_ARG = re.compile(r"^\s*(?:f\s*)?[\"']")
_PY_INTERP = re.compile(r"f[\"'][^\"']*\{|[\"']\s*%\s*[\w(]|\.format\(|[\"']\s*\+\s*\w")
_JS_TEMPLATE = re.compile(r"\.(?:query|execute|raw|prepare)\s*\(\s*`[^`]*\$\{")
_JS_RAW_UNSAFE = re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(")
_JAVA_DRIVER = re.compile(
    r"(?:createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\("
)
_JAVA_INTERP = re.compile(r"[\"']\s*\+\s*\w|String\.format\s*\(")
_PHP_DRIVER = re.compile(r"(?:mysqli_query|pg_query|->query|->exec|->prepare)\s*\(")
_PHP_INTERP = re.compile(r"[\"']\s*\.\s*\$|\"[^\"]*(?:\$\w+|\{\$)")
_GO_DRIVER = re.compile(r"\.(?:Query|QueryRow|Exec|QueryContext)\s*\(")
_GO_INTERP = re.compile(r"fmt\.Sprintf\s*\(|[\"']\s*\+\s*\w")
_CS_DRIVER = re.compile(r"new\s+Sql(?:Command|DataAdapter)\s*\(|(?:FromSqlRaw|ExecuteSqlRaw)\s*\(")
_CS_INTERP = re.compile(r"\$\"|[\"']\s*\+\s*\w")


def _call_args(text: str, open_idx: int, limit: int = 400) -> str:
    """Return the argument text of the call whose '(' sits at ``open_idx``."""
    depth = 0
    for pos in range(open_idx, min(len(text), open_idx + limit)):
        char = text[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:pos]
    return text[open_idx + 1:open_idx + 1 + limit]


def _py_sql_hit(window: str) -> Optional[str]:
    """Python: test for interpolation inside the execute() argument, not anywhere nearby.

    A parameterised ``cur.execute("... ?", params)`` next to an unrelated ``.format()`` on the
    following line is the dominant false positive, so the interpolation test is scoped to the
    driver call's own arguments.
    """
    for match in _PY_DRIVER.finditer(window):
        args = _call_args(window, match.end() - 1)
        if not _PY_SQL_ARG.match(args):
            continue
        if _PARAM_SAFE.search(args):
            continue
        if _SQL_VERB.search(args) and _PY_INTERP.search(args):
            return "SQL string interpolated into a Python DB-API execute()"
    return None


def _sql_hit(lang: str, window: str) -> Optional[str]:
    if lang == "py":
        return _py_sql_hit(window)
    elif lang == "js":
        if _JS_TEMPLATE.search(window):
            return "SQL template literal with ${...} passed to a driver query()"
        if _JS_RAW_UNSAFE.search(window):
            return "Prisma $queryRawUnsafe/$executeRawUnsafe with a built SQL string"
    elif lang == "java":
        if _JAVA_DRIVER.search(window) and _JAVA_INTERP.search(window):
            return "SQL concatenated into a JDBC/JPA statement"
    elif lang == "php":
        if _PHP_DRIVER.search(window) and _PHP_INTERP.search(window):
            return "SQL built with PHP string interpolation or concatenation"
    elif lang == "go":
        if _GO_DRIVER.search(window) and _GO_INTERP.search(window):
            return "SQL built with fmt.Sprintf/concatenation before database/sql call"
    elif lang == "cs":
        if _CS_DRIVER.search(window) and _CS_INTERP.search(window):
            return "SQL built with string interpolation before SqlCommand/FromSqlRaw"
    return None


@register
class SqlStringBuilding(Check):
    name = "whitebox.sql_string_building"
    title = "SQL statement assembled by string concatenation or interpolation"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for rel, text in _walk(root, _CODE_EXT):
            if emitted >= _CAP:
                return
            lang = _LANG_BY_EXT.get(os.path.splitext(rel)[1].lower())
            if lang is None:
                continue
            rel_posix = rel.replace(os.sep, "/")
            downgraded = _is_downgraded_path(rel)
            seen: set = set()
            for lineno, window in _windows(text, 2):
                if len(seen) >= _PER_FILE or emitted >= _CAP:
                    break
                if not _SQL_VERB.search(window):
                    continue
                if _PARAM_SAFE.search(window) or _TAGGED_SAFE.search(window):
                    continue
                label = _sql_hit(lang, window)
                if not label or label in seen:
                    continue
                seen.add(label)
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="{0} in {1}".format(label, rel_posix),
                    severity=Severity.LOW if downgraded else Severity.HIGH,
                    confidence=Confidence.LOW if downgraded else Confidence.MEDIUM,
                    category=_INJECTION_CAT,
                    cwe="CWE-89",
                    description="{0}:{1} hands a SQL statement built by concatenation or "
                    "interpolation to a database driver. If any interpolated value reaches this "
                    "code from a request, it is SQL injection. Confidence is MEDIUM because "
                    "reachability from untrusted input is not proven by static matching alone"
                    "{2}.".format(
                        rel_posix,
                        lineno,
                        "; this path looks like test/fixture/migration code, which usually builds "
                        "DDL from constants, so it is reported at LOW" if downgraded else "",
                    ),
                    remediation="Use parameter binding for every value: placeholders plus a params "
                    "tuple/array (cursor.execute(sql, params), PreparedStatement.setX, $queryRaw "
                    "tagged templates, sqlx named args). Only identifiers that cannot be "
                    "parameterised should be interpolated, and only from an allowlist.",
                    location="{0}:{1}".format(rel_posix, lineno),
                    evidence=window.strip()[:180],
                    references=_REF_SQLI,
                )


# --------------------------------------------------------------------------------------
# whitebox.auth_verification_disabled
# --------------------------------------------------------------------------------------

_VERIFY_RULES = [
    (
        re.compile(r"jwt\.decode\([^)]*verify\s*=\s*False"),
        "JWT decoded with signature verification disabled",
        Severity.HIGH, "CWE-347", _CRYPTO_CAT,
        "Always verify the signature: pass the key and algorithms=['RS256'] (or your algorithm) "
        "and let the library reject unverified tokens.",
    ),
    (
        re.compile(r"[\"']?verify_signature[\"']?\s*:\s*(?:False|false)"),
        "JWT signature verification switched off in options",
        Severity.HIGH, "CWE-347", _CRYPTO_CAT,
        "Remove verify_signature: false. Decode with the signing key so forged tokens are rejected.",
    ),
    (
        re.compile(r"algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']"),
        "JWT 'none' algorithm accepted",
        Severity.HIGH, "CWE-347", _CRYPTO_CAT,
        "Never allow alg=none. Pin an explicit allowlist of asymmetric or HMAC algorithms.",
    ),
    (
        re.compile(r"\bParseUnverified\s*\("),
        "JWT parsed without verification (ParseUnverified)",
        Severity.HIGH, "CWE-347", _CRYPTO_CAT,
        "Use jwt.Parse/ParseWithClaims with a keyfunc and a validated signing method.",
    ),
    (
        re.compile(r"SkipClaimsValidation\s*:\s*true"),
        "JWT claims validation skipped",
        Severity.HIGH, "CWE-347", _CRYPTO_CAT,
        "Leave claims validation enabled so exp/nbf/aud are enforced.",
    ),
    (
        re.compile(r"rejectUnauthorized\s*:\s*false"),
        "TLS certificate validation disabled (rejectUnauthorized: false)",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Keep rejectUnauthorized true and add the internal CA to the trust store instead.",
    ),
    (
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0"),
        "TLS certificate validation disabled process-wide",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Never set NODE_TLS_REJECT_UNAUTHORIZED=0; it disables verification for every connection "
        "in the process. Use NODE_EXTRA_CA_CERTS for private CAs.",
    ),
    (
        re.compile(r"InsecureSkipVerify\s*:\s*true"),
        "Go TLS verification disabled (InsecureSkipVerify: true)",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Set InsecureSkipVerify to false and supply RootCAs with the CA you actually trust.",
    ),
    (
        re.compile(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)"),
        "cURL TLS verification disabled",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Leave CURLOPT_SSL_VERIFYPEER=true and VERIFYHOST=2, and point CURLOPT_CAINFO at a CA "
        "bundle.",
    ),
    (
        re.compile(r"ssl\._create_unverified_context\s*\(|ssl\.CERT_NONE"),
        "Python TLS context created without certificate verification",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Use ssl.create_default_context() and load your CA with load_verify_locations().",
    ),
    (
        re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER"),
        "Java hostname verification disabled",
        Severity.HIGH, "CWE-295", _CRYPTO_CAT,
        "Use the default (browser-compatible) hostname verifier so the certificate CN/SAN is "
        "matched against the host.",
    ),
    (
        re.compile(r"supports_credentials\s*=\s*True"),
        "Flask-CORS credentialed wildcard origin",
        Severity.HIGH, "CWE-942", _ACCESS_CAT,
        "Do not combine supports_credentials=True with origins='*'. Echo only origins from an "
        "explicit allowlist.",
    ),
]

_FLASK_CORS_ANY = re.compile(r"origins\s*=\s*[\[\s]*[\"']\*[\"']")
_CORS_LIB = re.compile(r"\bcors\s*\(\s*\{")
_CORS_ORIGIN_ANY = re.compile(r"origin\s*:\s*(?:true|[\"']\*[\"'])")
_CORS_CREDS = re.compile(r"credentials\s*:\s*true")
_ACAO_ANY = re.compile(r"(?i)Access-Control-Allow-Origin[\"']?\s*[,:=]\s*[\"']\*")
_ACAC_TRUE = re.compile(r"(?i)Access-Control-Allow-Credentials[\"']?\s*[,:=]\s*[\"']?true")
_JWT_VERIFY_JS = re.compile(r"\bjwt\.verify\s*\(")
_ALGORITHMS_KEY = re.compile(r"algorithms\s*[:=]")
_HOSTNAME_VERIFIER = re.compile(r"setHostnameVerifier\s*\(")
_RETURN_TRUE = re.compile(r"return\s+true")
_EMPTY_TRUST = re.compile(r"checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.]+\s*)?\{\s*\}")
# The security noun must end the identifier: a trailing \w* would let "mac" swallow machineID
# and macAddress, and "token"/"secret" swallow tokenType/secretName. A prefix is still allowed
# so csrfToken, sessionToken and requestSignature are kept.
_TIMING_CMP = re.compile(
    r"(?i)\b\w*(?:signature|hmac|digest|mac|token|secret|checksum)"
    r"(?:s|_?(?:value|bytes|hash|hex|str|b64))?\b\s*(?:===|!==|==|!=|\.equals\s*\()"
)
_SAFE_CMP = re.compile(
    r"(?i)(compare_digest|timingSafeEqual|MessageDigest\.isEqual|hash_equals|constant_time)"
)
# The right-hand side has to be another runtime value. A quoted literal means a token *type* or
# a secret *name* is being compared, not the secret itself.
_TIMING_RHS = re.compile(r"^\s*[A-Za-z_$@][\w$.]*")
_TRIVIAL_RHS = re.compile(
    r"(?i)^\s*(?:None|null|nil|undefined|true|false|0)\b|^\s*(?:[\"'`]|\d|\)|;|=|$)"
)


def _verification_hits(window: str):
    """Yield (title, severity, confidence, cwe, category, remediation) for one window."""
    for pattern, title, severity, cwe, category, remediation in _VERIFY_RULES:
        if not pattern.search(window):
            continue
        if cwe == "CWE-942" and not _FLASK_CORS_ANY.search(window):
            continue
        yield title, severity, Confidence.MEDIUM, cwe, category, remediation

    if _HOSTNAME_VERIFIER.search(window) and _RETURN_TRUE.search(window):
        yield (
            "Custom HostnameVerifier that accepts every hostname",
            Severity.HIGH, Confidence.MEDIUM, "CWE-295", _CRYPTO_CAT,
            "Delete the custom verifier and rely on the platform default so certificate CN/SAN is "
            "checked against the host being contacted.",
        )
    if _EMPTY_TRUST.search(window):
        yield (
            "Empty checkServerTrusted() trust manager",
            Severity.HIGH, Confidence.MEDIUM, "CWE-295", _CRYPTO_CAT,
            "A trust manager with an empty checkServerTrusted body accepts any certificate. Use the "
            "default TrustManagerFactory, pinned to your CA if needed.",
        )
    if _CORS_LIB.search(window) and _CORS_ORIGIN_ANY.search(window) and _CORS_CREDS.search(window):
        yield (
            "CORS configured with a wildcard/reflected origin and credentials",
            Severity.HIGH, Confidence.MEDIUM, "CWE-942", _ACCESS_CAT,
            "Never combine credentials: true with origin: true or '*'. Validate the Origin header "
            "against an allowlist and echo only matching origins.",
        )
    if _ACAO_ANY.search(window) and _ACAC_TRUE.search(window):
        yield (
            "Access-Control-Allow-Origin: * sent with Allow-Credentials: true",
            Severity.HIGH, Confidence.MEDIUM, "CWE-942", _ACCESS_CAT,
            "Drop the wildcard and echo a validated origin, or stop sending "
            "Access-Control-Allow-Credentials.",
        )
    if _JWT_VERIFY_JS.search(window) and not _ALGORITHMS_KEY.search(window):
        yield (
            "jwt.verify() called without an algorithms allowlist",
            Severity.MEDIUM, Confidence.LOW, "CWE-347", _CRYPTO_CAT,
            "Pass algorithms: ['RS256'] (or your algorithm) to jwt.verify so an attacker cannot "
            "swap the token header to a different algorithm family.",
        )
    if not _SAFE_CMP.search(window):
        for match in _TIMING_CMP.finditer(window):
            rhs = window[match.end():]
            if not _TIMING_RHS.match(rhs) or _TRIVIAL_RHS.match(rhs):
                continue
            yield (
                "Secret or signature compared with a non-constant-time operator",
                Severity.MEDIUM, Confidence.MEDIUM, "CWE-208", _CRYPTO_CAT,
                "Compare secrets with a constant-time helper: hmac.compare_digest, "
                "crypto.timingSafeEqual, MessageDigest.isEqual or hash_equals.",
            )
            break


@register
class AuthVerificationDisabled(Check):
    name = "whitebox.auth_verification_disabled"
    title = "Signature, certificate or origin verification explicitly disabled in code"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for rel, text in _walk(root, _CODE_EXT):
            if emitted >= _CAP:
                return
            if _skip_verification_file(rel, text):
                continue
            rel_posix = rel.replace(os.sep, "/")
            seen: set = set()
            for lineno, window in _windows(text, 3):
                if len(seen) >= _PER_FILE or emitted >= _CAP:
                    break
                for hit in _verification_hits(window):
                    title, severity, confidence, cwe, category, remediation = hit
                    if title in seen:
                        continue
                    seen.add(title)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title="{0} in {1}".format(title, rel_posix),
                        severity=severity,
                        confidence=confidence,
                        category=category,
                        cwe=cwe,
                        description="{0} at {1}:{2}. Turning this verification off removes the only "
                        "thing that distinguishes a genuine peer, token or origin from an "
                        "attacker-supplied one, so anyone able to sit on the path or craft a "
                        "request can impersonate the trusted party. Confidence is MEDIUM because "
                        "static matching cannot prove the code path ships to "
                        "production.".format(title, rel_posix, lineno),
                        remediation=remediation,
                        location="{0}:{1}".format(rel_posix, lineno),
                        evidence=window.strip()[:180],
                        references=_REF_VERIFY,
                    )
                    if len(seen) >= _PER_FILE or emitted >= _CAP:
                        break


# --------------------------------------------------------------------------------------
# whitebox.weak_crypto_usage
# --------------------------------------------------------------------------------------

_ECB = re.compile(
    r"[\"'](?:AES|DES|DESede|Blowfish|RC2)/ECB/|\bMODE_ECB\b"
    r"|createCipheriv\s*\(\s*[\"'][\w-]*-ecb|\bNewECBEncrypter\s*\("
)
_BROKEN_PRIM = re.compile(
    r"(?i)(?:getInstance|createCipher|createDecipher|Cipher\.new)\s*\(\s*"
    r"[\"'](des|desede|3des|rc2|rc4|arcfour|blowfish)\b"
)
_LEGACY_CREATE_CIPHER = re.compile(r"crypto\.createCipher\s*\(|crypto\.createDecipher\s*\(")
_STATIC_IV_JAVA = re.compile(r"IvParameterSpec\s*\(\s*new\s+byte\s*\[\s*\d+\s*\]\s*\)")
_STATIC_IV_LIT = re.compile(
    r"(?i)\biv\s*[:=]\s*(?:b?[\"'][^\"']{4,}[\"']|Buffer\.alloc\s*\(\s*\d+\s*\)"
    r"|bytes\s*\(\s*\d+\s*\))"
)
_CRYPTO_TOKEN = re.compile(
    r"(?i)(createCipheriv|createDecipheriv|Cipher\.|AES\.new|EVP_|crypto\.|cipher|encrypt|decrypt)"
)
_WEAK_RNG = re.compile(
    r"Math\.random\s*\(\s*\)|random\.(?:random|randint|choice)\s*\(|new\s+Random\s*\("
    r"|rand\.(?:Intn|Int)\s*\(|mt_rand\s*\(|uniqid\s*\("
)
# Security nouns. Deliberately excludes reset/verify/invite/coupon: resetForm, verifyEmail and
# inviteLink carry no crypto meaning and are ubiquitous in web code.
_SEC_NAME = (
    r"(?:token|secret|otp|nonce|salt|session|api_?key|apikey|csrf|xsrf|password|passwd|pwd"
    r"|auth_?code|recovery_?code|private_?key|signing_?key|seed)"
)
# `name = <rng>` / `name := <rng>` / `name: Type = <rng>` on the SAME line, up to the RNG call.
_SEC_ASSIGN = re.compile(
    r"(?i)\b\w*" + _SEC_NAME + r"\w*"
    r"(?:\s*:\s*[A-Za-z_][\w<>\[\], .]*)?"
    r"\s*(?::=|=)\s*[^=;]{0,80}$"
)
# `{ token: <rng> }` object/dict literal key, where the RNG is the value.
_SEC_KV = re.compile(r"(?i)\b\w*" + _SEC_NAME + r"\w*[\"']?\s*:\s*$")
# `def make_token(...)` / `function generateSessionId()` / `const newNonce = () =>`.
_SEC_FUNC = re.compile(
    r"(?i)\b(?:def|function|func|fn)\s+\w*" + _SEC_NAME + r"\w*"
    r"|\b(?:const|let|var|val)\s+\w*" + _SEC_NAME + r"\w*\s*=\s*(?:async\s+)?"
    r"(?:function\b|\([^)]*\)\s*=>)"
)
# `random.nextBytes(salt)` — the RNG fills a security-named buffer passed as an argument.
_SEC_ARG = re.compile(r"(?i)\(\s*\w*" + _SEC_NAME + r"\w*\s*[,)\]]")
_TRAILING_COMMENT = re.compile(r"//|/\*|#")
_WEAK_SEED = re.compile(
    r"SecureRandom\s*\(\s*[\"'][^\"']*[\"']\s*\.getBytes|\.setSeed\s*\(\s*\d"
)
_BCRYPT_TOKEN = re.compile(r"(?i)\bbcrypt\b")
_BCRYPT_ROUNDS_KV = re.compile(r"(?i)\b(?:saltRounds|rounds|cost|log_rounds|work_factor)\s*[:=]\s*(\d{1,2})\b")
_BCRYPT_ROUNDS_CALL = re.compile(r"(?i)\b(?:genSaltSync|genSalt|gensalt)\s*\(\s*(\d{1,2})\s*[,)]")
_PBKDF2_TOKEN = re.compile(r"(?i)pbkdf2")
_PBKDF2_KV = re.compile(r"(?i)\b(?:iterations|iteration_count|rounds|count)\s*[:=]\s*(\d+)")
_PBKDF2_PY = re.compile(r"pbkdf2_hmac\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(\d+)")
_PBKDF2_NODE = re.compile(r"pbkdf2(?:Sync)?\s*\(\s*[^,]+,\s*[^,]+,\s*(\d+)")
_SCRYPT_TOKEN = re.compile(r"(?i)scrypt")
_SCRYPT_N = re.compile(r"\bN\s*[:=]\s*(\d+)")


def _as_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _work_factor_hit(window: str) -> Optional[str]:
    if _BCRYPT_TOKEN.search(window):
        for pattern in (_BCRYPT_ROUNDS_KV, _BCRYPT_ROUNDS_CALL):
            match = pattern.search(window)
            value = _as_int(match.group(1)) if match else None
            if value is not None and value <= 10:
                return "bcrypt cost factor {0} (minimum recommended is 12)".format(value)
    if _PBKDF2_TOKEN.search(window):
        for pattern in (_PBKDF2_PY, _PBKDF2_NODE, _PBKDF2_KV):
            match = pattern.search(window)
            value = _as_int(match.group(1)) if match else None
            if value is not None and 0 < value < 10000:
                return "PBKDF2 iteration count {0} (well below current guidance)".format(value)
    if _SCRYPT_TOKEN.search(window):
        match = _SCRYPT_N.search(window)
        value = _as_int(match.group(1)) if match else None
        if value is not None and 0 < value < 16384:
            return "scrypt N={0} (minimum recommended is 16384)".format(value)
    return None


def _rng_security_binding(lines: List[str]) -> bool:
    """True when a weak RNG is lexically bound to a security value in this window.

    Mere co-occurrence of ``Math.random()`` and the word "session" somewhere in the window is
    not enough — jitter/backoff/shard-picking code trips that constantly. The RNG has to be
    assigned to a security-named target on its own line, fill a security-named argument, or sit
    in the body of a function whose name is a security noun.
    """
    declared = False
    for line in lines:
        match = _WEAK_RNG.search(line)
        if match is None:
            declared = declared or bool(_SEC_FUNC.search(line))
            continue
        prefix = line[:match.start()]
        if _SEC_ASSIGN.search(prefix) or _SEC_KV.search(prefix):
            return True
        rest = _TRAILING_COMMENT.split(line[match.end():], 1)[0]
        if _SEC_ARG.search(rest):
            return True
        if declared:
            return True
    return False


def _crypto_hits(window: str, lines: List[str]):
    """Yield (title, severity, cwe, remediation) for one comment-stripped window."""
    if _ECB.search(window):
        yield (
            "Block cipher used in ECB mode",
            Severity.HIGH, "CWE-327",
            "ECB leaks plaintext structure because identical blocks encrypt identically. Use an "
            "authenticated mode such as AES-GCM (or AES-CBC with a random IV plus an HMAC).",
        )
    match = _BROKEN_PRIM.search(window)
    if match:
        yield (
            "Broken cipher primitive ({0}) selected".format(match.group(1).upper()),
            Severity.HIGH, "CWE-327",
            "DES, 3DES, RC2, RC4 and Blowfish are broken or below strength. Migrate to AES-256-GCM "
            "or ChaCha20-Poly1305.",
        )
    if _LEGACY_CREATE_CIPHER.search(window):
        yield (
            "Node crypto.createCipher() derives the key with a weak KDF and a fixed IV",
            Severity.HIGH, "CWE-326",
            "Replace createCipher/createDecipher with createCipheriv/createDecipheriv, a key from a "
            "proper KDF, and a fresh random IV per message.",
        )
    if _STATIC_IV_JAVA.search(window) or (
        _STATIC_IV_LIT.search(window) and _CRYPTO_TOKEN.search(window)
    ):
        yield (
            "Hardcoded or all-zero initialisation vector",
            Severity.HIGH, "CWE-329",
            "Generate a fresh random IV/nonce per encryption (os.urandom, crypto.randomBytes, "
            "SecureRandom) and store it alongside the ciphertext.",
        )
    if _rng_security_binding(lines):
        yield (
            "Non-cryptographic RNG used to mint a security value",
            Severity.HIGH, "CWE-338",
            "Use a CSPRNG for tokens, OTPs, salts, nonces and session ids: secrets.token_urlsafe, "
            "crypto.randomBytes, crypto/rand, random_bytes() or SecureRandom.",
        )
    if _WEAK_SEED.search(window):
        yield (
            "SecureRandom seeded with a fixed value",
            Severity.HIGH, "CWE-336",
            "Never seed SecureRandom from a constant. Construct it with no seed so the platform "
            "entropy source is used.",
        )
    work = _work_factor_hit(window)
    if work:
        yield (
            "Password hashing work factor below current guidance",
            Severity.MEDIUM, "CWE-916",
            "Raise the work factor ({0}) or move to argon2id. Benchmark so hashing takes on the "
            "order of 100ms on production hardware.".format(work),
        )


@register
class WeakCryptoUsage(Check):
    name = "whitebox.weak_crypto_usage"
    title = "Broken cipher mode, hardcoded IV or non-cryptographic RNG for security values"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for rel, text in _walk(root, _CODE_EXT):
            if emitted >= _CAP:
                return
            rel_posix = rel.replace(os.sep, "/")
            mocky = _is_mocky(rel)
            seen: set = set()
            for lineno, chunk in _window_lines(text, 3):
                if len(seen) >= _PER_FILE or emitted >= _CAP:
                    break
                window = " ".join(chunk)
                for title, severity, cwe, remediation in _crypto_hits(window, chunk):
                    if title in seen:
                        continue
                    seen.add(title)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title="{0} in {1}".format(title, rel_posix),
                        severity=_LOWER_SEVERITY[severity] if mocky else severity,
                        confidence=Confidence.LOW if mocky else Confidence.MEDIUM,
                        category=_CRYPTO_CAT,
                        cwe=cwe,
                        description="{0} at {1}:{2}. The surrounding window contains a real crypto "
                        "API call, so this is an actual algorithm/parameter choice rather than a "
                        "mention in prose. Confidence is MEDIUM because static matching cannot "
                        "prove which data this protects{3}.".format(
                            title,
                            rel_posix,
                            lineno,
                            "; the path looks like test/mock/fixture code so it is reported one "
                            "severity lower" if mocky else "",
                        ),
                        remediation=remediation,
                        location="{0}:{1}".format(rel_posix, lineno),
                        evidence=window.strip()[:180],
                        references=_REF_CRYPTO,
                    )
                    if len(seen) >= _PER_FILE or emitted >= _CAP:
                        break
