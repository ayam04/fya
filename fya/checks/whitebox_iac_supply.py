"""Infrastructure-as-code and CI/supply-chain analysis for source targets.

Everything in this module is pure offline text parsing: no docker/terraform/kubectl is
invoked, no network request is made, nothing on disk is written. Files are selected by
basename so extensionless and dot files (Dockerfile, .npmrc, .gitlab-ci.yml) are reachable,
which the extension-driven walker in ``whitebox.py`` cannot do.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import List, Optional, Sequence, Set, Tuple

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .whitebox import _IGNORE_DIRS, _PLACEHOLDER

# ---------------------------------------------------------------------------
# shared constants
# ---------------------------------------------------------------------------

_MISCONFIG = "A05:2021 Security Misconfiguration"
_INTEGRITY = "A08:2021 Software and Data Integrity Failures"
_ACCESS = "A01:2021 Broken Access Control"
_CRYPTO = "A02:2021 Cryptographic Failures"
_AUTHFAIL = "A07:2021 Identification and Authentication Failures"
_LOGGING = "A09:2021 Security Logging and Monitoring Failures"

_MAX_FILE_BYTES = 1_000_000
_MAX_FILES = 4000

# ``whitebox._IGNORE_DIRS`` already covers .git/.terraform/node_modules/vendor/... but its
# walker also drops every dotted directory, which would hide .github, .circleci and .bundle.
_ALLOWED_DOT_DIRS = {".github", ".circleci", ".bundle"}

_TEST_SEGMENTS = {
    "test", "tests", "testing", "testdata", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "e2e", "spec", "specs", "demo", "demos", "__tests__",
}

_SEV_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

_REFS_CIS = ["https://www.cisecurity.org/cis-benchmarks"]
_REFS_K8S = ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
_REFS_TF = ["https://developer.hashicorp.com/terraform/language"]
_REFS_DOCKER = ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"]
_REFS_SUPPLY = ["https://slsa.dev/spec/v1.0/threats"]


def _lower_severity(sev: Severity) -> Severity:
    return _SEV_ORDER[max(0, _SEV_ORDER.index(sev) - 1)]


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:  # different drive on Windows
        return path.replace(os.sep, "/")


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")[:-1]
    return any(part.lower() in _TEST_SEGMENTS for part in parts)


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return None


def _walk_paths(root: str):
    """Yield (fullpath, basename) for every file under root, bounded and dot-dir aware."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in _IGNORE_DIRS and (not d.startswith(".") or d in _ALLOWED_DOT_DIRS)
        ]
        dirnames.sort()
        for name in sorted(filenames):
            yield os.path.join(dirpath, name), name
            count += 1
            if count >= _MAX_FILES:
                return


def _strip_hash_comment_lines(text: str) -> List[Tuple[int, str]]:
    """Return [(1-based lineno, line)] with whole-line '#' comments blanked out."""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        out.append((lineno, "" if line.lstrip().startswith("#") else line.rstrip("\r")))
    return out


def _split_inline_list(raw: str) -> List[str]:
    raw = raw.strip()
    if raw.startswith("["):
        raw = raw[1:]
    if raw.endswith("]"):
        raw = raw[:-1]
    return [item.strip().strip("\"'") for item in raw.split(",") if item.strip()]


def _looks_real_secret(value: str) -> bool:
    value = value.strip().strip("\"'")
    if len(value) < 6:
        return False
    if value.startswith("$") or "${" in value or "{{" in value:
        return False
    return not _PLACEHOLDER.search(value)


# A credential *pointer* names where the secret lives (a mounted file, an ARN, an SSM
# parameter, a vault path). The Docker/Kubernetes secret patterns are built out of exactly
# these, so flagging them would report the recommended practice as a leak.
_POINTER_KEY_SUFFIX = re.compile(
    r"(?i)_(FILE|FILEPATH|PATH|NAME|ARN|URL|URI|ENDPOINT|PARAMETER|LOCATION|REF|SOURCE)$"
)
_POINTER_VALUE = re.compile(
    r"(?i)^(?:[a-z][a-z0-9+.\-]*://|arn:|vault:|projects/[^\s/]+/secrets/|/|\./|\.\./|~/)"
)
_POINTER_FILE_VALUE = re.compile(r"(?i)\.(pem|key|json|txt|env|conf|cfg|ini|ya?ml|crt|p12|pfx)$")


def _is_secret_pointer(key: str, value: str) -> bool:
    """True when key/value names *where* a credential lives instead of holding one."""
    key = key.strip().strip("\"'")
    value = value.strip().strip("\"'")
    if _POINTER_KEY_SUFFIX.search(key):
        return True
    return bool(_POINTER_VALUE.match(value) or _POINTER_FILE_VALUE.search(value))


def _is_literal_secret(key: str, value: str) -> bool:
    """True only when `value` is a credential itself, not a reference to one."""
    return _looks_real_secret(value) and not _is_secret_pointer(key, value)


def _is_private_host(host: str) -> bool:
    host = host.strip().strip("[]").lower()
    if not host:
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}:
        return True
    if host.endswith((".local", ".internal", ".localdomain", ".lan", ".test")):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _host_of(url: str) -> str:
    match = re.match(r"[a-z+]+://([^/\s\"'@]*@)?([^/:\s\"']+)", url, re.IGNORECASE)
    return match.group(2) if match else ""


# ---------------------------------------------------------------------------
# 1. Dockerfile hardening
# ---------------------------------------------------------------------------

_DOCKERFILE_NAME = re.compile(r"(?i)^(dockerfile|containerfile)([._-][\w.-]+)?$")
_NONROOT_IMAGE = re.compile(r"(?i)(distroless|chainguard|nonroot|^scratch$)")
_SECRET_KEY = re.compile(
    r"(?i)(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)"
)
_ADD_REMOTE = re.compile(r"(?i)^ADD\s+(?:--\S+\s+)*https?://")
_FETCH_PIPE_SH = re.compile(
    r"(?i)\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:/bin/|/usr/bin/)?(?:ba|z|k|a)?sh\b"
)
_INSECURE_FETCH = re.compile(
    r"(?i)(--insecure\b|--no-check-certificate\b|--trusted-host\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)"
)
_CURL_K = re.compile(r"(?:^|\s)-[A-Za-z]*k(?=\s|$)")
_CHMOD_777 = re.compile(r"(?i)\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b")


def _is_dockerfile(name: str) -> bool:
    return bool(_DOCKERFILE_NAME.match(name)) or name.lower().endswith(".dockerfile")


def _dockerfile_instructions(text: str) -> List[Tuple[int, str, str]]:
    """Return [(physical lineno, INSTRUCTION, args)] with continuations joined."""
    logical: List[Tuple[int, str]] = []
    buf = ""
    start = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r").rstrip()
        if not buf and line.lstrip().startswith("#"):
            continue
        continues = line.endswith("\\")
        piece = line[:-1] if continues else line
        if not buf:
            start = lineno
            buf = piece.strip()
        elif not piece.lstrip().startswith("#"):
            buf = (buf + " " + piece.strip()).strip()
        if not continues:
            if buf:
                logical.append((start, buf))
            buf = ""
    if buf:
        logical.append((start, buf))

    out = []
    for lineno, body in logical:
        match = re.match(r"^([A-Za-z]+)\s*(.*)$", body)
        if not match:
            continue
        out.append((lineno, match.group(1).upper(), match.group(2).strip()))
    return out


def _parse_from(args: str) -> Tuple[str, Optional[str]]:
    tokens = [tok for tok in args.split() if not tok.startswith("--")]
    if not tokens:
        return "", None
    alias = None
    if len(tokens) >= 3 and tokens[1].lower() == "as":
        alias = tokens[2]
    return tokens[0], alias


def _image_is_floating(image: str) -> bool:
    if "@sha256:" in image or "@sha512:" in image:
        return False
    base = image.split("@")[0]
    slash = base.rfind("/")
    colon = base.rfind(":")
    tag = base[colon + 1:] if colon > slash else ""
    return tag == "" or tag.lower() == "latest"


def _env_pairs(args: str) -> List[Tuple[str, str]]:
    pairs = re.findall(
        r"([A-Za-z_][\w.\-]*)\s*=\s*(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+)", args
    )
    if pairs:
        return [(key, val) for key, val in pairs]
    match = re.match(r"^([A-Za-z_][\w.\-]*)\s+(.+)$", args)
    if match:
        return [(match.group(1), match.group(2))]
    return []


@register
class DockerfileHardening(Check):
    name = "whitebox.dockerfile_hardening"
    title = "Dockerfile builds a root, floating-tag or secret-baked image"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 12

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for path, name in _walk_paths(root):
            if emitted >= self._CAP:
                return
            if not _is_dockerfile(name):
                continue
            text = _read(path)
            if not text:
                continue
            rel = _rel(root, path)
            for finding in self._analyze(rel, text, _is_test_path(rel)):
                yield finding
                emitted += 1
                if emitted >= self._CAP:
                    return

    def _emit(self, rel, lineno, title, severity, confidence, cwe, category, description,
              remediation, evidence, downgrade):
        if downgrade:
            severity = _lower_severity(severity)
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_DOCKER,
        )

    def _analyze(self, rel: str, text: str, low: bool) -> List[Finding]:
        insts = _dockerfile_instructions(text)
        if not insts:
            return []
        from_idx = [i for i, item in enumerate(insts) if item[1] == "FROM"]
        if not from_idx:
            return []

        aliases = set()
        for i in from_idx:
            _, alias = _parse_from(insts[i][2])
            if alias:
                aliases.add(alias.lower())

        final_start = from_idx[-1]
        final = insts[final_start:]
        final_lineno, _, final_args = insts[final_start]
        final_image, _ = _parse_from(final_args)
        out: List[Finding] = []

        # (1) runs as root
        users = [(ln, args.split()[0] if args.split() else "") for ln, ins, args in final if ins == "USER"]
        root_user = (not users) or users[-1][1].split(":")[0].lower() in {"root", "0"}
        image_exempt = (
            final_image.lower() == "scratch"
            or bool(_NONROOT_IMAGE.search(final_image))
        )
        earlier_nonroot = any(
            ins == "USER" and args.split() and args.split()[0].split(":")[0].lower() not in {"root", "0"}
            for _, ins, args in insts[:final_start]
        )
        copies_from_stage = any(
            ins == "COPY" and re.search(r"(?i)--from=", args) for _, ins, args in final
        )
        if root_user and not image_exempt and not (earlier_nonroot and copies_from_stage and not users):
            out.append(self._emit(
                rel, users[-1][0] if users else final_lineno,
                "Container image runs as root in {}".format(rel),
                Severity.MEDIUM, Confidence.MEDIUM, "CWE-250", _MISCONFIG,
                "The final build stage of {} never drops privileges: no USER instruction follows the last "
                "FROM, or the last USER is root. Anything that escapes the process — a deserialisation bug, "
                "a command injection, a vulnerable library — then runs as uid 0 inside the container, which "
                "makes kernel and mount-namespace escapes materially easier.".format(rel),
                "Create an unprivileged account in the image (adduser/useradd) and end the final stage with "
                "`USER app`. Give the account only the directories it must write to.",
                "final stage image: {}".format(final_image or "?"), low,
            ))

        # (2) floating base image
        if (
            final_image
            and final_image.lower() != "scratch"
            and "$" not in final_image
            and final_image.lower() not in aliases
            and _image_is_floating(final_image)
        ):
            out.append(self._emit(
                rel, final_lineno,
                "Base image is not pinned in {}".format(rel),
                Severity.LOW, Confidence.MEDIUM, "CWE-829", _INTEGRITY,
                "The final FROM in {} resolves `{}` at build time with no immutable digest and either no tag "
                "or the :latest tag. The bytes you tested and the bytes you ship can differ, and a compromised "
                "or simply updated upstream tag silently changes the contents of every rebuild.".format(rel, final_image),
                "Pin the base image by digest (`FROM image:tag@sha256:...`) and bump it deliberately with a "
                "tool such as Dependabot or Renovate.",
                "FROM {}".format(final_image), low,
            ))

        for lineno, ins, args in insts:
            full = "{} {}".format(ins, args)

            # (3) ADD from a remote URL
            if ins == "ADD" and _ADD_REMOTE.match(full):
                out.append(self._emit(
                    rel, lineno,
                    "Dockerfile ADDs code from a remote URL in {}".format(rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                    "Line {} of {} pulls a remote URL straight into the image with ADD. ADD does not verify a "
                    "checksum or a signature, so whoever controls that URL (or the network path to it) controls "
                    "the contents of the image layer.".format(lineno, rel),
                    "Download the artifact in a RUN step, verify a pinned sha256 with `sha256sum -c`, and only "
                    "then unpack it. Prefer a package manager with signature verification.",
                    full, low,
                ))

            # (4) secret baked into a layer
            if ins in {"ENV", "ARG"}:
                for key, value in _env_pairs(args):
                    if not _SECRET_KEY.search(key) or not _is_literal_secret(key, value):
                        continue
                    out.append(self._emit(
                        rel, lineno,
                        "Credential baked into an image layer in {}".format(rel),
                        Severity.HIGH, Confidence.MEDIUM, "CWE-798", _AUTHFAIL,
                        "{} sets {} to a literal value at line {}. Both ENV and ARG values are recorded in the "
                        "image metadata and survive in `docker history`, so anyone who can pull the image can "
                        "read the credential even if a later layer deletes it.".format(rel, key, lineno),
                        "Remove the value and rotate it. Inject secrets at run time via the orchestrator, or at "
                        "build time with BuildKit `--mount=type=secret`, which is never persisted in a layer.",
                        "{}={}...".format(key, value.strip("\"'")[:4]), low,
                    ))
                    break

            # (5) unverified fetch-and-exec
            if ins == "RUN":
                insecure = _INSECURE_FETCH.search(args) or (
                    re.search(r"(?i)\bcurl\b", args) and _CURL_K.search(args)
                )
                if _FETCH_PIPE_SH.search(args) or insecure:
                    out.append(self._emit(
                        rel, lineno,
                        "Build step fetches and executes unverified code in {}".format(rel),
                        Severity.MEDIUM, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                        "Line {} of {} downloads a remote script or package and runs it without verifying its "
                        "integrity — either by piping the download straight into a shell, or by disabling "
                        "certificate validation. A network attacker or a compromised host on the other end gets "
                        "code execution inside your build.".format(lineno, rel),
                        "Fetch to a file, verify a pinned checksum or GPG signature, then execute. Never pass "
                        "-k/--insecure/--no-check-certificate; fix the CA bundle instead.",
                        args[:180], low,
                    ))

                # (6) world-writable permissions
                if _CHMOD_777.search(args):
                    out.append(self._emit(
                        rel, lineno,
                        "World-writable permissions set in {}".format(rel),
                        Severity.LOW, Confidence.MEDIUM, "CWE-732", _MISCONFIG,
                        "Line {} of {} chmods a path to 777. Every process in the container, including an "
                        "unprivileged one an attacker lands in, can then overwrite those files — which turns a "
                        "file-write primitive into code execution when the path holds scripts or binaries."
                        .format(lineno, rel),
                        "Grant the narrowest mode that works (typically 0644 for data, 0755 for executables) and "
                        "set ownership with `COPY --chown` instead of loosening permissions.",
                        args[:180], low,
                    ))

        # one finding per rule per file
        seen = set()
        unique = []
        for finding in out:
            if finding.title in seen:
                continue
            seen.add(finding.title)
            unique.append(finding)
        return unique


# ---------------------------------------------------------------------------
# 2. Kubernetes workload security
# ---------------------------------------------------------------------------

_K8S_KIND = re.compile(
    r"^kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Role|ClusterRole|"
    r"RoleBinding|ClusterRoleBinding|NetworkPolicy|PodSecurityPolicy)\b",
    re.MULTILINE,
)
_K8S_APIVERSION = re.compile(r"^apiVersion:\s*\S", re.MULTILINE)
_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
_DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "ALL"}
_HOSTPATH_CRITICAL = {"/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock"}
_HOSTPATH_HIGH = {"/var/lib/kubelet", "/", "/etc", "/proc", "/root", "/var/lib/docker"}


def _split_yaml_docs(numbered: Sequence[Tuple[int, str]]) -> List[List[Tuple[int, str]]]:
    docs: List[List[Tuple[int, str]]] = []
    current: List[Tuple[int, str]] = []
    for lineno, line in numbered:
        if re.match(r"^---\s*$", line):
            if current:
                docs.append(current)
            current = []
            continue
        current.append((lineno, line))
    if current:
        docs.append(current)
    return docs


def _yaml_values(block: Sequence[Tuple[int, str]], key: str) -> List[str]:
    pattern = re.compile(r"^\s*-?\s*" + re.escape(key) + r":\s*(.*)$")
    values: List[str] = []
    for idx, (_lineno, line) in enumerate(block):
        match = pattern.match(line)
        if not match:
            continue
        rest = match.group(1).strip()
        if rest.startswith("["):
            values.extend(_split_inline_list(rest))
        elif rest:
            values.append(rest.strip("\"'"))
        else:
            for _ln2, line2 in block[idx + 1:]:
                stripped = line2.strip()
                if stripped.startswith("-"):
                    values.append(stripped[1:].strip().strip("\"'"))
                elif stripped:
                    break
    return values


def _rbac_rule_blocks(doc: Sequence[Tuple[int, str]]) -> List[List[Tuple[int, str]]]:
    blocks: List[List[Tuple[int, str]]] = []
    index = 0
    total = len(doc)
    while index < total:
        if re.match(r"^rules:\s*$", doc[index][1]):
            index += 1
            item: Optional[List[Tuple[int, str]]] = None
            item_indent: Optional[int] = None
            while index < total:
                lineno, line = doc[index]
                if line.strip():
                    indent = len(line) - len(line.lstrip())
                    if indent == 0:
                        break
                    match = re.match(r"^(\s*)-\s", line)
                    if match and (item_indent is None or len(match.group(1)) == item_indent):
                        if item:
                            blocks.append(item)
                        item_indent = len(match.group(1))
                        item = [(lineno, line)]
                        index += 1
                        continue
                if item is not None:
                    item.append((lineno, line))
                index += 1
            if item:
                blocks.append(item)
            continue
        index += 1
    return blocks


@register
class K8sWorkloadSecurity(Check):
    name = "whitebox.k8s_workload_security"
    title = "Kubernetes manifest grants privileged, host-namespace or wildcard-RBAC access"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 20
    _PER_FILE = 4

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for path, name in _walk_paths(root):
            if emitted >= self._CAP:
                return
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            text = _read(path)
            if not text or "kind:" not in text:
                continue
            rel = _rel(root, path)
            low = _is_test_path(rel)
            per_file = 0
            for finding in self._analyze(rel, text, low):
                yield finding
                emitted += 1
                per_file += 1
                if per_file >= self._PER_FILE or emitted >= self._CAP:
                    break
            if emitted >= self._CAP:
                return

    def _emit(self, rel, lineno, title, severity, confidence, cwe, description, remediation,
              evidence, downgrade):
        if downgrade:
            severity = _lower_severity(severity)
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=_MISCONFIG,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_K8S,
        )

    def _analyze(self, rel: str, text: str, low: bool) -> List[Finding]:
        out: List[Finding] = []
        for doc in _split_yaml_docs(_strip_hash_comment_lines(text)):
            raw = "\n".join(line for _ln, line in doc)
            if not (_K8S_APIVERSION.search(raw) and _K8S_KIND.search(raw)):
                continue
            templated = "{{" in raw
            downgrade = low or templated
            kind_match = _K8S_KIND.search(raw)
            kind = kind_match.group(1) if kind_match else ""
            if templated:
                doc = [(ln, re.sub(r"\{\{.*?\}\}", "", line)) for ln, line in doc]
            out.extend(self._doc_rules(rel, kind, doc, downgrade))
        return out

    def _doc_rules(self, rel, kind, doc, downgrade) -> List[Finding]:
        out: List[Finding] = []
        hostpath_lines: List[int] = []

        for idx, (lineno, line) in enumerate(doc):
            if re.search(r"\bprivileged:\s*true\b", line):
                out.append(self._emit(
                    rel, lineno, "Privileged container in {}".format(rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-250",
                    "{} declares `privileged: true` at line {}. A privileged container keeps all Linux "
                    "capabilities and unrestricted device access, so any code execution inside it is "
                    "equivalent to root on the node.".format(rel, lineno),
                    "Remove `privileged: true`. Grant only the individual capabilities the workload needs "
                    "via securityContext.capabilities.add, and enforce a restricted Pod Security Standard "
                    "on the namespace.",
                    line.strip(), downgrade,
                ))

            host_ns = re.search(r"\b(hostNetwork|hostPID|hostIPC):\s*true\b", line)
            if host_ns:
                field = host_ns.group(1)
                out.append(self._emit(
                    rel, lineno, "Host namespace shared ({}) in {}".format(field, rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-250",
                    "{} sets `{}: true` at line {}. Sharing a host namespace removes the isolation boundary "
                    "between the pod and the node: hostPID exposes and can signal every host process, "
                    "hostNetwork exposes loopback-bound node services and the cloud metadata endpoint, and "
                    "hostIPC exposes shared memory.".format(rel, field, lineno),
                    "Drop the host namespace. If the workload genuinely needs node-level visibility, run it "
                    "as a tightly scoped DaemonSet with its own service account and a restrictive "
                    "NetworkPolicy.",
                    line.strip(), downgrade,
                ))

            if re.search(r"\bhostPath:\s*$", line) or re.search(r"\bhostPath:\s*\{", line):
                hostpath_lines.append(idx)

            if re.search(r"\ballowPrivilegeEscalation:\s*true\b", line):
                out.append(self._emit(
                    rel, lineno, "Privilege escalation allowed in {}".format(rel),
                    Severity.MEDIUM, Confidence.HIGH, "CWE-250",
                    "{} sets `allowPrivilegeEscalation: true` at line {}, so a process in the container can "
                    "gain more privileges than its parent through setuid binaries or file capabilities."
                    .format(rel, lineno),
                    "Set `allowPrivilegeEscalation: false` in the container securityContext and drop all "
                    "capabilities you do not explicitly need.",
                    line.strip(), downgrade,
                ))

            if re.search(r"\brunAsUser:\s*0\s*$", line) or re.search(r"\brunAsNonRoot:\s*false\b", line):
                out.append(self._emit(
                    rel, lineno, "Workload runs as root in {}".format(rel),
                    Severity.MEDIUM, Confidence.HIGH, "CWE-250",
                    "{} explicitly runs the container as uid 0 at line {} (runAsUser: 0 or "
                    "runAsNonRoot: false). Combined with a writable hostPath or a kernel bug this is the "
                    "usual first step of a container escape.".format(rel, lineno),
                    "Set `runAsNonRoot: true` and a non-zero `runAsUser`, and build the image with an "
                    "unprivileged account that owns the paths it must write.",
                    line.strip(), downgrade,
                ))

            if re.search(r"\bautomountServiceAccountToken:\s*true\b", line):
                out.append(self._emit(
                    rel, lineno, "Service account token auto-mounted in {}".format(rel),
                    Severity.LOW, Confidence.MEDIUM, "CWE-250",
                    "{} explicitly enables `automountServiceAccountToken` at line {}. The pod's API "
                    "credentials are then written into every container, so any file-read or SSRF bug in the "
                    "workload hands an attacker the service account's API permissions.".format(rel, lineno),
                    "Set `automountServiceAccountToken: false` unless the workload calls the Kubernetes API, "
                    "and scope the service account's RBAC to the minimum it needs.",
                    line.strip(), downgrade,
                ))

            cap_match = re.match(r"^\s*add:\s*(.*)$", line)
            if cap_match:
                context = " ".join(prev for _n, prev in doc[max(0, idx - 3):idx])
                if "capabilities" in context or "Capabilities" in context:
                    caps = _split_inline_list(cap_match.group(1)) if cap_match.group(1).strip().startswith("[") else []
                    if not caps:
                        for _n2, line2 in doc[idx + 1:]:
                            stripped = line2.strip()
                            if stripped.startswith("-"):
                                caps.append(stripped[1:].strip().strip("\"'"))
                            elif stripped:
                                break
                    risky = sorted({c.upper() for c in caps} & _DANGEROUS_CAPS)
                    if risky:
                        out.append(self._emit(
                            rel, lineno, "Dangerous Linux capability added in {}".format(rel),
                            Severity.HIGH, Confidence.HIGH, "CWE-250",
                            "{} adds {} at line {}. These capabilities are escape primitives: SYS_ADMIN alone "
                            "permits mounting filesystems and writing cgroup release_agent, SYS_MODULE loads "
                            "kernel modules, and SYS_PTRACE lets the container attach to host processes when a "
                            "namespace is shared.".format(rel, ", ".join(risky), lineno),
                            "Drop these capabilities. Start from `drop: [ALL]` and add back only narrow, "
                            "specific capabilities such as NET_BIND_SERVICE.",
                            line.strip(), downgrade,
                        ))

        for idx in hostpath_lines:
            window = doc[idx:idx + 5]
            for lineno, line in window:
                path_match = re.match(r"^\s*path:\s*[\"']?([^\"'\s]+)", line)
                if not path_match:
                    continue
                value = path_match.group(1).rstrip("/") or "/"
                if value in _HOSTPATH_CRITICAL:
                    severity = Severity.CRITICAL
                elif value in _HOSTPATH_HIGH or path_match.group(1) == "/":
                    severity = Severity.HIGH
                else:
                    break
                out.append(self._emit(
                    rel, lineno, "Sensitive hostPath mount ({}) in {}".format(value, rel),
                    severity, Confidence.HIGH, "CWE-732",
                    "{} mounts the node path `{}` into the pod at line {}. Mounting the container runtime "
                    "socket or a sensitive host directory gives the workload direct control of the node: the "
                    "socket alone is enough to start a new privileged container and read every secret the "
                    "node holds.".format(rel, value, lineno),
                    "Remove the hostPath. If the workload really needs node access, use a dedicated, audited "
                    "operator with a narrow read-only mount, and block hostPath volumes with a Pod Security "
                    "admission policy.",
                    line.strip(), downgrade,
                ))
                break

        raw = "\n".join(line for _ln, line in doc)
        first_line = doc[0][0] if doc else 1

        if kind in _WORKLOAD_KINDS and re.search(r"^\s*containers:\s*$", raw, re.MULTILINE):
            if not re.search(r"^\s*limits:\s*$", raw, re.MULTILINE):
                out.append(self._emit(
                    rel, first_line, "Workload declares no resource limits in {}".format(rel),
                    Severity.LOW, Confidence.LOW, "CWE-770",
                    "The {} in {} defines containers with no `limits:` block. Without CPU and memory limits a "
                    "single compromised or looping pod can starve every other workload on the node, turning a "
                    "small bug into a cluster-wide availability incident.".format(kind, rel),
                    "Set requests and limits for cpu and memory on every container, and back them with a "
                    "namespace LimitRange and ResourceQuota.",
                    "kind: {}".format(kind), True,
                ))
            if not re.search(r"securityContext:", raw):
                out.append(self._emit(
                    rel, first_line, "Workload declares no securityContext in {}".format(rel),
                    Severity.LOW, Confidence.LOW, "CWE-250",
                    "The {} in {} has no securityContext at pod or container level, so it inherits the "
                    "defaults: root user, writable root filesystem, privilege escalation permitted and the "
                    "full default capability set.".format(kind, rel),
                    "Add a securityContext with runAsNonRoot, readOnlyRootFilesystem, "
                    "allowPrivilegeEscalation: false and capabilities.drop: [ALL].",
                    "kind: {}".format(kind), True,
                ))

        if kind in {"Role", "ClusterRole"}:
            for block in _rbac_rule_blocks(doc):
                lineno = block[0][0]
                api_groups = _yaml_values(block, "apiGroups")
                resources = _yaml_values(block, "resources")
                verbs = _yaml_values(block, "verbs")
                if ("*" in api_groups or "*" in resources) and "*" in verbs:
                    out.append(self._emit(
                        rel, lineno, "Wildcard RBAC rule in {}".format(rel),
                        Severity.HIGH, Confidence.HIGH, "CWE-269",
                        "The {} in {} grants '*' verbs on '*' resources at line {}. Any subject bound to it "
                        "can read every secret, create privileged pods and escalate to cluster-admin, which "
                        "makes the binding equivalent to full cluster compromise.".format(kind, rel, lineno),
                        "Enumerate the apiGroups, resources and verbs the workload actually calls and list "
                        "them explicitly. Never grant '*' outside a break-glass admin role.",
                        "apiGroups={} resources={} verbs={}".format(api_groups, resources, verbs), downgrade,
                    ))
                elif (
                    kind == "ClusterRole"
                    and "secrets" in [r.lower() for r in resources]
                    and {"get", "list", "watch"} & {v.lower() for v in verbs}
                ):
                    out.append(self._emit(
                        rel, lineno, "ClusterRole can read all secrets in {}".format(rel),
                        Severity.MEDIUM, Confidence.MEDIUM, "CWE-269",
                        "The ClusterRole in {} allows reading Secrets across every namespace at line {}. That "
                        "includes service account tokens, so a subject with this role can impersonate other "
                        "workloads and escalate laterally through the cluster.".format(rel, lineno),
                        "Scope secret access to a namespaced Role, name the individual secrets with "
                        "resourceNames, or move the values to a external secret store with short-lived "
                        "credentials.",
                        "resources={} verbs={}".format(resources, verbs), downgrade,
                    ))
        return out


# ---------------------------------------------------------------------------
# 3. Terraform exposure
# ---------------------------------------------------------------------------

_HCL_HEADER = re.compile(
    r'^[ \t]*(resource|data|variable|module|provider|terraform|output|locals)'
    r'((?:[ \t]+"[^"\n]*"|[ \t]+[A-Za-z0-9_.\-]+)*)[ \t]*\{',
    re.MULTILINE,
)
_SENSITIVE_PORTS = (
    22, 23, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5601, 5672, 5984,
    6379, 8020, 9042, 9092, 9200, 11211, 15672, 27017, 50070,
)
_OPEN_CIDR = re.compile(r'"(?:0\.0\.0\.0/0|::/0)"')
_CRED_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api_?key|access_key|private_key|credential)"
)


def _strip_hcl_comments(text: str) -> str:
    out: List[str] = []
    index = 0
    total = len(text)
    while index < total:
        char = text[index]
        if char == '"':
            out.append(char)
            index += 1
            while index < total:
                if text[index] == "\\" and index + 1 < total:
                    out.append(text[index:index + 2])
                    index += 2
                    continue
                out.append(text[index])
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if char == "#" or text[index:index + 2] == "//":
            newline = text.find("\n", index)
            if newline == -1:
                break
            index = newline
            continue
        if text[index:index + 2] == "/*":
            end = text.find("*/", index + 2)
            chunk = text[index:] if end == -1 else text[index:end + 2]
            out.append(re.sub(r"[^\n]", " ", chunk))
            if end == -1:
                break
            index = end + 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _match_brace(text: str, start: int) -> int:
    depth = 0
    index = start
    total = len(text)
    while index < total:
        char = text[index]
        if char == '"':
            index += 1
            while index < total:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    break
                index += 1
            index += 1
            continue
        if text[index:index + 2] == "<<":
            heredoc = re.match(r"<<-?\s*\"?([A-Za-z_][A-Za-z0-9_]*)\"?", text[index:])
            if heredoc:
                terminator = re.search(
                    r"^\s*" + re.escape(heredoc.group(1)) + r"\s*$",
                    text[index + heredoc.end():],
                    re.MULTILINE,
                )
                if terminator:
                    index += heredoc.end() + terminator.end()
                    continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _hcl_blocks(text: str):
    """Yield (block_type, labels, body, start_lineno) using a brace counter."""
    for match in _HCL_HEADER.finditer(text):
        open_idx = match.end() - 1
        close_idx = _match_brace(text, open_idx)
        if close_idx == -1:
            continue
        labels = [
            quoted or bare
            for quoted, bare in re.findall(r'"([^"]*)"|([A-Za-z0-9_.\-]+)', match.group(2))
        ]
        yield (
            match.group(1),
            labels,
            text[open_idx + 1:close_idx],
            text.count("\n", 0, match.start()) + 1,
        )


_EGRESS_HEADER = re.compile(
    r'^[ \t]*(?:egress\b[^\n{]*|dynamic[ \t]+"egress"[^\n{]*)\{', re.MULTILINE
)
_INGRESS_HEADER = re.compile(
    r'^[ \t]*(?:ingress\b[^\n{]*|dynamic[ \t]+"ingress"[^\n{]*)\{', re.MULTILINE
)
_INGRESS_SIGNAL = re.compile(
    r'(?i)\btype\s*=\s*"ingress"|\bdirection\s*=\s*"(?:Inbound|INGRESS)"|\bsource_ranges\s*='
)
_EGRESS_SIGNAL = re.compile(
    r'(?i)\btype\s*=\s*"egress"|\bdirection\s*=\s*"(?:Outbound|EGRESS)"'
    r'|\bdestination_ranges\s*=|\bdestination_address_prefix'
)


def _blank_span(text: str, start: int, end: int) -> str:
    """Blank out text[start:end], keeping newlines so line numbers stay correct."""
    return text[:start] + re.sub(r"[^\n]", " ", text[start:end]) + text[end:]


def _ingress_candidates(body: str, lname: str, lineno: int) -> List[Tuple[str, int]]:
    """Return [(rule body, lineno)] for the *inbound* rules a firewall resource declares.

    Inline ``egress`` / ``dynamic "egress"`` blocks are blanked out first. A security group
    whose only inline rule is the near-universal allow-all egress block must never be scored
    as if it were ingress, and the resource body is only scanned as a single rule when it
    positively declares itself inbound.
    """
    stripped = body
    while True:
        match = _EGRESS_HEADER.search(stripped)
        if not match:
            break
        close_idx = _match_brace(stripped, match.end() - 1)
        end = len(stripped) if close_idx == -1 else close_idx + 1
        stripped = _blank_span(stripped, match.start(), end)

    candidates: List[Tuple[str, int]] = []
    for match in _INGRESS_HEADER.finditer(stripped):
        close_idx = _match_brace(stripped, match.end() - 1)
        if close_idx == -1:
            continue
        candidates.append(
            (stripped[match.end():close_idx], lineno + stripped.count("\n", 0, match.start()))
        )
    if candidates:
        return candidates
    # Single-rule resources (aws_security_group_rule, aws_vpc_security_group_ingress_rule,
    # google_compute_firewall, azurerm_network_security_rule) carry the rule on the resource
    # body itself, so fall back to it — but only on a positive inbound signal.
    if _EGRESS_SIGNAL.search(stripped) or "egress" in lname:
        return []
    if _INGRESS_SIGNAL.search(stripped) or "ingress" in lname:
        return [(stripped, lineno)]
    return []


def _port_ranges(body: str) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    from_ports = [int(v) for v in re.findall(r"\bfrom_port\s*=\s*(\d+)", body)]
    to_ports = [int(v) for v in re.findall(r"\bto_port\s*=\s*(\d+)", body)]
    for low, high in zip(from_ports, to_ports):
        ranges.append((min(low, high), max(low, high)))
    for raw in re.findall(r"\bports\s*=\s*\[([^\]]*)\]", body):
        for item in _split_inline_list(raw):
            match = re.match(r"^(\d+)(?:-(\d+))?$", item)
            if match:
                low = int(match.group(1))
                high = int(match.group(2) or match.group(1))
                ranges.append((min(low, high), max(low, high)))
    for raw in re.findall(r"\bdestination_port_ranges?\s*=\s*\[?\s*\"([^\"]+)\"", body):
        if raw.strip() == "*":
            ranges.append((0, 65535))
            continue
        match = re.match(r"^(\d+)(?:-(\d+))?$", raw.strip())
        if match:
            low = int(match.group(1))
            high = int(match.group(2) or match.group(1))
            ranges.append((min(low, high), max(low, high)))
    return ranges


_STORAGE_RESOURCE = re.compile(r"(?i)(s3|storage_bucket|storage_account|blob|bucket|gcs)")
_ANY_PRINCIPAL = re.compile(r'"Principal"\s*:\s*(?:"\*"|\{[^}]*"AWS"\s*:\s*(?:"\*"|\[[^\]]*"\*"))')


def _unconditional_public_principal(body: str) -> Optional[str]:
    """Evidence when a policy allows `Principal: *` in a statement that carries no Condition.

    A wildcard principal that is gated by a Condition (aws:SourceArn, aws:SourceVpce,
    kms:CallerAccount, aws:PrincipalOrgID, ...) is the documented way to write account- or
    service-scoped resource policies and is not public, so it must not be reported.
    """
    if not _ANY_PRINCIPAL.search(body) or not re.search(r'"Effect"\s*:\s*"Allow"', body):
        return None
    match = re.search(r"\{[\s\S]*\}", body)
    if match:
        try:
            doc = json.loads(match.group(0))
        except ValueError:
            doc = None
        if isinstance(doc, dict) and "Statement" in doc:
            statements = doc["Statement"]
            if isinstance(statements, dict):
                statements = [statements]
            if not isinstance(statements, list):
                return None
            for stmt in statements:
                if not isinstance(stmt, dict) or stmt.get("Condition"):
                    continue
                if str(stmt.get("Effect", "")).lower() != "allow":
                    continue
                principal = stmt.get("Principal")
                aws = principal.get("AWS") if isinstance(principal, dict) else None
                if principal == "*" or aws == "*" or (isinstance(aws, list) and "*" in aws):
                    return "unconditional Allow to Principal *"
            return None
    if re.search(r'"Condition"\s*:', body):
        return None
    return "unconditional Allow to Principal *"


def _open_ingress_severity(body: str) -> Optional[Tuple[str, List[int]]]:
    """Return (evidence, sensitive ports) when the body opens a risky port to the world."""
    if not _OPEN_CIDR.search(body):
        return None
    if re.search(r"\bprotocol\s*=\s*\"(?:-1|all|\*)\"", body, re.IGNORECASE):
        return ("protocol = \"-1\" (all ports)", list(_SENSITIVE_PORTS[:6]))
    ranges = _port_ranges(body)
    if not ranges:
        return None
    hit = sorted({p for p in _SENSITIVE_PORTS for low, high in ranges if low <= p <= high})
    wide = any(low == 0 and high >= 65535 for low, high in ranges)
    if not hit and not wide:
        # Only web ports (or some other narrow, non-sensitive range) are open: legitimate.
        return None
    evidence = "0.0.0.0/0 -> " + ", ".join(
        "{}-{}".format(low, high) if low != high else str(low) for low, high in ranges[:4]
    )
    return (evidence, hit or [0])


@register
class TerraformExposure(Check):
    name = "whitebox.terraform_exposure"
    title = "Terraform provisions internet-exposed, public or unencrypted infrastructure"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 20
    _PER_FILE = 4

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for path, name in _walk_paths(root):
            if emitted >= self._CAP:
                return
            lowered = name.lower()
            if not lowered.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json")):
                continue
            text = _read(path)
            if not text:
                continue
            rel = _rel(root, path)
            low = _is_test_path(rel)
            per_file = 0
            findings = (
                self._tfvars_rules(rel, text, low)
                if lowered.endswith((".tfvars", ".tfvars.json"))
                else self._hcl_rules(rel, text, low)
            )
            for finding in findings:
                yield finding
                emitted += 1
                per_file += 1
                if per_file >= self._PER_FILE or emitted >= self._CAP:
                    break
            if emitted >= self._CAP:
                return

    def _emit(self, rel, lineno, title, severity, confidence, cwe, category, description,
              remediation, evidence, downgrade):
        if downgrade:
            severity = _lower_severity(severity)
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_TF,
        )

    def _tfvars_rules(self, rel: str, text: str, low: bool) -> List[Finding]:
        out = []
        for lineno, line in _strip_hash_comment_lines(text):
            match = re.match(r'^\s*([A-Za-z_][\w\-]*)\s*=\s*"([^"]+)"\s*$', line)
            if not match or not _CRED_NAME.search(match.group(1)):
                continue
            if not _is_literal_secret(match.group(1), match.group(2)):
                continue
            out.append(self._emit(
                rel, lineno, "Hardcoded credential in Terraform variables ({})".format(rel),
                Severity.HIGH, Confidence.MEDIUM, "CWE-798", _AUTHFAIL,
                "{} assigns a literal value to `{}` at line {}. tfvars files are routinely committed and are "
                "also copied into the state file, so the credential is exposed to everyone with repository or "
                "state-backend read access and must be considered compromised.".format(rel, match.group(1), lineno),
                "Remove the value, rotate the credential, and source it from a secrets manager data source or "
                "a TF_VAR_ environment variable supplied by CI. Add *.tfvars to .gitignore.",
                "{} = \"{}...\"".format(match.group(1), match.group(2)[:4]), low,
            ))
            break
        return out

    def _hcl_rules(self, rel: str, text: str, low: bool) -> List[Finding]:
        out: List[Finding] = []
        clean = _strip_hcl_comments(text)
        for btype, labels, body, lineno in _hcl_blocks(clean):
            label0 = labels[0] if labels else ""
            out.extend(self._block_rules(rel, btype, label0, labels, body, lineno, low))
        return out

    def _block_rules(self, rel, btype, label0, labels, body, lineno, low) -> List[Finding]:
        out: List[Finding] = []
        lname = label0.lower()

        # (1) open ingress
        if btype == "resource" and ("security_group" in lname or "firewall" in lname or "network_security_rule" in lname):
            for sub, sub_line in _ingress_candidates(body, lname, lineno):
                verdict = _open_ingress_severity(sub)
                if not verdict:
                    continue
                evidence, ports = verdict
                out.append(self._emit(
                    rel, sub_line, "Security group opens sensitive ports to the internet in {}".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-284", _ACCESS,
                    "The `{}` block starting at line {} of {} allows inbound traffic from 0.0.0.0/0 (or ::/0) "
                    "to administrative or datastore ports ({}). Anything bound there is reachable from the "
                    "whole internet and will be found by mass scanners within minutes of being "
                    "provisioned.".format(label0, sub_line, rel, ", ".join(str(p) for p in ports[:6]) or "all"),
                    "Restrict the CIDR to the office/VPN range or a peered VPC, put administrative access "
                    "behind a bastion or SSM Session Manager, and keep 0.0.0.0/0 for public web ports only.",
                    evidence, low,
                ))
                break

        # (2) public storage
        if btype == "resource":
            public_evidence = None
            if re.search(r'\bacl\s*=\s*"public-read(?:-write)?"', body):
                public_evidence = "acl = public-read"
            elif re.search(
                r"\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false",
                body,
            ):
                public_evidence = "public access block disabled"
            elif re.search(r'"(?:allUsers|allAuthenticatedUsers)"', body) or re.search(
                r'\bmember\s*=\s*"allUsers"', body
            ):
                public_evidence = "IAM member allUsers"
            elif re.search(r'\bcontainer_access_type\s*=\s*"(?:blob|container)"', body) or re.search(
                r"\ballow_nested_items_to_be_public\s*=\s*true", body
            ):
                public_evidence = "azure public blob access"
            anon_policy = _unconditional_public_principal(body)
            if not public_evidence and anon_policy and _STORAGE_RESOURCE.search(lname):
                public_evidence = anon_policy
            if public_evidence:
                out.append(self._emit(
                    rel, lineno, "Object storage is publicly readable in {}".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-732", _ACCESS,
                    "The `{}` resource at line {} of {} exposes its contents to anonymous callers ({}). Public "
                    "buckets are enumerated continuously by third parties and are one of the most common "
                    "sources of large-scale data exposure.".format(label0, lineno, rel, public_evidence),
                    "Set the bucket to private, enable all four S3 public access block settings (or the cloud "
                    "equivalent), and serve public objects through a CDN with signed URLs.",
                    public_evidence, low,
                ))
            elif anon_policy:
                out.append(self._emit(
                    rel, lineno, "Resource policy grants access to every AWS principal in {}".format(rel),
                    Severity.MEDIUM, Confidence.LOW, "CWE-732", _ACCESS,
                    "The `{}` resource at line {} of {} attaches a policy statement that allows `Principal: *` "
                    "with no Condition block, so any AWS account — not only yours — can call the listed "
                    "actions. Statements that are scoped with a condition such as aws:SourceArn, "
                    "aws:SourceVpce or kms:CallerAccount are not reported.".format(label0, lineno, rel),
                    "Name the principals explicitly, or keep the wildcard and add a Condition that pins the "
                    "caller (aws:PrincipalOrgID, aws:SourceArn, aws:SourceVpce, kms:CallerAccount).",
                    anon_policy, low,
                ))

            # (3) publicly accessible database
            if re.search(r"\bpublicly_accessible\s*=\s*true", body) and (
                "db_instance" in lname or "rds" in lname or "redshift" in lname or "cluster" in lname
            ):
                out.append(self._emit(
                    rel, lineno, "Database is publicly accessible in {}".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-284", _ACCESS,
                    "The `{}` resource at line {} of {} sets `publicly_accessible = true`, giving the database "
                    "instance a public IP. The only remaining control is the security group and the database "
                    "password, so a weak credential or a single over-broad rule exposes the whole "
                    "dataset.".format(label0, lineno, rel),
                    "Set `publicly_accessible = false`, place the instance in private subnets, and reach it "
                    "through a bastion, VPN or VPC peering.",
                    "publicly_accessible = true", low,
                ))

            # (4) encryption
            enc_off = re.search(
                r"\b(storage_encrypted|encrypted|encryption_enabled|enable_encryption|"
                r"encrypt_at_rest|kms_encrypted|at_rest_encryption_enabled)\s*=\s*false",
                body,
            )
            if enc_off:
                out.append(self._emit(
                    rel, lineno, "Encryption at rest explicitly disabled in {}".format(rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-311", _CRYPTO,
                    "The `{}` resource at line {} of {} sets `{} = false`, so the underlying volume or "
                    "datastore is written unencrypted. Snapshots, backups and decommissioned disks then carry "
                    "readable data outside your access-control boundary.".format(
                        label0, lineno, rel, enc_off.group(1)),
                    "Enable encryption at rest with a customer-managed KMS key. For existing resources, "
                    "encryption usually requires a snapshot-and-restore, so plan the migration.",
                    enc_off.group(0), low,
                ))
            elif lname in {"aws_db_instance", "aws_rds_cluster", "aws_ebs_volume"} and not re.search(
                r"\b(storage_encrypted|encrypted)\s*=", body
            ):
                out.append(self._emit(
                    rel, lineno, "Encryption at rest not declared in {}".format(rel),
                    Severity.LOW, Confidence.LOW, "CWE-311", _CRYPTO,
                    "The `{}` resource at line {} of {} does not declare encryption at rest. Provider defaults "
                    "for this attribute have changed between versions, so the resource may or may not be "
                    "encrypted depending on the provider pin — which is itself the problem.".format(
                        label0, lineno, rel),
                    "Set `storage_encrypted = true` (or `encrypted = true`) explicitly and reference a KMS key "
                    "so the intent is recorded in code rather than inherited from a default.",
                    "no encryption attribute in {}".format(label0), True,
                ))

            # (8) audit logging off
            log_off = re.search(
                r"\b(enable_logging|logging_enabled|enable_log_file_validation|audit_logs_enabled|"
                r"enable_flow_logs)\s*=\s*false",
                body,
            )
            if log_off:
                out.append(self._emit(
                    rel, lineno, "Audit logging disabled in {}".format(rel),
                    Severity.LOW, Confidence.MEDIUM, "CWE-778", _LOGGING,
                    "The `{}` resource at line {} of {} sets `{} = false`. Without these logs there is no "
                    "record of who called what, so an intrusion cannot be scoped or proven after the "
                    "fact.".format(label0, lineno, rel, log_off.group(1)),
                    "Enable logging, ship it to a separate, append-only account or project, and alert on "
                    "configuration changes to the logging resource itself.",
                    log_off.group(0), low,
                ))

        # (5) IAM wildcard
        if btype in {"resource", "data"} and ("iam" in lname or "policy" in lname):
            action_star = re.search(r'(?:"Action"|actions)\s*[:=]\s*(?:"\*"|\[\s*"\*"\s*,?\s*\])', body)
            resource_star = re.search(r'(?:"Resource"|resources)\s*[:=]\s*(?:"\*"|\[\s*"\*"\s*,?\s*\])', body)
            allow = re.search(r'(?:"Effect"\s*:\s*"Allow"|effect\s*=\s*"Allow")', body)
            has_effect = re.search(r'(?:"Effect"|effect)\s*[:=]', body)
            if action_star and resource_star and (allow or not has_effect):
                out.append(self._emit(
                    rel, lineno, "IAM policy grants '*' on '*' in {}".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-269", _ACCESS,
                    "The `{}` block at line {} of {} allows every action on every resource. Any principal "
                    "attached to this policy — including a compromised CI runner or an application role reached "
                    "through SSRF — holds full control of the account.".format(label0 or btype, lineno, rel),
                    "Replace the wildcards with the specific actions and resource ARNs the workload calls. "
                    "Generate the list from CloudTrail/Access Analyzer rather than guessing.",
                    "Action=* Resource=*", low,
                ))

        # (6) hardcoded credential in a variable default
        if btype == "variable" and _CRED_NAME.search(label0):
            default = re.search(r'\bdefault\s*=\s*"([^"]+)"', body)
            if default and _is_literal_secret(label0, default.group(1)):
                out.append(self._emit(
                    rel, lineno, "Hardcoded credential in Terraform variable default ({})".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-798", _AUTHFAIL,
                    "Variable `{}` in {} carries a literal default value at line {}. The value is committed to "
                    "the repository and copied verbatim into the Terraform state, so it is readable by "
                    "everyone with repo or state access.".format(label0, rel, lineno),
                    "Drop the default, mark the variable `sensitive = true`, and supply the value from a "
                    "secrets manager data source or a TF_VAR_ environment variable in CI. Rotate the current "
                    "value.",
                    "default = \"{}...\"".format(default.group(1)[:4]), low,
                ))

        # (7) unencrypted remote state backend
        if btype == "terraform":
            for match in re.finditer(r'^[ \t]*backend\s+"s3"[^\n{]*\{', body, re.MULTILINE):
                open_idx = match.end() - 1
                close_idx = _match_brace(body, open_idx)
                sub = body[open_idx + 1:close_idx] if close_idx != -1 else ""
                offset = body.count("\n", 0, match.start())
                if not re.search(r"\bencrypt\s*=\s*true", sub):
                    out.append(self._emit(
                        rel, lineno + offset, "Terraform S3 state backend is unencrypted in {}".format(rel),
                        Severity.LOW, Confidence.MEDIUM, "CWE-311", _CRYPTO,
                        "The S3 backend declared at line {} of {} does not set `encrypt = true`. Terraform "
                        "state contains every generated password, key and connection string in plaintext, so "
                        "the bucket is one of the most sensitive artefacts in the "
                        "estate.".format(lineno + offset, rel),
                        "Set `encrypt = true`, point `kms_key_id` at a customer-managed key, and enable bucket "
                        "versioning plus a strict bucket policy on the state bucket.",
                        "backend \"s3\" without encrypt = true", low,
                    ))
                break
        return out


# ---------------------------------------------------------------------------
# 4. docker-compose hardening
# ---------------------------------------------------------------------------

_COMPOSE_NAME = re.compile(r"(?i)^(docker-)?compose([.-][\w.-]+)?\.ya?ml$")
_DATASTORE_PORTS = {
    1433, 2375, 2376, 3306, 5432, 5672, 6379, 9042, 9092, 9200, 11211, 15672, 27017, 50070,
}
_COMPOSE_SECRET_KEY = re.compile(r"(?i)^(.*_)?(PASSWORD|SECRET|TOKEN|API_?KEY|ROOT_PASSWORD)(_.*)?$")
_LOCAL_IFACES = {"127.0.0.1", "::1", "localhost", "[::1]"}


def _compose_services(numbered: Sequence[Tuple[int, str]]):
    """Yield (service_name, header_lineno, [(lineno, line)]) segmented by indentation."""
    start = None
    for index, (_lineno, line) in enumerate(numbered):
        if re.match(r"^services:\s*$", line):
            start = index + 1
            break
    if start is None:
        return
    svc_indent: Optional[int] = None
    index = start
    total = len(numbered)
    while index < total:
        lineno, line = numbered[index]
        if not line.strip():
            index += 1
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            break
        match = re.match(r"^(\s{2,4})([\w.\-]+):\s*$", line)
        if match and (svc_indent is None or len(match.group(1)) == svc_indent):
            svc_indent = len(match.group(1))
            body = []
            cursor = index + 1
            while cursor < total:
                lineno2, line2 = numbered[cursor]
                if line2.strip():
                    if len(line2) - len(line2.lstrip()) <= svc_indent:
                        break
                    body.append((lineno2, line2))
                cursor += 1
            yield match.group(2), lineno, body
            index = cursor
            continue
        index += 1


def _subblock_entries(body: Sequence[Tuple[int, str]], key: str) -> List[Tuple[int, str]]:
    """Return [(lineno, entry)] for the list/map under `key:` inside a service body."""
    pattern = re.compile(r"^(\s*)" + re.escape(key) + r":\s*(.*)$")
    out: List[Tuple[int, str]] = []
    index = 0
    total = len(body)
    while index < total:
        lineno, line = body[index]
        match = pattern.match(line)
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        inline = match.group(2).strip()
        if inline.startswith("["):
            for item in _split_inline_list(inline):
                out.append((lineno, item))
            index += 1
            continue
        cursor = index + 1
        while cursor < total:
            lineno2, line2 = body[cursor]
            if line2.strip():
                if len(line2) - len(line2.lstrip()) <= indent:
                    break
                entry = line2.strip()
                if entry.startswith("-"):
                    entry = entry[1:].strip()
                out.append((lineno2, entry.strip("\"'")))
            cursor += 1
        index = cursor
    return out


def _parse_port_entry(entry: str) -> Optional[Tuple[str, int]]:
    entry = entry.strip().strip("\"'")
    if not entry or entry.startswith("$"):
        return None
    entry = entry.split("/")[0]
    parts = entry.split(":")
    try:
        container_raw = parts[-1].split("-")[0]
        container = int(container_raw)
    except ValueError:
        return None
    iface = ":".join(parts[:-2]) if len(parts) >= 3 else ""
    return iface, container


@register
class ComposeHardening(Check):
    name = "whitebox.compose_hardening"
    title = "docker-compose service is privileged, mounts the docker socket, or exposes a datastore"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 15
    _PER_FILE = 4

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for path, name in _walk_paths(root):
            if emitted >= self._CAP:
                return
            if not _COMPOSE_NAME.match(name):
                continue
            text = _read(path)
            if not text:
                continue
            numbered = _strip_hash_comment_lines(text)
            joined = "\n".join(line for _ln, line in numbered)
            if not re.search(r"^services:\s*$", joined, re.MULTILINE):
                continue
            if re.search(r"^kind:\s", joined, re.MULTILINE):
                continue
            rel = _rel(root, path)
            low = _is_test_path(rel) or bool(re.search(r"(?i)\.(test|ci|dev|local)\.", name))
            per_file = 0
            for finding in self._analyze(rel, numbered, low):
                yield finding
                emitted += 1
                per_file += 1
                if per_file >= self._PER_FILE or emitted >= self._CAP:
                    break
            if emitted >= self._CAP:
                return

    def _emit(self, rel, lineno, title, severity, confidence, cwe, category, description,
              remediation, evidence, downgrade):
        if downgrade:
            severity = _lower_severity(severity)
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_CIS,
        )

    def _analyze(self, rel, numbered, low) -> List[Finding]:
        out: List[Finding] = []
        for service, header_line, body in _compose_services(numbered):
            out.extend(self._service_rules(rel, service, header_line, body, low))
        return out

    def _service_rules(self, rel, service, header_line, body, low) -> List[Finding]:
        out: List[Finding] = []

        for lineno, line in body:
            if re.search(r"^\s*privileged:\s*true\s*$", line):
                out.append(self._emit(
                    rel, lineno, "Compose service '{}' runs privileged in {}".format(service, rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-250", _MISCONFIG,
                    "Service `{}` in {} sets `privileged: true` at line {}. The container keeps every Linux "
                    "capability and raw device access, so code execution inside it is effectively root on the "
                    "host.".format(service, rel, lineno),
                    "Remove `privileged: true` and grant only the specific capabilities or device mappings the "
                    "service needs.",
                    line.strip(), low,
                ))
            host_ns = re.search(r"^\s*(pid|ipc|userns_mode):\s*[\"']?host[\"']?\s*$", line)
            if host_ns:
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' shares the host {} namespace in {}".format(service, host_ns.group(1), rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-668", _MISCONFIG,
                    "Service `{}` in {} sets `{}: host` at line {}, removing the namespace boundary with the "
                    "host. With host PID the container can see and signal every host process and read their "
                    "memory; with host IPC it shares System V shared memory with the host."
                    .format(service, rel, host_ns.group(1), lineno),
                    "Remove the host namespace setting. If a diagnostic tool genuinely needs it, run that tool "
                    "ad hoc rather than shipping it in the stack.",
                    line.strip(), low,
                ))
            if re.search(r"^\s*network_mode:\s*[\"']?host[\"']?\s*$", line):
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' uses host networking in {}".format(service, rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-668", _MISCONFIG,
                    "Service `{}` in {} runs with `network_mode: host` at line {}. The container shares the "
                    "host network stack, so every port it opens is published on all host interfaces and it can "
                    "reach services the host binds to loopback.".format(service, rel, lineno),
                    "Use the default bridge network and publish only the ports you need, bound to 127.0.0.1 "
                    "where the service is not meant to be public.",
                    line.strip(), low,
                ))
            if re.search(r"^\s*user:\s*[\"']?(root|0)[\"']?\s*$", line):
                out.append(self._emit(
                    rel, lineno, "Compose service '{}' runs as root in {}".format(service, rel),
                    Severity.LOW, Confidence.MEDIUM, "CWE-250", _MISCONFIG,
                    "Service `{}` in {} pins `user: root` at line {}. Any process compromise inside the "
                    "container starts from uid 0, which removes a useful layer of defence against escapes and "
                    "against writes through bind mounts.".format(service, rel, lineno),
                    "Run the service as a dedicated unprivileged uid and chown the volumes it needs to write.",
                    line.strip(), low,
                ))

        for lineno, entry in _subblock_entries(body, "volumes"):
            source = entry.split(":")[0].strip()
            if "/var/run/docker.sock" in entry or "/run/docker.sock" in entry:
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' mounts the Docker socket in {}".format(service, rel),
                    Severity.CRITICAL, Confidence.HIGH, "CWE-250", _MISCONFIG,
                    "Service `{}` in {} bind-mounts the Docker socket at line {}. Anyone who executes code in "
                    "that container can ask the daemon to start a new privileged container with the host root "
                    "filesystem mounted, which is a complete, one-step host takeover."
                    .format(service, rel, lineno),
                    "Remove the socket mount. If the service must orchestrate containers, put a filtering "
                    "proxy such as docker-socket-proxy in front of the API and allow only the endpoints it "
                    "needs, read-only.",
                    entry[:120], low,
                ))
            elif source == "/" or entry.startswith("/:"):
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' bind-mounts the whole host filesystem in {}".format(service, rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-732", _MISCONFIG,
                    "Service `{}` in {} mounts `/` from the host at line {}. The container can read every "
                    "secret on the machine and, unless the mount is read-only, write to /etc, cron "
                    "directories and systemd units.".format(service, rel, lineno),
                    "Mount only the specific directories the service needs, read-only wherever possible.",
                    entry[:120], low,
                ))

        caps = {c.upper() for _ln, c in _subblock_entries(body, "cap_add")}
        risky = sorted(caps & {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"})
        if risky:
            lineno = next((ln for ln, c in _subblock_entries(body, "cap_add") if c.upper() in risky), header_line)
            out.append(self._emit(
                rel, lineno,
                "Compose service '{}' adds escape-capable Linux capabilities in {}".format(service, rel),
                Severity.HIGH, Confidence.MEDIUM, "CWE-250", _MISCONFIG,
                "Service `{}` in {} adds {}. These capabilities are container-escape primitives: SYS_ADMIN "
                "permits mounts and cgroup release_agent writes, SYS_MODULE loads kernel modules and "
                "SYS_PTRACE attaches to other processes.".format(service, rel, ", ".join(risky)),
                "Drop these capabilities. Start from `cap_drop: [ALL]` and add back only narrow ones such as "
                "NET_BIND_SERVICE.",
                "cap_add: {}".format(", ".join(risky)), low,
            ))

        for lineno, entry in _subblock_entries(body, "security_opt"):
            if re.search(r"(?i)(seccomp|apparmor)\s*[:=]\s*unconfined", entry):
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' disables the seccomp/AppArmor profile in {}".format(service, rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-250", _MISCONFIG,
                    "Service `{}` in {} sets `{}` at line {}. The default seccomp profile blocks roughly 40 "
                    "dangerous syscalls; turning it off re-enables the syscall surface most container escapes "
                    "are built on.".format(service, rel, entry, lineno),
                    "Remove the unconfined setting. If one syscall is genuinely required, ship a custom "
                    "seccomp profile that allows exactly that call.",
                    entry[:120], low,
                ))
                break

        for lineno, entry in _subblock_entries(body, "ports"):
            parsed = _parse_port_entry(entry)
            if not parsed:
                continue
            iface, container = parsed
            if container not in _DATASTORE_PORTS:
                continue
            if iface and iface.strip("[]") in {i.strip("[]") for i in _LOCAL_IFACES}:
                continue
            out.append(self._emit(
                rel, lineno,
                "Compose service '{}' publishes datastore port {} on all interfaces in {}".format(
                    service, container, rel),
                Severity.HIGH, Confidence.MEDIUM, "CWE-668", _MISCONFIG,
                "Service `{}` in {} publishes container port {} at line {} without binding the host side to "
                "loopback. Docker inserts its own iptables rules ahead of most host firewalls, so on a "
                "non-laptop host this database or admin interface is reachable from the network."
                .format(service, rel, container, lineno),
                "Bind the published port to loopback (`127.0.0.1:{0}:{0}`), or drop the `ports:` entry "
                "entirely and let other services reach it over the internal compose network.".format(container),
                entry[:120], low,
            ))
            break

        env_entries = _subblock_entries(body, "environment") + _subblock_entries(body, "env")
        for lineno, entry in env_entries:
            if "=" in entry:
                key, _sep, value = entry.partition("=")
            elif ":" in entry:
                key, _sep, value = entry.partition(":")
            else:
                continue
            key = key.strip().strip("\"'")
            value = value.strip().strip("\"'")
            upper = key.upper()
            if upper in {"MYSQL_ALLOW_EMPTY_PASSWORD", "ALLOW_EMPTY_PASSWORD", "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD"} \
                    and value.lower() in {"yes", "true", "1"}:
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' disables database authentication in {}".format(service, rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-1188", _AUTHFAIL,
                    "Service `{}` in {} sets `{}` at line {}, which starts the database with an empty root "
                    "password. Combined with any published port this is an unauthenticated database on the "
                    "network.".format(service, rel, key, lineno),
                    "Remove the flag and supply a strong password from a secret or an env file that is not "
                    "committed.",
                    entry[:120], low,
                ))
                break
            if upper == "POSTGRES_HOST_AUTH_METHOD" and value.lower() == "trust":
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' disables PostgreSQL authentication in {}".format(service, rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-1188", _AUTHFAIL,
                    "Service `{}` in {} sets `POSTGRES_HOST_AUTH_METHOD=trust` at line {}. PostgreSQL then "
                    "accepts any connection as any user with no password at all.".format(service, rel, lineno),
                    "Remove the setting and configure scram-sha-256 with a real password supplied through a "
                    "secret.",
                    entry[:120], low,
                ))
                break
            if _COMPOSE_SECRET_KEY.match(upper) and _is_literal_secret(key, value):
                out.append(self._emit(
                    rel, lineno,
                    "Compose service '{}' hardcodes a credential in {}".format(service, rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-798", _AUTHFAIL,
                    "Service `{}` in {} sets `{}` to a literal value at line {}. The credential is committed "
                    "to the repository, visible in `docker inspect` and in the process environment of every "
                    "process in the container.".format(service, rel, key, lineno),
                    "Move the value to an uncommitted .env file or a Docker secret, reference it as "
                    "${{{}}}, and rotate the current value.".format(key),
                    "{}={}...".format(key, value[:4]), low,
                ))
                break
        return out


# ---------------------------------------------------------------------------
# 5. CI/CD supply chain
# ---------------------------------------------------------------------------

_USES = re.compile(r"^\s*-?\s*uses:\s*[\"']?([^\s\"'#]+)")
_BRANCH_REFS = {"main", "master", "develop", "dev", "latest", "head", "trunk"}
_FIRST_PARTY_OWNERS = {"actions", "github"}
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SECRET_ECHO = re.compile(r"(?i)\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.")
# Consumers that deliberately move a secret *out* of the log: piping it into a login command,
# masking it, or writing it to a file or to $GITHUB_ENV.
_SECRET_SINK = re.compile(
    r"(?i)(--password-stdin|--with-token|--token-stdin|::add-mask::|--stdin\b"
    r"|\$GITHUB_ENV|\$GITHUB_OUTPUT|\$GITHUB_STATE|\$GITHUB_PATH)"
)
_CURL_PIPE_SH = re.compile(r"(?i)\b(?:curl|wget)\b[^|\n;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
_UNTRUSTED_CI_VARS = (
    "CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_DESCRIPTION|CI_COMMIT_REF_NAME|"
    "CI_COMMIT_BRANCH|CI_COMMIT_TAG|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|"
    "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
)
# GitLab exports these as ordinary environment variables and writes the script verbatim, so a
# plain `$CI_COMMIT_REF_NAME` is a shell parameter expansion, not a textual substitution, and
# cannot inject a command. It only becomes injection where the value is re-evaluated.
_GITLAB_REEVAL = re.compile(
    r"(?:\beval\b[^\n]*|`[^`\n]*|\$\([^)\n]*|\b(?:ba|z|k)?sh[ \t]+-c[ \t][^\n]*"
    r"|\bssh\b[^\n]*|\bawk\b[^\n]*|\bxargs\b[^\n]*)"
    r"\$\{?(" + _UNTRUSTED_CI_VARS + r")\}?"
)


def _secret_reaches_log(line: str) -> bool:
    """True when an echoed `secrets.*` expression actually lands in the build log."""
    match = _SECRET_ECHO.search(line)
    if not match:
        return False
    if _SECRET_SINK.search(line):
        return False
    # A pipe or a redirection after the expression sends the value somewhere else.
    return not re.search(r"[|>]", line[match.end():])


def _workflow_triggers(numbered: Sequence[Tuple[int, str]]) -> Set[str]:
    """Return the event names declared by the workflow's top-level `on:` key."""
    triggers: Set[str] = set()
    total = len(numbered)
    for index in range(total):
        match = re.match(r"^[\"']?on[\"']?\s*:\s*(.*)$", numbered[index][1])
        if not match:
            continue
        rest = match.group(1).strip()
        if rest.startswith("["):
            triggers.update(item.lower() for item in _split_inline_list(rest))
        elif rest:
            triggers.add(rest.strip("\"'").lower())
        else:
            event_indent: Optional[int] = None
            for _ln, line in numbered[index + 1:]:
                if not line.strip():
                    continue
                indent = len(line) - len(line.lstrip())
                if indent == 0:
                    break
                if event_indent is None:
                    event_indent = indent
                if indent != event_indent:
                    continue
                key = re.match(r"^\s*-?\s*[\"']?([\w-]+)[\"']?\s*:?\s*$", line)
                if key:
                    triggers.add(key.group(1).lower())
        break
    return triggers
_ROOT_CI_FILES = {
    ".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml", "jenkinsfile",
}


@register
class ActionsSupplyChain(Check):
    name = "whitebox.actions_supply_chain"
    title = "CI pipeline consumes unpinned actions or runs privileged on untrusted input"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 20

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        owner = self._repo_owner(root)
        emitted = 0
        seen_actions: Set[Tuple[str, str]] = set()
        for path, rel in self._ci_files(root):
            if emitted >= self._CAP:
                return
            text = _read(path)
            if not text:
                continue
            numbered = _strip_hash_comment_lines(text)
            low = _is_test_path(rel)
            for finding in self._analyze(rel, numbered, owner, seen_actions, low):
                yield finding
                emitted += 1
                if emitted >= self._CAP:
                    return

    @staticmethod
    def _repo_owner(root: str) -> Optional[str]:
        text = _read(os.path.join(root, ".git", "config"))
        if not text:
            return None
        match = re.search(r"url\s*=\s*\S*?(?:github\.com|gitlab\.com)[:/]([\w.\-]+)/", text)
        return match.group(1).lower() if match else None

    def _ci_files(self, root: str) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for path, name in _walk_paths(root):
            rel = _rel(root, path)
            lowered = name.lower()
            parts = rel.lower().split("/")
            if parts[:2] == [".github", "workflows"] and lowered.endswith((".yml", ".yaml")):
                out.append((path, rel))
            elif parts[:2] == [".github", "actions"] and lowered in {"action.yml", "action.yaml"}:
                out.append((path, rel))
            elif parts[:1] == [".circleci"] and lowered in {"config.yml", "config.yaml"}:
                out.append((path, rel))
            elif len(parts) == 1 and lowered in _ROOT_CI_FILES:
                out.append((path, rel))
        return out

    def _emit(self, rel, lineno, title, severity, confidence, cwe, category, description,
              remediation, evidence, downgrade):
        if downgrade:
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_SUPPLY,
        )

    def _analyze(self, rel, numbered, owner, seen_actions, low) -> List[Finding]:
        out: List[Finding] = []
        joined = "\n".join(line for _ln, line in numbered)
        is_gitlab = os.path.basename(rel).lower().startswith(".gitlab-ci")
        third_party = False

        for lineno, line in numbered:
            match = _USES.match(line)
            if match:
                ref_spec = match.group(1)
                if self._is_third_party(ref_spec, owner):
                    third_party = True
                verdict = self._classify_uses(ref_spec, owner)
                if verdict:
                    slug, ref, severity = verdict
                    if (slug, ref) not in seen_actions:
                        seen_actions.add((slug, ref))
                        out.append(self._emit(
                            rel, lineno,
                            "Third-party action '{}' is not pinned in {}".format(slug, rel),
                            severity, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                            "{} consumes `{}@{}` at line {}. Tags and branches are mutable, so the owner of "
                            "that repository (or anyone who compromises it) can change the code your pipeline "
                            "executes with your secrets, retroactively and without a commit in your "
                            "repo.".format(rel, slug, ref, lineno),
                            "Pin third-party actions to a full 40-character commit SHA and keep the "
                            "human-readable version in a trailing comment. Let Dependabot bump the SHA.",
                            "uses: {}".format(ref_spec), low,
                        ))

            if re.search(r"^\s*permissions:\s*write-all\s*$", line):
                out.append(self._emit(
                    rel, lineno, "GITHUB_TOKEN granted write-all in {}".format(rel),
                    Severity.MEDIUM, Confidence.HIGH, "CWE-732", _MISCONFIG,
                    "{} sets `permissions: write-all` at line {}, so every step — including third-party "
                    "actions — receives a token that can push commits, publish releases and edit workflow "
                    "files. One malicious dependency in the job is enough to backdoor the "
                    "repository.".format(rel, lineno),
                    "Declare least-privilege permissions at workflow level (`permissions: {contents: read}`) "
                    "and widen them only on the specific job that needs it.",
                    line.strip(), low,
                ))

            if re.search(r"(?i)ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*[\"']?(true|1)", line):
                out.append(self._emit(
                    rel, lineno, "Unsecure workflow commands re-enabled in {}".format(rel),
                    Severity.HIGH, Confidence.HIGH, "CWE-94", _INTEGRITY,
                    "{} sets ACTIONS_ALLOW_UNSECURE_COMMANDS at line {}. This restores the deprecated "
                    "`::set-env::`/`::add-path::` workflow commands, which let any string a step prints to "
                    "stdout modify the runner's environment and PATH — a straightforward path from "
                    "'log an untrusted value' to code execution.".format(rel, lineno),
                    "Remove the variable and migrate the steps to $GITHUB_ENV / $GITHUB_PATH, sanitising any "
                    "untrusted value before writing it.",
                    line.strip(), low,
                ))

            if _secret_reaches_log(line):
                out.append(self._emit(
                    rel, lineno, "Workflow prints a secret to the build log in {}".format(rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-532", _LOGGING,
                    "{} echoes a `secrets.*` expression at line {}. Masking in Actions is best-effort and is "
                    "defeated by any transformation (base64, json, splitting), so the value can end up "
                    "readable in a log that anyone with repo read access can download.".format(rel, lineno),
                    "Never print secrets. Pass them through `env:` and let the tool read them from the "
                    "environment; if you must debug, print only a length or a hash prefix.",
                    line.strip(), low,
                ))

            if _CURL_PIPE_SH.search(line):
                out.append(self._emit(
                    rel, lineno, "Pipeline pipes a remote script into a shell in {}".format(rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                    "{} downloads a script and executes it directly at line {}. The pipeline runs with "
                    "repository secrets and a scoped token, so whoever controls that URL controls your "
                    "build.".format(rel, lineno),
                    "Download to a file, verify a pinned checksum or signature, then run it. Better still, "
                    "install the tool from a lockfile-managed package registry.",
                    line.strip(), low,
                ))

            if re.search(r"^\s*secrets:\s*inherit\s*$", line):
                caller = self._nearby_uses(numbered, lineno)
                if caller and owner and not caller.lower().startswith(owner + "/"):
                    out.append(self._emit(
                        rel, lineno, "secrets: inherit passed to a foreign workflow in {}".format(rel),
                        Severity.MEDIUM, Confidence.MEDIUM, "CWE-522", _INTEGRITY,
                        "{} calls the reusable workflow `{}` with `secrets: inherit` at line {}. Every secret "
                        "in the repository — not just the ones that workflow needs — is handed to code owned "
                        "by someone else.".format(rel, caller, lineno),
                        "Replace `secrets: inherit` with an explicit `secrets:` map listing only the values "
                        "the called workflow requires.",
                        line.strip(), low,
                    ))

        pr_triggers = _workflow_triggers(numbered) & {"pull_request", "pull_request_target"}
        if pr_triggers and re.search(r"(?i)runs-on:.*self-hosted", joined):
            lineno = next(
                (ln for ln, line in numbered if re.search(r"(?i)runs-on:.*self-hosted", line)), 1
            )
            trigger = "pull_request_target" if "pull_request_target" in pr_triggers else "pull_request"
            out.append(self._emit(
                rel, lineno, "Fork pull requests run on a self-hosted runner in {}".format(rel),
                Severity.HIGH if trigger == "pull_request_target" else Severity.MEDIUM,
                Confidence.MEDIUM, "CWE-269", _INTEGRITY,
                "{} declares `{}` in its `on:` block and executes on a self-hosted runner. Self-hosted "
                "runners are not ephemeral by default, so on a public repository — or any repository that "
                "accepts fork pull requests — attacker-authored code runs on a long-lived machine inside "
                "your network and can persist on it, poisoning the tool cache for every later "
                "job.".format(rel, trigger),
                "Run untrusted pull requests on GitHub-hosted runners, or use ephemeral, single-job "
                "self-hosted runners in an isolated network and require approval (an environment gate) "
                "before a fork PR build starts.",
                "{} + runs-on: self-hosted".format(trigger), low,
            ))

        if third_party and not re.search(r"^\s*permissions:\s*", joined, re.MULTILINE):
            out.append(self._emit(
                rel, 1, "Workflow does not restrict GITHUB_TOKEN permissions in {}".format(rel),
                Severity.LOW, Confidence.LOW, "CWE-732", _MISCONFIG,
                "{} runs third-party actions but declares no `permissions:` block, so the job inherits the "
                "repository default — historically read/write on contents. Narrowing the token is the single "
                "cheapest limit on the damage a compromised action can do.".format(rel),
                "Add `permissions: {contents: read}` at the top of the workflow and grant extra scopes per "
                "job only where they are needed.",
                "no permissions: block", True,
            ))

        if is_gitlab:
            out.extend(self._gitlab_rules(rel, numbered, low))
        return out

    @staticmethod
    def _nearby_uses(numbered, lineno) -> Optional[str]:
        for ln, line in numbered:
            if abs(ln - lineno) <= 4:
                match = _USES.match(line)
                if match:
                    return match.group(1).split("@")[0]
        return None

    @staticmethod
    def _split_uses(ref_spec: str, owner: Optional[str]):
        """Return (slug, ref) when ref_spec is a third-party owner/repo@ref, else None."""
        if ref_spec.startswith(("./", "../", "docker://")) or "@" not in ref_spec:
            return None
        slug, _sep, ref = ref_spec.rpartition("@")
        parts = slug.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        action_owner = parts[0].lower()
        if action_owner in _FIRST_PARTY_OWNERS or (owner and action_owner == owner):
            return None
        return "/".join(parts[:2]), ref

    @classmethod
    def _is_third_party(cls, ref_spec: str, owner: Optional[str]) -> bool:
        return cls._split_uses(ref_spec, owner) is not None

    @classmethod
    def _classify_uses(cls, ref_spec: str, owner: Optional[str]):
        parsed = cls._split_uses(ref_spec, owner)
        if not parsed:
            return None
        slug, ref = parsed
        if _SHA40.match(ref.lower()) or ref.lower().startswith("sha256:"):
            return None
        severity = Severity.HIGH if ref.lower() in _BRANCH_REFS else Severity.MEDIUM
        return slug, ref, severity

    def _gitlab_rules(self, rel, numbered, low) -> List[Finding]:
        out: List[Finding] = []
        script_indent: Optional[int] = None
        fired_injection = False
        for lineno, line in numbered:
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            header = re.match(r"^(\s*)(?:before_|after_)?script:\s*$", line)
            if header:
                script_indent = len(header.group(1))
                continue
            if script_indent is not None and indent <= script_indent:
                script_indent = None
            if script_indent is not None and not fired_injection:
                match = _GITLAB_REEVAL.search(line)
                if match:
                    fired_injection = True
                    out.append(self._emit(
                        rel, lineno, "GitLab job re-evaluates attacker-controlled input as a shell command in {}".format(rel),
                        Severity.HIGH, Confidence.MEDIUM, "CWE-94", "A03:2021 Injection",
                        "{} passes ${} through a construct that evaluates its value as shell source at line "
                        "{} — eval, a command substitution, or an argument to `sh -c`/`ssh`. Commit messages, "
                        "branch names and merge-request titles are attacker-supplied on any project that "
                        "accepts contributions, so a crafted value becomes command execution on the runner. "
                        "(A plain `$CI_COMMIT_*` expansion is only an environment lookup and is not reported.)"
                        .format(rel, match.group(1), lineno),
                        "Do not re-evaluate the value. Read it from the environment inside the program that "
                        "needs it, and if it must reach a command, quote it (\"$CI_COMMIT_REF_NAME\") and "
                        "pass it as an argument rather than as shell source.",
                        line.strip(), low,
                    ))
            var_match = re.match(r'^\s{2,}([A-Z][A-Z0-9_]*):\s*[\"\']?([^\"\'\s#]+)[\"\']?\s*$', line)
            if (
                var_match
                and _CRED_NAME.search(var_match.group(1))
                and _is_literal_secret(var_match.group(1), var_match.group(2))
            ):
                out.append(self._emit(
                    rel, lineno, "GitLab CI variable holds a literal secret in {}".format(rel),
                    Severity.HIGH, Confidence.MEDIUM, "CWE-798", _AUTHFAIL,
                    "{} defines `{}` with a literal value at line {}. Everything in .gitlab-ci.yml is "
                    "committed, visible to every project member and printed by jobs that dump their "
                    "environment.".format(rel, var_match.group(1), lineno),
                    "Move the value to a masked, protected CI/CD variable in the project settings (or an "
                    "external vault) and rotate the current one.",
                    "{}=...".format(var_match.group(1)), low,
                ))
                break
        return out


# ---------------------------------------------------------------------------
# 6. Insecure package sources
# ---------------------------------------------------------------------------

_PKG_BASENAMES = {
    ".npmrc", ".yarnrc", ".yarnrc.yml", "package.json", "pip.conf", "pip.ini",
    "pyproject.toml", "setup.cfg", "pipfile", "gemfile", "pom.xml", "build.gradle",
    "build.gradle.kts", "composer.json", "cargo.toml", "go.mod", "nuget.config",
    "config", "dockerfile",
}
_PKG_VERIFY_OFF = re.compile(
    r"(?i)(strict-ssl\s*[=:]\s*false"
    r"|--trusted-host\b"
    r"|PIP_TRUSTED_HOST\b"
    r"|\bGOINSECURE\b"
    r"|<disableSslVerification>\s*true"
    r"|BUNDLE_SSL_VERIFY_MODE\s*[:=]\s*0"
    r"|enableStrictSsl\s*:\s*false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)"
)
_URL_TAIL = r"(http://[^\s\"'<>,;)\]]+)"
# Only keys a package manager resolves artifacts from. Project metadata (homepage, bugs,
# repository, download_url) and XML namespace URIs are never fetched and must not be reported.
_PLAIN_REGISTRY = re.compile(
    r"(?i)^\s*[\"']?(?:[\w.@\-]*[:_])?"
    r"(extra-index-url|index-url|index_url|index|registries|registry-url|registry|"
    r"npmregistryserver|npmpublishregistry|mirrors?)"
    r"[\"']?\s*(?:[=:]\s*|\s+)[\"']?" + _URL_TAIL
)
_PLAIN_INDEX_FLAG = re.compile(
    r"(?i)(--index-url|--extra-index-url|--registry|-i)[=\s]+[\"']?" + _URL_TAIL
)
_SHELL_REGISTRY_SET = re.compile(
    r"(?i)\b(?:npm_config_registry|yarn_registry|config\s+set\s+registry|set\s+registry)"
    r"\s*[=:]?\s*[\"']?" + _URL_TAIL
)
_INI_SECTION = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_SOURCE_SECTION = re.compile(r"(?i)(source|repositor|registr|index|mirror)")
_CONTEXT_URL_KEY = re.compile(
    r"(?i)^\s*[\"']?(url|source|location|remote)[\"']?\s*[=:]\s*[\"']?" + _URL_TAIL
)
_GEM_SOURCE = re.compile(r"(?i)^\s*source\s+[\"'](http://[^\"']+)[\"']")
_BUNDLE_MIRROR = re.compile(r"(?i)^\s*BUNDLE_MIRROR__\S+\s*:\s*[\"']?" + _URL_TAIL)
_GRADLE_REPO_URL = re.compile(r"(?i)\b(?:url|setUrl|uri)\s*[=(]*\s*[\"'](http://[^\"']+)[\"']")
_XML_REPO_TAGS = (
    "repository", "pluginRepository", "snapshotRepository", "mirror", "packageSources",
    "distributionManagement",
)
_JSON_METADATA_KEYS = {
    "homepage", "bugs", "repository", "documentation", "docs", "support", "author",
    "authors", "funding", "license", "issues", "changelog", "readme", "wiki", "source",
    "download_url", "$schema",
}
_JSON_SOURCE_CONTAINERS = {"repositories", "registries", "packagesources", "publishconfig"}
_JSON_REGISTRY_KEYS = {"registry", "index-url", "extra-index-url", "index_url"}
_DISTRO_SOURCE = re.compile(r"(?i)^\s*(deb|deb-src)\s+")
_INSTALL_SCRIPT_KEYS = {"preinstall", "install", "postinstall", "prepare", "prepublish"}
_INSTALL_SCRIPT_CMD = re.compile(r"(?i)\b(curl|wget|iwr|invoke-webrequest|node\s+-e|python3?\s+-c)\b")
_DOCKER_UNVERIFIED = re.compile(
    r"(?i)(--trusted-host\b|--allow-unauthenticated\b|--nogpgcheck\b|--no-check-certificate\b"
    r"|strict-ssl\s+false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)"
)


def _xml_repo_urls(text: str) -> List[Tuple[int, str]]:
    """Return [(lineno, url)] for URLs inside elements Maven/NuGet actually resolve from.

    Namespace URIs (``xmlns``, ``xsi:schemaLocation``) and project metadata such as the
    project's own ``<url>`` are never fetched, so only ``<repository>``, ``<mirror>`` and
    friends are considered.
    """
    spans: List[Tuple[int, int]] = []
    for tag in _XML_REPO_TAGS:
        pattern = r"(?is)<" + tag + r"\b[^>]*>.*?</\s*" + tag + r"\s*>"
        for match in re.finditer(pattern, text):
            spans.append((match.start(), match.end()))
    out: List[Tuple[int, str]] = []
    for match in re.finditer(r"http://[^\s\"'<>)\],]+", text):
        if not any(start <= match.start() < end for start, end in spans):
            continue
        out.append((text.count("\n", 0, match.start()) + 1, match.group(0)))
    return out


def _json_registry_urls(node, inside_source: bool = False, depth: int = 0) -> List[str]:
    """Return http:// URLs a package manager resolves from, ignoring metadata keys."""
    if depth > 12:
        return []
    out: List[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            lkey = str(key).lower()
            if lkey in _JSON_METADATA_KEYS:
                continue
            child = inside_source or lkey in _JSON_SOURCE_CONTAINERS
            if isinstance(value, str):
                if value.lower().startswith("http://") and (child or lkey in _JSON_REGISTRY_KEYS):
                    out.append(value)
            else:
                out.extend(_json_registry_urls(value, child, depth + 1))
    elif isinstance(node, list):
        for item in node:
            out.extend(_json_registry_urls(item, inside_source, depth + 1))
    return out


def _plaintext_source_hits(name: str, text: str) -> List[Tuple[int, str]]:
    """Return [(lineno, url)] for plaintext URLs this file resolves dependencies from."""
    lowered = name.lower()
    if lowered.endswith((".xml", ".config")):
        return _xml_repo_urls(text)

    out: List[Tuple[int, str]] = []
    if lowered.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return out
        lines = text.splitlines()
        for url in _json_registry_urls(data):
            lineno = next((idx for idx, line in enumerate(lines, 1) if url in line), 1)
            out.append((lineno, url))
        return out

    section = ""
    for lineno, line in _strip_hash_comment_lines(text):
        if not line or _DISTRO_SOURCE.match(line.strip()):
            continue
        if "/etc/apk/repositories" in line or "sources.list" in line:
            continue
        header = _INI_SECTION.match(line)
        if header:
            section = header.group(1).lower()
            continue
        match = _PLAIN_REGISTRY.match(line) or _PLAIN_INDEX_FLAG.search(line)
        if match:
            out.append((lineno, match.group(2)))
            continue
        shell = _SHELL_REGISTRY_SET.search(line) or _BUNDLE_MIRROR.match(line)
        if shell:
            out.append((lineno, shell.group(1)))
            continue
        if _SOURCE_SECTION.search(section):
            contextual = _CONTEXT_URL_KEY.match(line)
            if contextual:
                out.append((lineno, contextual.group(2)))
                continue
        if lowered.startswith("gemfile"):
            gem = _GEM_SOURCE.match(line)
            if gem:
                out.append((lineno, gem.group(1)))
                continue
        if lowered.startswith("build.gradle"):
            gradle = _GRADLE_REPO_URL.search(line)
            if gradle:
                out.append((lineno, gradle.group(1)))
    return out


@register
class InsecurePackageSource(Check):
    name = "whitebox.insecure_package_source"
    title = "Dependencies resolved over plaintext or verification-disabled channels"
    target_kinds = (TargetKind.SOURCE,)
    min_profile = Profile.PASSIVE

    _CAP = 12

    def run(self, ctx: ScanContext):
        root = ctx.target.source_path
        if not root or not os.path.isdir(root):
            return
        emitted = 0
        for path, name in _walk_paths(root):
            if emitted >= self._CAP:
                return
            lowered = name.lower()
            selected = (
                lowered in _PKG_BASENAMES
                or (lowered.startswith("requirements") and lowered.endswith(".txt"))
                or _is_dockerfile(name)
            )
            if not selected:
                continue
            rel = _rel(root, path)
            if lowered == "config" and not rel.lower().endswith((".bundle/config", ".circleci/config")):
                continue
            if lowered == "config" and rel.lower().endswith(".circleci/config"):
                continue
            text = _read(path)
            if not text:
                continue
            low = _is_test_path(rel)
            for finding in self._analyze(rel, name, text, low):
                yield finding
                emitted += 1
                if emitted >= self._CAP:
                    return

    def _emit(self, rel, lineno, title, severity, confidence, cwe, category, description,
              remediation, evidence, downgrade):
        if downgrade:
            severity = _lower_severity(severity)
            confidence = Confidence.LOW
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe=cwe,
            description=description,
            remediation=remediation,
            location="{}:{}".format(rel, lineno),
            evidence=evidence[:200],
            references=_REFS_SUPPLY,
        )

    def _analyze(self, rel, name, text, low) -> List[Finding]:
        out: List[Finding] = []
        lowered = name.lower()
        reported_hosts = set()

        # (a)/(d) plaintext package sources
        for lineno, url in _plaintext_source_hits(name, text):
            host = _host_of(url)
            if not host or _is_private_host(host) or host in reported_hosts:
                continue
            reported_hosts.add(host)
            out.append(self._emit(
                rel, lineno, "Packages fetched over plaintext HTTP in {}".format(rel),
                Severity.HIGH, Confidence.MEDIUM, "CWE-319", _INTEGRITY,
                "{} resolves dependencies from `{}` over plain HTTP at line {}. Anyone on the network path — "
                "a hostile Wi-Fi, a compromised proxy, a CI egress box — can substitute the package contents, "
                "which is code execution at install time on developer machines and build "
                "agents.".format(rel, host, lineno),
                "Switch the registry, index or repository URL to https://. If the mirror has no TLS, put it "
                "behind one, and enable checksum/lockfile verification for the ecosystem.",
                url[:160], low,
            ))
            break

        # (b) certificate verification disabled
        for lineno, line in _strip_hash_comment_lines(text):
            if not line or not _PKG_VERIFY_OFF.search(line):
                continue
            if _is_dockerfile(name) and not re.match(r"(?i)^\s*(RUN|ENV|ARG)\b", line):
                continue
            severity = Severity.MEDIUM if _is_dockerfile(name) else Severity.HIGH
            out.append(self._emit(
                rel, lineno, "Package-manager certificate verification disabled in {}".format(rel),
                severity, Confidence.MEDIUM, "CWE-295", _CRYPTO,
                "{} disables TLS verification for the package manager at line {}. The download still uses "
                "https, but any certificate is accepted, so a machine-in-the-middle can serve arbitrary "
                "package contents that are then executed by the installer.".format(rel, lineno),
                "Remove the flag and fix the underlying trust problem instead: install the corporate root CA "
                "into the system store, or point the tool at a proper CA bundle.",
                line.strip()[:160], low,
            ))
            break

        # (e) Dockerfile unverified installs
        if _is_dockerfile(name):
            for lineno, instr, args in _dockerfile_instructions(text):
                if instr == "RUN" and _DOCKER_UNVERIFIED.search(args):
                    out.append(self._emit(
                        rel, lineno, "Dockerfile installs packages without verification in {}".format(rel),
                        Severity.MEDIUM, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                        "The RUN step at line {} of {} turns off signature or certificate checking for the "
                        "package manager. Every image rebuild will accept whatever the network hands it, "
                        "baking unverified code into a layer you then ship.".format(lineno, rel),
                        "Drop the flag, add the needed CA or GPG key to the image explicitly, and pin package "
                        "versions so a rebuild is reproducible.",
                        args[:160], low,
                    ))
                    break

        # (c)/(f) package.json specifics
        if lowered == "package.json":
            out.extend(self._package_json(rel, text, low))
        return out

    def _package_json(self, rel, text, low) -> List[Finding]:
        out: List[Finding] = []
        try:
            data = json.loads(text)
        except ValueError:
            return out
        if not isinstance(data, dict):
            return out

        lines = text.splitlines()

        def _lineno_for(needle: str) -> int:
            for index, line in enumerate(lines, 1):
                if needle in line:
                    return index
            return 1

        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for pkg, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                insecure = re.match(r"^(?:git\+)?(?:http|git)://", spec) or re.match(
                    r"^http://\S+\.(?:tgz|tar\.gz|zip)$", spec
                )
                if insecure:
                    host = _host_of(spec.replace("git+", ""))
                    if host and _is_private_host(host):
                        continue
                    out.append(self._emit(
                        rel, _lineno_for('"{}"'.format(pkg)),
                        "Dependency '{}' resolved over an unauthenticated protocol in {}".format(pkg, rel),
                        Severity.HIGH, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                        "{} pulls `{}` from `{}`. git:// and http:// offer no authentication of the server or "
                        "integrity of the payload, so a network attacker can replace the package source and "
                        "run code during `npm install`.".format(rel, pkg, spec),
                        "Use an https:// or git+ssh:// URL, pin the dependency to a commit SHA rather than a "
                        "branch, and commit a lockfile so the resolved integrity hash is enforced.",
                        "{}: {}".format(pkg, spec)[:160], low,
                    ))
                    return out
                if re.match(r"^(?:git\+)?(?:ssh|https)://", spec) and re.search(
                    r"(?i)#(master|main|HEAD)$", spec
                ):
                    out.append(self._emit(
                        rel, _lineno_for('"{}"'.format(pkg)),
                        "Dependency '{}' tracks a mutable branch in {}".format(pkg, rel),
                        Severity.LOW, Confidence.LOW, "CWE-494", _INTEGRITY,
                        "{} pins `{}` to a branch rather than a commit. Whatever is on that branch at install "
                        "time is what gets installed, so upstream can change your dependency contents without "
                        "any change in your repository.".format(rel, pkg),
                        "Pin git dependencies to a full commit SHA and update them deliberately.",
                        "{}: {}".format(pkg, spec)[:160], True,
                    ))

        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for key, value in scripts.items():
                if key.lower() not in _INSTALL_SCRIPT_KEYS or not isinstance(value, str):
                    continue
                if not _INSTALL_SCRIPT_CMD.search(value):
                    continue
                out.append(self._emit(
                    rel, _lineno_for('"{}"'.format(key)),
                    "Install-time script fetches and runs remote code in {}".format(rel),
                    Severity.MEDIUM, Confidence.MEDIUM, "CWE-494", _INTEGRITY,
                    "The `{}` script in {} downloads or evaluates code as part of `npm install`. Install "
                    "hooks run automatically on every developer machine and CI agent that installs this "
                    "package, so the remote endpoint is effectively a trusted code source.".format(key, rel),
                    "Move the work into an explicit build step, vendor the artifact, or at minimum verify a "
                    "pinned checksum before executing anything you downloaded.",
                    "{}: {}".format(key, value)[:160], low,
                ))
                break
        return out
