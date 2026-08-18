"""AndroidManifest.xml and res/xml static analysis for APK targets.

Every check in this module is an offline read of the APK zip: no device, no
network, no ``ctx.http`` (which is ``None`` for APK targets). Binary XML is
decoded with the stdlib helpers in :mod:`fya.checks._apk_common`.
"""

from __future__ import annotations

import os
import re
import struct
from typing import List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._apk_common import (
    attr,
    is_true,
    iter_entries,
    local_name,
    manifest_tree,
    open_apk,
    read_axml,
)

_MASVS_REF = ["https://mas.owasp.org/MASVS/", "https://mas.owasp.org/MASTG/"]

_CAP = 8
_BACKUP_CAP = 5
_SIGNING_CAP = 5

_RES_XML_RE = re.compile(r"^res/xml(?:-v\d+)?/[^/]+\.xml$")
_RES_XML_ENTRY_CAP = 400
_RES_XML_DOC_CAP = 40
_RES_XML_MAX_BYTES = 2 * 1024 * 1024
_DEX_MAX_BYTES = 48 * 1024 * 1024

# Auto-generated library providers. They are exported=false in practice or carry
# no app data, and flagging them produces noise in every modern app.
_INIT_PROVIDERS = frozenset(
    {
        "androidx.startup.InitializationProvider",
        "androidx.work.impl.WorkManagerInitializer",
        "androidx.lifecycle.ProcessLifecycleOwnerInitializer",
        "androidx.emoji2.text.EmojiCompatInitializer",
        "androidx.profileinstaller.ProfileInstallerInitializer",
        "com.google.firebase.provider.FirebaseInitProvider",
        "com.google.android.gms.ads.MobileAdsInitProvider",
        "com.crashlytics.android.CrashlyticsInitProvider",
        "com.squareup.picasso.PicassoProvider",
        "io.flutter.plugins.firebase.core.FlutterFirebaseCoreInitProvider",
    }
)

_FILE_PROVIDER_PATH_TAGS = frozenset(
    {
        "root-path",
        "files-path",
        "cache-path",
        "external-path",
        "external-files-path",
        "external-cache-path",
        "external-media-path",
    }
)
_WIDE_PATH_VALUES = frozenset({"/", ".", ""})
_FILE_PROVIDER_META = "android.support.FILE_PROVIDER_PATHS"

# What an over-wide root actually reaches, keyed by "is this an external-* root".
# external-* roots live in shared storage, not in the app sandbox.
_PATH_ROOT_IMPACT = {
    False: "Any URI the app grants - or any component that can influence the URI it shares - "
    "then reaches arbitrary app-private files under that root, including shared_prefs and "
    "databases.",
    True: "Any URI the app grants - or any component that can influence the URI it shares - "
    "then reaches every file the app can read in that shared external storage root, including "
    "media and documents written by other apps.",
}

_WILDCARD_PATTERNS = frozenset({".*", ".*.*"})

# Schemes the platform or a well-known vendor already owns. A custom scheme
# outside this set is first-come-first-served and can be claimed by any app.
_FRAMEWORK_SCHEMES = frozenset(
    {
        "android-app",
        "intent",
        "content",
        "file",
        "package",
        "market",
        "tel",
        "mailto",
        "sms",
        "geo",
    }
)

_PIN_MARKERS = (b"CertificatePinner", b"X509TrustManager")

_V2_BLOCK_ID = 0x7109871A
_V3_BLOCK_ID = 0xF05368C0
_V31_BLOCK_ID = 0x1B93AD61
_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_EOCD_SCAN_BYTES = 66000
_MAX_SIG_PAIRS = 64
_MAX_PAIR_REGION = 64 * 1024 * 1024

_DEBUG_CERT_MARKER = b"Android Debug"


# ---------------------------------------------------------------------------
# small shared utilities
# ---------------------------------------------------------------------------


def _res_xml_docs(zf, wanted_tags: Set[str]) -> List[Tuple[str, ET.Element]]:
    """Return [(entry name, root element)] for res/xml docs with a wanted root tag."""
    docs: List[Tuple[str, ET.Element]] = []
    for name, data in iter_entries(
        zf,
        _RES_XML_RE.match,
        max_entries=_RES_XML_ENTRY_CAP,
        max_bytes=_RES_XML_MAX_BYTES,
    ):
        root = read_axml(data)
        if root is None:
            continue
        if local_name(root.tag) in wanted_tags:
            docs.append((name, root))
            if len(docs) >= _RES_XML_DOC_CAP:
                break
    return docs


def _resource_entry_name(value: Optional[str]) -> Optional[str]:
    """Return the res/xml entry stem a manifest attribute points at.

    ``"@xml/file_paths"`` -> ``"file_paths"``. A compiled manifest that kept the
    numeric resource id (``"@0x7f130002"``), an inline value or an empty
    attribute returns None, which callers read as "cannot resolve".
    """
    text = (value or "").strip()
    if not text.startswith("@") or text.lower().startswith("@0x"):
        return None
    tail = text.partition("/")[2].strip()
    if not tail or "/" in tail:
        return None
    return tail


def _entry_stem(name: str) -> str:
    """``res/xml-v31/file_paths.xml`` -> ``file_paths``."""
    base = name.rsplit("/", 1)[-1]
    if base.lower().endswith(".xml"):
        base = base[:-4]
    return base


def _referenced_docs(
    docs: List[Tuple[str, ET.Element]], resources: List[Optional[str]]
) -> List[Tuple[str, ET.Element]]:
    """Keep only the docs a manifest attribute actually points at.

    Libraries merged into the app ship their own ``res/xml`` rule files, so
    scanning every document of a given root tag reports files the app never
    loads. When no attribute resolves to an entry name - the usual case for a
    compiled manifest holding a numeric id - every doc is kept, so the scan
    degrades to the unfiltered behaviour instead of going blind.
    """
    stems = {stem for stem in (_resource_entry_name(r) for r in resources) if stem}
    if not stems:
        return docs
    return [(name, root) for name, root in docs if _entry_stem(name) in stems]


def _iter_debug_scoped(node: ET.Element, under_debug: bool = False):
    """Yield (element, under_debug_overrides) for every descendant of ``node``."""
    for child in list(node):
        child_debug = under_debug or local_name(child.tag) == "debug-overrides"
        yield child, child_debug
        for item in _iter_debug_scoped(child, child_debug):
            yield item


def _int_attr(node: Optional[ET.Element], name: str) -> Optional[int]:
    raw = attr(node, name)
    if raw is None:
        return None
    text = str(raw).strip()
    try:
        if text.lower().startswith(("0x", "@0x")):
            return int(text.lstrip("@"), 16)
        return int(text)
    except ValueError:
        return None


def _resolve_component(package: str, name: str) -> str:
    name = (name or "").strip()
    if not name:
        return ""
    if name.startswith("."):
        return (package or "") + name
    if "." not in name and package:
        return package + "." + name
    return name


def _dex_contains(zf, markers) -> bool:
    def _is_dex(entry: str) -> bool:
        return entry.startswith("classes") and entry.endswith(".dex")

    for _name, data in iter_entries(zf, _is_dex, max_entries=64, max_bytes=_DEX_MAX_BYTES):
        for marker in markers:
            if marker in data:
                return True
    return False


def _sdk_versions(root: ET.Element) -> Tuple[Optional[int], Optional[int]]:
    uses_sdk = root.find(".//uses-sdk")
    return _int_attr(uses_sdk, "minSdkVersion"), _int_attr(uses_sdk, "targetSdkVersion")


# ---------------------------------------------------------------------------
# apk.network_security_config
# ---------------------------------------------------------------------------


@register
class ApkNetworkSecurityConfig(Check):
    name = "apk.network_security_config"
    title = "Network Security Config trusts user CAs, permits cleartext, or pins nothing"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        zf = open_apk(apk_path)
        if zf is None:
            return
        with zf:
            docs = _res_xml_docs(zf, {"network-security-config"})
            if not docs:
                return
            emitted = 0
            pinned = any(
                local_name(node.tag) == "pin-set" for _name, root in docs for node in root.iter()
            )
            for name, root in docs:
                for node, under_debug in _iter_debug_scoped(root):
                    if emitted >= _CAP:
                        break
                    if under_debug:
                        continue
                    tag = local_name(node.tag)
                    if tag in ("base-config", "domain-config"):
                        finding = self._cleartext(name, node, tag)
                        if finding is not None:
                            emitted += 1
                            yield finding
                    elif tag == "certificates":
                        finding = self._trust_anchor(name, node)
                        if finding is not None:
                            emitted += 1
                            yield finding
                if emitted >= _CAP:
                    break

            if emitted < _CAP and not pinned and not _dex_contains(zf, _PIN_MARKERS):
                yield Finding(
                    check=self.name,
                    title="No certificate pinning declared anywhere in the app",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="MASVS-NETWORK",
                    cwe="CWE-295",
                    description="The app ships a network security configuration but no <pin-set>, "
                    "and the dex code references neither CertificatePinner nor a custom "
                    "X509TrustManager. Any CA in the device trust store - including one added by "
                    "an attacker with device access or pushed by an MDM - can therefore terminate "
                    "the app's TLS connections.",
                    remediation="Add a <pin-set> with backup pins and a realistic expiration to the "
                    "domain-config for your own API hosts, or pin in code via OkHttp's "
                    "CertificatePinner. Do not pin third-party hosts you do not control.",
                    location=docs[0][0],
                    evidence="no <pin-set> in %d network-security-config file(s)" % len(docs),
                    references=_MASVS_REF,
                )

    def _cleartext(self, name: str, node: ET.Element, tag: str) -> Optional[Finding]:
        if not is_true(attr(node, "cleartextTrafficPermitted")):
            return None
        domains = [
            (child.text or "").strip()
            for child in node
            if local_name(child.tag) == "domain" and (child.text or "").strip()
        ]
        scope = ", ".join(domains[:4]) if domains else "all domains"
        return Finding(
            check=self.name,
            title="Network security config permits cleartext traffic",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="MASVS-NETWORK",
            cwe="CWE-319",
            description="A <%s> outside <debug-overrides> sets cleartextTrafficPermitted=\"true\" "
            "for %s. Release builds will therefore send plaintext HTTP for those hosts, which any "
            "party on the network path can read or rewrite." % (tag, scope),
            remediation="Remove cleartextTrafficPermitted=\"true\", or move it inside "
            "<debug-overrides> so it only applies to debuggable builds, and serve the affected "
            "hosts over HTTPS.",
            location="%s [%s: %s]" % (name, tag, scope),
            evidence="<%s cleartextTrafficPermitted=\"true\"> scope=%s" % (tag, scope),
            references=_MASVS_REF,
        )

    def _trust_anchor(self, name: str, node: ET.Element) -> Optional[Finding]:
        src = (attr(node, "src") or "").strip()
        if not src:
            return None
        if src == "user":
            return Finding(
                check=self.name,
                title="Network security config trusts user-installed CAs",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-NETWORK",
                cwe="CWE-295",
                description="A <trust-anchors> block outside <debug-overrides> declares "
                "<certificates src=\"user\"/>, so the release build accepts any CA the device "
                "owner or an MDM profile has installed. That makes transparent TLS interception "
                "of the app's traffic a one-tap operation on a device the attacker controls.",
                remediation="Trust only src=\"system\" in the shipped configuration and move the "
                "user trust anchor into <debug-overrides>, which the platform applies exclusively "
                "to debuggable builds.",
                location="%s [certificates src=user]" % name,
                evidence="<trust-anchors><certificates src=\"user\"/> outside debug-overrides",
                references=_MASVS_REF,
            )
        if src == "system":
            return None
        return Finding(
            check=self.name,
            title="Network security config adds a custom trust anchor bundle",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            category="MASVS-NETWORK",
            cwe="CWE-295",
            description="A <trust-anchors> block outside <debug-overrides> loads certificates from "
            "%s. A bundled CA is only as safe as the key behind it, so confirm the bundle contains "
            "just the roots you operate and that it is rotated before expiry." % src,
            remediation="Review the bundled certificate, keep it scoped to a <domain-config> for "
            "your own hosts, and prefer pinning leaf or intermediate keys over shipping a CA.",
            location="%s [certificates src=%s]" % (name, src),
            evidence="<certificates src=\"%s\"/> outside debug-overrides" % src,
            references=_MASVS_REF,
        )


# ---------------------------------------------------------------------------
# apk.provider_exposure
# ---------------------------------------------------------------------------


@register
class ApkProviderExposure(Check):
    name = "apk.provider_exposure"
    title = "Content provider exposes app-private files"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        root = manifest_tree(apk_path)
        if root is None:
            return
        package = (root.get("package") or "").strip()
        min_sdk, _target_sdk = _sdk_versions(root)

        emitted = 0
        needs_paths_scan: List[Tuple[str, Optional[str]]] = []
        for provider in root.findall(".//provider"):
            if emitted >= _CAP:
                break
            raw_name = attr(provider, "name")
            if not raw_name:
                continue
            enabled = attr(provider, "enabled")
            if enabled is not None and (enabled or "").strip().lower() == "false":
                continue
            component = _resolve_component(package, raw_name)
            exported = self._is_exported(provider, min_sdk)
            allowlisted = component in _INIT_PROVIDERS
            location = "AndroidManifest.xml [provider: %s]" % component

            if exported and not allowlisted:
                for finding in self._one_sided(provider, component, location):
                    emitted += 1
                    yield finding
                    if emitted >= _CAP:
                        break
            if emitted >= _CAP:
                break
            if exported and not allowlisted:
                finding = self._wildcard_grants(provider, component, location)
                if finding is not None:
                    emitted += 1
                    yield finding
            if emitted >= _CAP:
                break
            if exported and is_true(attr(provider, "multiprocess")):
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="Exported provider runs multiprocess",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="MASVS-PLATFORM",
                    cwe="CWE-926",
                    description="The exported provider '%s' sets android:multiprocess=\"true\", so "
                    "an instance is created inside each calling process. Any per-process state the "
                    "provider keeps is then duplicated and no longer authoritative, which commonly "
                    "breaks permission or session bookkeeping done in the provider." % component,
                    remediation="Drop android:multiprocess for exported providers and keep a single "
                    "instance in the app process.",
                    location=location,
                    evidence="provider %s exported multiprocess=true" % component,
                    references=_MASVS_REF,
                )
            if self._is_file_provider(component):
                paths_res = self._paths_resource(provider)
                if paths_res is not None:
                    needs_paths_scan.append((component, _resource_entry_name(paths_res)))

        if emitted >= _CAP or not needs_paths_scan:
            return
        zf = open_apk(apk_path)
        if zf is None:
            return
        with zf:
            docs = _res_xml_docs(zf, {"paths"})
        # Pair each <paths> document with the provider whose meta-data references
        # it. A doc no provider points at belongs to a merged library and is not
        # this app's exposure; only when no reference resolves (compiled manifest
        # holding a numeric id) is every doc attributed to the first provider.
        by_stem = {stem: comp for comp, stem in needs_paths_scan if stem}
        fallback = next((comp for comp, stem in needs_paths_scan if not stem), None)
        for name, paths_root in docs:
            owner = by_stem.get(_entry_stem(name), fallback)
            if owner is None:
                continue
            for node in paths_root:
                if emitted >= _CAP:
                    return
                tag = local_name(node.tag)
                if tag not in _FILE_PROVIDER_PATH_TAGS:
                    continue
                raw_path = attr(node, "path")
                if raw_path is None or raw_path.strip() not in _WIDE_PATH_VALUES:
                    continue
                emitted += 1
                yield Finding(
                    check=self.name,
                    title="FileProvider maps an entire storage root",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="MASVS-STORAGE",
                    cwe="CWE-22",
                    description="The path configuration '%s' declares <%s path=\"%s\"/>, which maps "
                    "the whole %s root into the content:// namespace of '%s'. %s"
                    % (
                        name,
                        tag,
                        raw_path.strip(),
                        tag.replace("-path", ""),
                        owner,
                        _PATH_ROOT_IMPACT[tag.startswith("external")],
                    ),
                    remediation="Scope every path entry to the specific subdirectory you intend to "
                    "share (for example <files-path name=\"shared\" path=\"shared/\"/>) and never "
                    "use \"/\" or \".\".",
                    location="%s [%s]" % (name, tag),
                    evidence="%s: <%s path=\"%s\"/> for %s"
                    % (name, tag, raw_path.strip(), owner),
                    references=_MASVS_REF,
                )

    def _is_exported(self, provider: ET.Element, min_sdk: Optional[int]) -> bool:
        explicit = attr(provider, "exported")
        if explicit is not None:
            return is_true(explicit)
        if provider.find("intent-filter") is not None:
            return True
        return min_sdk is not None and min_sdk < 17

    def _is_file_provider(self, component: str) -> bool:
        return component.endswith("FileProvider")

    def _paths_resource(self, provider: ET.Element) -> Optional[str]:
        """Return the raw android:resource of the FILE_PROVIDER_PATHS meta-data."""
        for child in provider:
            if local_name(child.tag) != "meta-data":
                continue
            if (attr(child, "name") or "").strip() != _FILE_PROVIDER_META:
                continue
            return (attr(child, "resource") or "").strip()
        return None

    def _one_sided(self, provider: ET.Element, component: str, location: str):
        if attr(provider, "permission"):
            return
        read_perm = attr(provider, "readPermission")
        write_perm = attr(provider, "writePermission")
        if read_perm and not write_perm:
            yield Finding(
                check=self.name,
                title="Exported provider guards reads but not writes",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-926",
                description="The exported provider '%s' declares android:readPermission=\"%s\" and "
                "no android:writePermission or android:permission. Android applies each side "
                "independently, so reads are gated while insert, update and delete stay open to "
                "every app on the device." % (component, read_perm),
                remediation="Declare android:writePermission as well (or a single "
                "android:permission covering both sides), or set android:exported=\"false\" if no "
                "other app needs the provider.",
                location=location,
                evidence="provider %s readPermission=%s, no writePermission" % (component, read_perm),
                references=_MASVS_REF,
            )
        elif write_perm and not read_perm:
            yield Finding(
                check=self.name,
                title="Exported provider guards writes but not reads",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-926",
                description="The exported provider '%s' declares android:writePermission=\"%s\" and "
                "no android:readPermission or android:permission, so any app on the device can "
                "query it and read whatever rows it serves." % (component, write_perm),
                remediation="Declare android:readPermission as well (or a single "
                "android:permission covering both sides), or set android:exported=\"false\".",
                location=location,
                evidence="provider %s writePermission=%s, no readPermission"
                % (component, write_perm),
                references=_MASVS_REF,
            )

    def _wildcard_grants(
        self, provider: ET.Element, component: str, location: str
    ) -> Optional[Finding]:
        if not is_true(attr(provider, "grantUriPermissions")):
            return None
        guarded = bool((attr(provider, "permission") or "").strip()) or bool(
            (attr(provider, "readPermission") or "").strip()
            and (attr(provider, "writePermission") or "").strip()
        )
        grants = [c for c in provider if local_name(c.tag) == "grant-uri-permission"]
        path_perms = [c for c in provider if local_name(c.tag) == "path-permission"]
        reason = ""
        for grant in grants:
            pattern = (attr(grant, "pathPattern") or "").strip()
            path = (attr(grant, "path") or "").strip()
            prefix = (attr(grant, "pathPrefix") or "").strip()
            if pattern in _WILDCARD_PATTERNS:
                reason = "<grant-uri-permission pathPattern=\"%s\"/>" % pattern
                break
            if path == "/":
                reason = "<grant-uri-permission path=\"/\"/>"
                break
            if prefix == "/":
                reason = "<grant-uri-permission pathPrefix=\"/\"/>"
                break
        if reason:
            return Finding(
                check=self.name,
                title="Exported provider grants URI permissions for every path",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-266",
                description="The exported provider '%s' declares a URI grant covering its whole "
                "authority (%s). A malicious app that receives or guesses one of these URIs - or "
                "that tricks the app into granting one - gets access to any record or file the "
                "provider can reach, not just the item that was meant to be shared."
                % (component, reason),
                remediation="List explicit <grant-uri-permission> entries with a concrete "
                "pathPrefix for the exact subtree you share, and drop grantUriPermissions from "
                "providers that never hand out temporary access.",
                location=location,
                evidence="provider %s: %s" % (component, reason),
                references=_MASVS_REF,
            )
        if grants or path_perms or guarded:
            # Either the grants are already scoped, or a permission gates the
            # provider so bare grantUriPermissions is the documented way to share
            # a single item with FLAG_GRANT_READ_URI_PERMISSION. Neither is a
            # finding on its own.
            return None
        return Finding(
            check=self.name,
            title="Exported provider enables URI permission grants with no guard",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            category="MASVS-STORAGE",
            cwe="CWE-266",
            description="The exported provider '%s' sets android:grantUriPermissions=\"true\" with "
            "no <grant-uri-permission> or <path-permission> restriction and no android:permission. "
            "The flag alone grants nothing, but it means any URI this provider ever hands out is "
            "grantable, so a component that can be tricked into sharing an attacker-chosen URI "
            "leaks whatever that URI resolves to." % component,
            remediation="Restrict the grantable surface with <grant-uri-permission "
            "pathPrefix=\"...\"/> entries for the exact subtree you share, add an "
            "android:permission, or set android:exported=\"false\" if no other app needs it.",
            location=location,
            evidence="provider %s: grantUriPermissions=\"true\", no restriction, no permission"
            % component,
            references=_MASVS_REF,
        )


# ---------------------------------------------------------------------------
# apk.backup_rules
# ---------------------------------------------------------------------------


@register
class ApkBackupRules(Check):
    name = "apk.backup_rules"
    title = "Backup and data-extraction rules allow full app-data extraction"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        root = manifest_tree(apk_path)
        if root is None:
            return
        app = root.find(".//application")
        if app is None:
            return

        allow_raw = attr(app, "allowBackup")
        allow_backup = True if allow_raw is None else is_true(allow_raw)
        min_sdk, target_sdk = _sdk_versions(root)
        if target_sdk is None:
            target_sdk = min_sdk
        sdk_note = "targetSdkVersion=%s" % (target_sdk if target_sdk is not None else "unknown")
        full_backup = attr(app, "fullBackupContent")
        extraction_rules = attr(app, "dataExtractionRules")
        backup_agent = attr(app, "backupAgent")

        emitted = 0
        if (
            allow_raw is None
            and target_sdk is not None
            and target_sdk < 31
            and not full_backup
            and not extraction_rules
        ):
            emitted += 1
            yield Finding(
                check=self.name,
                title="Backup enabled by default (android:allowBackup absent)",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-530",
                description="<application> declares no android:allowBackup and no backup rules "
                "file, and %s, so the platform default of true applies. The full app sandbox - "
                "shared_prefs, databases and files - can be pulled off the device with "
                "`adb backup` or copied by the transport during a device-to-device transfer."
                % sdk_note,
                remediation="Set android:allowBackup=\"false\", or keep backup on and declare a "
                "fullBackupContent rules file that excludes credentials, tokens and databases.",
                location="AndroidManifest.xml [application]",
                evidence="android:allowBackup absent, no fullBackupContent, no dataExtractionRules, "
                "%s" % sdk_note,
                references=_MASVS_REF,
            )

        if emitted < _BACKUP_CAP and (full_backup or extraction_rules):
            zf = open_apk(apk_path)
            if zf is not None:
                with zf:
                    docs = _res_xml_docs(zf, {"full-backup-content", "data-extraction-rules"})
                docs = _referenced_docs(docs, [full_backup, extraction_rules])
                for finding in self._rule_files(docs, sdk_note):
                    emitted += 1
                    yield finding
                    if emitted >= _BACKUP_CAP:
                        break

        if emitted >= _BACKUP_CAP:
            return
        if target_sdk is not None and target_sdk >= 31 and allow_backup and not extraction_rules:
            emitted += 1
            yield Finding(
                check=self.name,
                title="Backup on for API 31+ with no dataExtractionRules",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-530",
                description="Backup is enabled and %s, but no android:dataExtractionRules file is "
                "declared. On API 31 and above that attribute is what controls cloud backup and "
                "device-to-device transfer separately, so without it both channels copy the whole "
                "sandbox." % sdk_note,
                remediation="Declare android:dataExtractionRules and exclude credential stores from "
                "both the <cloud-backup> and <device-transfer> sections.",
                location="AndroidManifest.xml [application dataExtractionRules]",
                evidence="allowBackup=%s, no dataExtractionRules, %s"
                % ("true (default)" if allow_raw is None else allow_raw, sdk_note),
                references=_MASVS_REF,
            )

        if emitted >= _BACKUP_CAP:
            return
        if backup_agent and allow_backup:
            yield Finding(
                check=self.name,
                title="Custom backup agent handles app data",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                description="The app declares android:backupAgent=\"%s\" while backup is enabled "
                "(%s). The agent decides what leaves the device, so review it for secrets written "
                "into the backup stream." % (backup_agent, sdk_note),
                remediation="Audit the backup agent's onFullBackup/onBackup implementation and keep "
                "tokens, keys and credentials out of the backup set.",
                location="AndroidManifest.xml [application backupAgent]",
                evidence="backupAgent=%s, %s" % (backup_agent, sdk_note),
                references=_MASVS_REF,
            )

    def _rule_files(self, docs: List[Tuple[str, ET.Element]], sdk_note: str):
        for name, root in docs:
            doc_kind = local_name(root.tag)
            for parent in root.iter():
                includes = [c for c in parent if local_name(c.tag) == "include"]
                if not includes:
                    continue
                excluded = {
                    (attr(c, "domain") or "").strip()
                    for c in parent
                    if local_name(c.tag) == "exclude"
                }
                section = local_name(parent.tag)
                for include in includes:
                    domain = (attr(include, "domain") or "").strip()
                    if domain not in ("sharedpref", "database"):
                        continue
                    raw_path = attr(include, "path")
                    path = "" if raw_path is None else raw_path.strip()
                    if path not in _WIDE_PATH_VALUES:
                        continue
                    if domain in excluded:
                        continue
                    where = section if section != doc_kind else doc_kind
                    yield Finding(
                        check=self.name,
                        title="Backup rules include the whole %s store" % domain,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="MASVS-STORAGE",
                        cwe="CWE-530",
                        description="The <%s> section of %s includes domain=\"%s\" with path "
                        "\"%s\" and declares no matching <exclude>, so every shared preference or "
                        "database file in that domain is copied off the device by backup or "
                        "device transfer (%s)." % (where, name, domain, path, sdk_note),
                        remediation="Narrow the <include> to the specific file you need, or add an "
                        "<exclude domain=\"%s\" path=\"...\"/> for each store holding tokens, "
                        "session cookies or keys." % domain,
                        location="%s [%s include domain=%s]" % (name, where, domain),
                        evidence="%s: <%s><include domain=\"%s\" path=\"%s\"/> with no <exclude>"
                        % (name, where, domain, path),
                        references=_MASVS_REF,
                    )


# ---------------------------------------------------------------------------
# apk.deeplink_surface
# ---------------------------------------------------------------------------


@register
class ApkDeeplinkSurface(Check):
    name = "apk.deeplink_surface"
    title = "Browser-reachable deep links: custom schemes, host-less filters, wildcard paths"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        root = manifest_tree(apk_path)
        if root is None:
            return
        package = (root.get("package") or "").strip()
        signature_perms = self._signature_permissions(root)

        seen: Set[str] = set()
        emitted = 0
        activities = root.findall(".//activity") + root.findall(".//activity-alias")
        for act in activities:
            if emitted >= _CAP:
                return
            guard = attr(act, "permission")
            if guard and guard in signature_perms:
                continue
            if not self._externally_reachable(act):
                continue
            component = _resolve_component(package, attr(act, "name") or "") or "activity"
            custom: List[Tuple[str, bool]] = []
            for ifilter in act.findall("intent-filter"):
                if emitted >= _CAP:
                    return
                if not self._is_browsable_view(ifilter):
                    continue
                datas = ifilter.findall("data")
                schemes = [
                    (attr(d, "scheme") or "").strip().lower()
                    for d in datas
                    if (attr(d, "scheme") or "").strip()
                ]
                hosts = {
                    (attr(d, "host") or "").strip()
                    for d in datas
                    if (attr(d, "host") or "").strip()
                }
                auto_verify = is_true(
                    attr(ifilter, "autoVerify") or attr(act, "autoVerify") or "false"
                )
                # A filter where every <data> carries a mimeType only matches
                # intents whose resolved content type matches too, so it is a
                # content-type handler rather than an open URL entry point.
                typed_only = bool(datas) and all(attr(d, "mimeType") for d in datas)

                web = sorted({s for s in schemes if s in ("http", "https")})
                if web and not hosts and not typed_only:
                    key = "%s|%s://*" % (component, web[0])
                    if key not in seen:
                        seen.add(key)
                        emitted += 1
                        yield self._hostless(component, web, key)
                        if emitted >= _CAP:
                            return

                for data in datas:
                    if emitted >= _CAP:
                        return
                    finding = self._per_data(component, data, seen)
                    if finding is not None:
                        emitted += 1
                        yield finding
                    entry = self._custom_scheme(data)
                    if entry is not None:
                        custom.append(entry)

                if emitted >= _CAP:
                    return
                if auto_verify and schemes and not web:
                    key = "autoverify:%s:%s" % (component, ",".join(sorted(set(schemes))))
                    if key not in seen:
                        seen.add(key)
                        emitted += 1
                        yield Finding(
                            check=self.name,
                            title="autoVerify set on a filter with no http(s) scheme",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            category="MASVS-PLATFORM",
                            cwe="CWE-939",
                            description="'%s' declares android:autoVerify=\"true\" on an "
                            "intent-filter whose only schemes are %s. App Link verification only "
                            "runs for http and https, so this filter is not verified and the "
                            "attribute gives no protection." % (component, ", ".join(sorted(set(schemes)))),
                            remediation="Remove autoVerify from non-web filters, or add the http "
                            "and https schemes plus a Digital Asset Links file if these links are "
                            "meant to be verified.",
                            location="AndroidManifest.xml [%s -> %s]" % (component, key),
                            evidence="%s autoVerify=true, schemes=%s"
                            % (component, ",".join(sorted(set(schemes)))),
                            references=_MASVS_REF,
                        )

            if custom and emitted < _CAP:
                key = "custom-schemes:%s" % component
                if key not in seen:
                    seen.add(key)
                    emitted += 1
                    yield self._custom_schemes(component, custom, key)

    def _signature_permissions(self, root: ET.Element) -> Set[str]:
        out: Set[str] = set()
        for perm in root.findall(".//permission"):
            pname = attr(perm, "name")
            level = (attr(perm, "protectionLevel") or "normal").lower()
            if pname and "signature" in level:
                out.add(pname)
        return out

    def _externally_reachable(self, act: ET.Element) -> bool:
        """False for an activity the platform can never launch from a browser.

        An explicit android:exported="false" (mandatory since API 31 for any
        component with an intent-filter) or android:enabled="false" makes the
        filter dead weight, so a leftover BROWSABLE filter on it is not a deep
        link surface at all.
        """
        for name in ("exported", "enabled"):
            raw = attr(act, name)
            if raw is not None and raw.strip().lower() == "false":
                return False
        return True

    def _is_browsable_view(self, ifilter: ET.Element) -> bool:
        cats = {attr(c, "name") for c in ifilter.findall("category")}
        actions = {attr(a, "name") for a in ifilter.findall("action")}
        return (
            "android.intent.category.BROWSABLE" in cats
            and "android.intent.action.VIEW" in actions
        )

    def _hostless(self, component: str, web: List[str], key: str) -> Finding:
        return Finding(
            check=self.name,
            title="Browsable web filter declares a scheme but no host",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="MASVS-PLATFORM",
            cwe="CWE-939",
            description="'%s' has a BROWSABLE VIEW filter with scheme %s and no android:host on "
            "any <data> element. Android combines data attributes as a cross product, so this "
            "filter matches every URL on that scheme: a web page can drive the activity with an "
            "attacker-chosen URL and any WebView or loader behind it follows."
            % (component, "/".join(web)),
            remediation="Add an explicit android:host (and pathPrefix where possible) to every "
            "<data> element, and validate the incoming URI in the activity before using it.",
            location="AndroidManifest.xml [%s -> %s]" % (component, key),
            evidence="%s: BROWSABLE filter scheme=%s with no host" % (component, "/".join(web)),
            references=_MASVS_REF,
        )

    def _per_data(self, component: str, data: ET.Element, seen: Set[str]) -> Optional[Finding]:
        scheme = (attr(data, "scheme") or "").strip().lower()
        if not scheme:
            return None
        host = (attr(data, "host") or "").strip()
        pattern = (attr(data, "pathPattern") or "").strip()
        prefix = (attr(data, "pathPrefix") or "").strip()
        path = (attr(data, "path") or "").strip()
        key = "%s://%s%s" % (scheme, host, path or prefix or pattern)
        # Scoped by component: two activities carrying the same wildcard filter are
        # two findings, not one.
        seen_key = "%s|%s" % (component, key)
        if seen_key in seen:
            return None

        wildcard_host = host == "*" or host.startswith("*.")
        if wildcard_host and (pattern in _WILDCARD_PATTERNS or prefix == "/"):
            seen.add(seen_key)
            return Finding(
                check=self.name,
                title="Deep link matches a wildcard host and every path",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-PLATFORM",
                cwe="CWE-939",
                description="'%s' handles %s with a wildcard host and an unrestricted path "
                "(pathPattern=%r, pathPrefix=%r). Every URL under that host pattern is routed into "
                "the activity, so an attacker-controlled subdomain or path reaches whatever the "
                "activity does with the URI." % (component, key, pattern, prefix),
                remediation="Pin android:host to the exact hosts you own and replace the wildcard "
                "path with a concrete pathPrefix, then validate the URI before acting on it.",
                location="AndroidManifest.xml [%s -> %s]" % (component, key),
                evidence="%s: host=%s pathPattern=%s pathPrefix=%s"
                % (component, host or "(none)", pattern or "(none)", prefix or "(none)"),
                references=_MASVS_REF,
            )

        return None

    def _custom_scheme(self, data: ET.Element) -> Optional[Tuple[str, bool]]:
        """Return (scheme, unrestricted) for a non-framework custom scheme."""
        scheme = (attr(data, "scheme") or "").strip().lower()
        if not scheme or scheme in ("http", "https") or scheme in _FRAMEWORK_SCHEMES:
            return None
        host = (attr(data, "host") or "").strip()
        pattern = (attr(data, "pathPattern") or "").strip()
        prefix = (attr(data, "pathPrefix") or "").strip()
        path = (attr(data, "path") or "").strip()
        wide_host = not host or host == "*" or host.startswith("*.")
        wide_path = not (path or prefix or pattern) or pattern in _WILDCARD_PATTERNS
        return scheme, wide_host and wide_path

    def _custom_schemes(
        self, component: str, entries: List[Tuple[str, bool]], key: str
    ) -> Finding:
        schemes = sorted({scheme for scheme, _wide in entries})
        wide = sorted({scheme for scheme, is_wide in entries if is_wide})
        listed = ", ".join("%s://" % s for s in schemes[:6])
        if len(schemes) > 6:
            listed += ", +%d more" % (len(schemes) - 6)
        if wide:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            extra = (
                "%s match every host and path on the scheme, so the activity is reachable with a "
                "fully attacker-chosen URI." % ", ".join("%s://" % s for s in wide[:4])
            )
        else:
            severity, confidence = Severity.LOW, Confidence.LOW
            extra = (
                "Each filter pins a host or path, which narrows the surface but does not stop "
                "another app from claiming the same scheme."
            )
        return Finding(
            check=self.name,
            title="Browser-reachable custom URI scheme on one activity",
            severity=severity,
            confidence=confidence,
            category="MASVS-PLATFORM",
            cwe="CWE-939",
            description="'%s' registers %s on BROWSABLE filters. Android does not verify "
            "custom-scheme ownership, so any other installed app can declare the same scheme and "
            "receive - or race for - links a web page opens. %s OAuth and vendor SDK callback "
            "schemes are normal and often unavoidable; the point is that every parameter arriving "
            "on them is untrusted input." % (component, listed, extra),
            remediation="Prefer verified App Links (https with android:autoVerify and a Digital "
            "Asset Links file) for anything sensitive, pin android:host on schemes you do control, "
            "and never accept tokens, credentials or redirect targets over a custom scheme without "
            "validating them in the activity.",
            location="AndroidManifest.xml [%s -> %s]" % (component, key),
            evidence="%s: BROWSABLE %s" % (component, listed),
            references=_MASVS_REF,
        )


# ---------------------------------------------------------------------------
# apk.signing_scheme
# ---------------------------------------------------------------------------


@register
class ApkSigningScheme(Check):
    name = "apk.signing_scheme"
    title = "APK signed v1-only (Janus) or with the debug certificate"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        zf = open_apk(apk_path)
        if zf is None:
            return
        with zf:
            has_sf = False
            certs: List[Tuple[str, bytes]] = []
            for name, data in iter_entries(
                zf, _is_signature_entry, max_entries=64, max_bytes=8 * 1024 * 1024
            ):
                upper = name.upper()
                if upper.endswith(".SF"):
                    has_sf = True
                else:
                    certs.append((name, data))

        v1 = has_sf and bool(certs)
        block_ids = _signing_block_ids(apk_path)
        v2 = block_ids is not None and _V2_BLOCK_ID in block_ids
        v3 = block_ids is not None and bool(block_ids & {_V3_BLOCK_ID, _V31_BLOCK_ID})

        root = manifest_tree(apk_path)
        min_sdk = _sdk_versions(root)[0] if root is not None else None
        sdk_note = "minSdkVersion=%s" % (min_sdk if min_sdk is not None else "unknown")

        emitted = 0
        for name, data in certs:
            if emitted >= _SIGNING_CAP:
                return
            if _DEBUG_CERT_MARKER not in data:
                continue
            emitted += 1
            yield Finding(
                check=self.name,
                title="APK signed with the Android debug certificate",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-CODE",
                cwe="CWE-798",
                description="The signature block %s contains the subject 'Android Debug'. The debug "
                "keystore ships with the Android SDK and its private key is identical on every "
                "machine, so anyone can forge an update, sign a trojanised build with the same "
                "identity, and satisfy any signature-level permission the app defines." % name,
                remediation="Re-sign the release build with a private release keystore, rotate any "
                "signature-level permission that trusted the debug identity, and keep the debug "
                "signing config out of the release build type.",
                location=name,
                evidence="%s contains 'Android Debug' in the signer certificate" % name,
                references=_MASVS_REF,
            )
            break

        if emitted >= _SIGNING_CAP:
            return

        if v1 and not v2 and not v3:
            janus = min_sdk is not None and min_sdk < 27
            yield Finding(
                check=self.name,
                title="APK uses v1 JAR signing only",
                severity=Severity.HIGH if janus else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-CODE",
                cwe="CWE-347",
                description="The archive carries META-INF JAR signatures but no APK Signing Block "
                "(no v2 or v3 signature), and %s. v1 signing only covers individual zip entries, "
                "so on API levels below 27 the Janus flaw (CVE-2017-13156) lets an attacker "
                "prepend a DEX file to the APK and keep the signature valid - the device then runs "
                "the attacker's code under the app's identity." % sdk_note,
                remediation="Sign release builds with apksigner using v2 and v3 schemes "
                "(v1SigningEnabled can stay on only for API levels that need it) and raise "
                "minSdkVersion to 27 or higher where possible.",
                location=apk_path,
                evidence="META-INF .SF + signature block present, no APK Signing Block, %s"
                % sdk_note,
                references=_MASVS_REF,
            )
            emitted += 1
        elif not v1 and block_ids is None:
            yield Finding(
                check=self.name,
                title="APK carries no signature at all",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-CODE",
                cwe="CWE-347",
                description="No META-INF JAR signature and no APK Signing Block were found, so the "
                "archive is unsigned. An unsigned APK cannot be installed by the platform and, more "
                "importantly for analysis, its contents carry no integrity guarantee - anything in "
                "it may have been modified after the build.",
                remediation="Sign the APK with apksigner before distributing it, and re-run this "
                "scan against the artefact you actually ship.",
                location=apk_path,
                evidence="no META-INF signature, no 'APK Sig Block 42'",
                references=_MASVS_REF,
            )
            emitted += 1

        if emitted >= _SIGNING_CAP:
            return
        if v2 and not v3:
            yield Finding(
                check=self.name,
                title="APK signed with v2 but not v3",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="MASVS-CODE",
                description="The APK Signing Block contains a v2 signature (0x7109871a) but no v3 "
                "block. v3 is what carries the signing-certificate lineage, so without it the app "
                "cannot rotate its signing key without breaking updates.",
                remediation="Enable v3 signing in the release signing config so a future key "
                "rotation stays possible.",
                location=apk_path,
                evidence="APK Signing Block ids: %s"
                % ", ".join(sorted("0x%08x" % i for i in (block_ids or set()))),
                references=_MASVS_REF,
            )


def _is_signature_entry(name: str) -> bool:
    upper = name.upper()
    if not upper.startswith("META-INF/") or upper.count("/") != 1:
        return False
    return upper.endswith((".SF", ".RSA", ".DSA", ".EC"))


def _signing_block_ids(apk_path: str) -> Optional[Set[int]]:
    """Return the id set of the APK Signing Block, or None when there is none."""
    try:
        with open(apk_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size < 32:
                return None
            tail_len = min(size, _EOCD_SCAN_BYTES)
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
            idx = tail.rfind(b"PK\x05\x06")
            if idx < 0 or idx + 20 > len(tail):
                return None
            cd_offset = struct.unpack_from("<I", tail, idx + 16)[0]
            if cd_offset < 32 or cd_offset > size:
                return None
            fh.seek(cd_offset - 16)
            if fh.read(16) != _SIG_BLOCK_MAGIC:
                return None
            fh.seek(cd_offset - 24)
            raw = fh.read(8)
            if len(raw) != 8:
                return None
            block_size = struct.unpack("<Q", raw)[0]
            block_start = cd_offset - 8 - block_size
            if not 0 < block_start < cd_offset:
                return None
            pairs_start = block_start + 8
            pairs_end = cd_offset - 24
            if pairs_end <= pairs_start or pairs_end - pairs_start > _MAX_PAIR_REGION:
                return None
            fh.seek(pairs_start)
            pairs = fh.read(pairs_end - pairs_start)
    except (OSError, ValueError, struct.error, OverflowError):
        return None

    ids: Set[int] = set()
    cursor = 0
    end = len(pairs)
    for _ in range(_MAX_SIG_PAIRS):
        if cursor + 12 > end:
            break
        try:
            pair_len = struct.unpack_from("<Q", pairs, cursor)[0]
            pair_id = struct.unpack_from("<I", pairs, cursor + 8)[0]
        except struct.error:
            break
        if pair_len < 4:
            break
        nxt = cursor + 8 + pair_len
        if nxt <= cursor or nxt > end:
            break
        ids.add(pair_id)
        cursor = nxt
    return ids
