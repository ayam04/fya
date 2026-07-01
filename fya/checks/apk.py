from __future__ import annotations

import re
import zipfile

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_MAX_MATCHES_PER_PATTERN = 8
_MAX_FILES_SCANNED = 4000
_MAX_BYTES_PER_ENTRY = 6 * 1024 * 1024
_MIN_SDK_FLOOR = 24

_SCANNABLE_SUFFIXES = (
    ".dex",
    ".arsc",
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".js",
    ".html",
    ".so",
    ".cfg",
    ".yaml",
    ".yml",
)
_SCANNABLE_PREFIXES = ("assets/", "res/raw/", "res/values")

_SECRET_PATTERNS = {
    "AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Firebase database URL": re.compile(r"https?://[a-z0-9.\-]+\.firebaseio\.com"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
}

_CLEARTEXT_URL = re.compile(r"http://[a-zA-Z0-9._\-]+(?:/[^\s\"'<>\\]*)?")
_LOCAL_HOST_HINTS = ("://localhost", "://127.0.0.1", "://10.0.2.2", "://schemas.android.com")

_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}

_MASVS_REF = ["https://mas.owasp.org/MASVS/", "https://mas.owasp.org/MASTG/"]


def _silence_androguard() -> None:
    import logging

    logging.getLogger("androguard").setLevel(logging.ERROR)
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:
        pass


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "ignore")


def _should_scan(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(_SCANNABLE_SUFFIXES):
        return True
    if any(lowered.startswith(prefix) for prefix in _SCANNABLE_PREFIXES):
        return True
    if lowered == "classes.dex":
        return True
    return False


def _is_ignorable_cleartext(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in _LOCAL_HOST_HINTS)


@register
class ApkContentSecrets(Check):
    name = "apk.hardcoded_secrets"
    title = "Hardcoded secrets in APK contents"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        try:
            archive = zipfile.ZipFile(apk_path)
        except (OSError, zipfile.BadZipFile) as exc:
            yield Finding(
                check=self.name,
                title="APK archive could not be opened",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                description=f"The APK at {apk_path} could not be read as a zip archive ({exc}).",
                remediation="Verify the file is a valid APK.",
                location=apk_path,
            )
            return

        found_counts = {label: 0 for label in _SECRET_PATTERNS}
        with archive:
            names = archive.namelist()[:_MAX_FILES_SCANNED]
            for name in names:
                if not _should_scan(name):
                    continue
                try:
                    info = archive.getinfo(name)
                except KeyError:
                    continue
                if info.file_size > _MAX_BYTES_PER_ENTRY:
                    continue
                try:
                    text = _decode(archive.read(name))
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue
                for label, pattern in _SECRET_PATTERNS.items():
                    if found_counts[label] >= _MAX_MATCHES_PER_PATTERN:
                        continue
                    for match in pattern.finditer(text):
                        found_counts[label] += 1
                        token = match.group(0)
                        redacted = token[:6] + "..." if len(token) > 10 else token
                        yield Finding(
                            check=self.name,
                            title=f"{label} embedded in app package",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category="MASVS-STORAGE",
                            cwe="CWE-798",
                            description=f"A value matching {label} was found inside {name}. "
                            "Hardcoded credentials shipped in an APK are trivially recoverable and "
                            "should be treated as compromised.",
                            remediation="Remove credentials from the package, rotate the exposed "
                            "secret, and fetch runtime secrets from a protected backend.",
                            location=name,
                            evidence=f"{label}: {redacted}",
                            references=_MASVS_REF,
                        )
                        if found_counts[label] >= _MAX_MATCHES_PER_PATTERN:
                            break


@register
class ApkCleartextUrls(Check):
    name = "apk.cleartext_urls"
    title = "Cleartext HTTP URLs in APK contents"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        try:
            archive = zipfile.ZipFile(apk_path)
        except (OSError, zipfile.BadZipFile):
            return

        seen = set()
        emitted = 0
        with archive:
            names = archive.namelist()[:_MAX_FILES_SCANNED]
            for name in names:
                if emitted >= _MAX_MATCHES_PER_PATTERN:
                    break
                if not _should_scan(name):
                    continue
                try:
                    info = archive.getinfo(name)
                except KeyError:
                    continue
                if info.file_size > _MAX_BYTES_PER_ENTRY:
                    continue
                try:
                    text = _decode(archive.read(name))
                except (OSError, zipfile.BadZipFile, RuntimeError):
                    continue
                for match in _CLEARTEXT_URL.finditer(text):
                    url = match.group(0)
                    if _is_ignorable_cleartext(url):
                        continue
                    if url in seen:
                        continue
                    seen.add(url)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title="Cleartext HTTP endpoint referenced in app",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        category="MASVS-NETWORK",
                        cwe="CWE-319",
                        description=f"The app package references a plaintext HTTP URL ({url}) in {name}. "
                        "Traffic to this endpoint can be intercepted or tampered with on the network.",
                        remediation="Use HTTPS for all endpoints and disable cleartext traffic in the "
                        "network security configuration.",
                        location=name,
                        evidence=url,
                        references=_MASVS_REF,
                    )
                    if emitted >= _MAX_MATCHES_PER_PATTERN:
                        break


@register
class ApkManifest(Check):
    name = "apk.manifest"
    title = "Android manifest configuration"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        try:
            from androguard.core.apk import APK

            _silence_androguard()
        except ImportError:
            yield Finding(
                check=self.name,
                title="Manifest analysis skipped (androguard not installed)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="MASVS-PLATFORM",
                description="Manifest-derived checks require androguard, which is not installed. "
                "Install the [apk] extra to enable AndroidManifest.xml analysis.",
                remediation="Install the optional dependency, for example: pip install fya[apk].",
                location=apk_path,
                references=_MASVS_REF,
            )
            return

        try:
            apk = APK(apk_path)
        except Exception as exc:
            yield Finding(
                check=self.name,
                title="Manifest could not be parsed",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                category="MASVS-PLATFORM",
                description=f"androguard failed to parse the manifest of {apk_path} ({exc}).",
                remediation="Verify the APK is well formed.",
                location=apk_path,
            )
            return

        yield from self._debuggable(apk, apk_path)
        yield from self._allow_backup(apk, apk_path)
        yield from self._cleartext(apk, apk_path)
        yield from self._exported(apk, apk_path)
        yield from self._min_sdk(apk, apk_path)
        yield from self._permissions(apk, apk_path)

    def _bool_attr(self, value) -> bool:
        return str(value).strip().lower() == "true"

    def _debuggable(self, apk, apk_path):
        value = apk.get_attribute_value("application", "debuggable")
        if value is not None and self._bool_attr(value):
            yield Finding(
                check=self.name,
                title="Application is debuggable",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-CODE",
                cwe="CWE-489",
                description="android:debuggable is set to true. A debuggable build lets anyone attach "
                "a debugger, read memory, and manipulate the running app on a device.",
                remediation="Set android:debuggable to false (the default) for release builds.",
                location="AndroidManifest.xml",
                evidence="application@android:debuggable=true",
                references=_MASVS_REF,
            )

    def _allow_backup(self, apk, apk_path):
        value = apk.get_attribute_value("application", "allowBackup")
        if value is not None and self._bool_attr(value):
            yield Finding(
                check=self.name,
                title="Application data backup is allowed",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-STORAGE",
                cwe="CWE-530",
                description="android:allowBackup is true, so app data can be extracted via adb backup "
                "on unlocked or rooted devices, potentially exposing sensitive data.",
                remediation="Set android:allowBackup to false, or define a restrictive backup rules set.",
                location="AndroidManifest.xml",
                evidence="application@android:allowBackup=true",
                references=_MASVS_REF,
            )

    def _cleartext(self, apk, apk_path):
        cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
        nsc = apk.get_attribute_value("application", "networkSecurityConfig")
        if cleartext is not None and self._bool_attr(cleartext):
            yield Finding(
                check=self.name,
                title="Cleartext network traffic is permitted",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-NETWORK",
                cwe="CWE-319",
                description="android:usesCleartextTraffic is true, allowing the app to send data over "
                "unencrypted HTTP, which is exposed to interception and tampering.",
                remediation="Set usesCleartextTraffic to false and use HTTPS with a network security config.",
                location="AndroidManifest.xml",
                evidence="application@android:usesCleartextTraffic=true",
                references=_MASVS_REF,
            )
        elif cleartext is None and not nsc:
            yield Finding(
                check=self.name,
                title="No network security configuration defined",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="MASVS-NETWORK",
                cwe="CWE-319",
                description="Neither usesCleartextTraffic nor a networkSecurityConfig is declared. "
                "Depending on the target SDK, cleartext traffic may be permitted by default.",
                remediation="Declare a network security configuration that disables cleartext traffic.",
                location="AndroidManifest.xml",
                evidence="no networkSecurityConfig and no usesCleartextTraffic attribute",
                references=_MASVS_REF,
            )

    def _permission_guarded_map(self, apk) -> dict:
        guarded = {}
        try:
            manifest = apk.get_android_manifest_xml()
        except Exception:
            return guarded
        if manifest is None:
            return guarded
        android_ns = "http://schemas.android.com/apk/res/android"
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in manifest.findall(".//" + tag):
                name = node.get("{%s}name" % android_ns)
                if not name:
                    continue
                perm = node.get("{%s}permission" % android_ns)
                guarded[(tag, name)] = bool(perm)
        return guarded

    def _exported(self, apk, apk_path):
        guarded = self._permission_guarded_map(apk)
        getters = (
            ("activity", getattr(apk, "get_activities", None)),
            ("service", getattr(apk, "get_services", None)),
            ("receiver", getattr(apk, "get_receivers", None)),
            ("provider", getattr(apk, "get_providers", None)),
        )
        reported = 0
        for kind, getter in getters:
            if not callable(getter):
                continue
            try:
                components = getter() or []
            except Exception:
                components = []
            for component in components:
                if reported >= _MAX_MATCHES_PER_PATTERN:
                    return
                exported = None
                try:
                    exported = apk.get_element(kind, "exported", name=component)
                except Exception:
                    exported = None
                if exported is None or not self._bool_attr(exported):
                    continue
                if guarded.get((kind, component)):
                    continue
                reported += 1
                yield Finding(
                    check=self.name,
                    title=f"Exported {kind} without permission guard",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="MASVS-PLATFORM",
                    cwe="CWE-926",
                    description=f"The {kind} '{component}' is exported (android:exported=true) with no "
                    "permission requirement, so other apps on the device can invoke it directly.",
                    remediation="Set android:exported to false if external access is not required, or "
                    "protect the component with a signature-level permission.",
                    location="AndroidManifest.xml",
                    evidence=f"{kind} {component} exported=true, no permission",
                    references=_MASVS_REF,
                )

    def _min_sdk(self, apk, apk_path):
        raw = None
        try:
            raw = apk.get_min_sdk_version()
        except Exception:
            raw = None
        if raw is None:
            return
        try:
            min_sdk = int(raw)
        except (TypeError, ValueError):
            return
        if min_sdk < _MIN_SDK_FLOOR:
            yield Finding(
                check=self.name,
                title=f"Low minSdkVersion ({min_sdk})",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="MASVS-PLATFORM",
                description=f"minSdkVersion is {min_sdk}, below API {_MIN_SDK_FLOOR}. Older Android "
                "versions lack current platform hardening and receive no security updates.",
                remediation=f"Raise minSdkVersion to {_MIN_SDK_FLOOR} or higher where feasible.",
                location="AndroidManifest.xml",
                evidence=f"minSdkVersion={min_sdk}",
                references=_MASVS_REF,
            )

    def _permissions(self, apk, apk_path):
        try:
            permissions = apk.get_permissions() or []
        except Exception:
            permissions = []
        flagged = sorted({p for p in permissions if p in _DANGEROUS_PERMISSIONS})
        if flagged:
            yield Finding(
                check=self.name,
                title="Sensitive permissions requested",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="MASVS-PLATFORM",
                description="The app requests permissions that grant access to sensitive user data or "
                "device capabilities. Confirm each one is required and justified.",
                remediation="Request only the permissions the app genuinely needs and document their use.",
                location="AndroidManifest.xml",
                evidence=", ".join(flagged[:_MAX_MATCHES_PER_PATTERN]),
                references=_MASVS_REF,
            )
