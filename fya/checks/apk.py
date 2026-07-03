from __future__ import annotations

import re
import zipfile
from urllib.parse import urlsplit

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
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "10.0.2.2", "schemas.android.com"}

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
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOCAL_HOSTS


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
        yield from self._deeplinks(apk, apk_path)
        yield from self._weak_custom_permissions(apk, apk_path)

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

    def _exported(self, apk, apk_path):
        try:
            manifest = apk.get_android_manifest_xml()
        except Exception:
            manifest = None
        if manifest is None:
            return
        android_ns = "http://schemas.android.com/apk/res/android"
        name_key = "{%s}name" % android_ns
        exported_key = "{%s}exported" % android_ns
        permission_key = "{%s}permission" % android_ns
        reported = 0
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in manifest.findall(".//" + kind):
                if reported >= _MAX_MATCHES_PER_PATTERN:
                    return
                component = node.get(name_key)
                if not component:
                    continue
                exported = node.get(exported_key)
                has_intent_filter = node.find("intent-filter") is not None
                if exported is not None:
                    if not self._bool_attr(exported):
                        continue
                elif not has_intent_filter:
                    continue
                if node.get(permission_key):
                    continue
                if exported is not None:
                    reason = "android:exported=true"
                    evidence = f"{kind} {component} exported=true, no permission"
                else:
                    reason = "an intent-filter and no explicit android:exported, so it is exported by default"
                    evidence = f"{kind} {component} exported by default via intent-filter, no permission"
                reported += 1
                yield Finding(
                    check=self.name,
                    title=f"Exported {kind} without permission guard",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="MASVS-PLATFORM",
                    cwe="CWE-926",
                    description=f"The {kind} '{component}' has {reason} and no "
                    "permission requirement, so other apps on the device can invoke it directly.",
                    remediation="Set android:exported to false if external access is not required, or "
                    "protect the component with a signature-level permission.",
                    location="AndroidManifest.xml",
                    evidence=evidence,
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

    def _deeplinks(self, apk, apk_path):
        try:
            manifest = apk.get_android_manifest_xml()
        except Exception:
            manifest = None
        if manifest is None:
            return
        ns = "http://schemas.android.com/apk/res/android"
        name_key = "{%s}name" % ns
        scheme_key = "{%s}scheme" % ns
        host_key = "{%s}host" % ns
        autoverify_key = "{%s}autoVerify" % ns
        reported = 0
        activities = manifest.findall(".//activity") + manifest.findall(".//activity-alias")
        for act in activities:
            if reported >= _MAX_MATCHES_PER_PATTERN:
                return
            for ifilter in act.findall("intent-filter"):
                cats = {c.get(name_key) for c in ifilter.findall("category")}
                if "android.intent.category.BROWSABLE" not in cats:
                    continue
                autoverify = str(ifilter.get(autoverify_key) or act.get(autoverify_key) or "").lower() == "true"
                if autoverify:
                    continue
                for data in ifilter.findall("data"):
                    scheme = (data.get(scheme_key) or "").lower()
                    host = data.get(host_key)
                    if scheme in ("http", "https") and host:
                        reported += 1
                        yield Finding(
                            check=self.name,
                            title=f"Unverified App Link ({scheme}://{host})",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category="MASVS-PLATFORM",
                            cwe="CWE-927",
                            description=f"An activity handles {scheme}://{host} links via a BROWSABLE "
                            "intent-filter without android:autoVerify=\"true\". Without verified App Links, "
                            "any other app can register the same host and intercept these links, enabling "
                            "deep-link hijacking and phishing.",
                            remediation="Set android:autoVerify=\"true\" and publish a Digital Asset Links "
                            "file, or do not handle web links you do not own.",
                            location="AndroidManifest.xml",
                            evidence=f"{act.get(name_key)} handles {scheme}://{host}, autoVerify not set",
                            references=_MASVS_REF,
                        )
                        break

    def _weak_custom_permissions(self, apk, apk_path):
        try:
            manifest = apk.get_android_manifest_xml()
        except Exception:
            manifest = None
        if manifest is None:
            return
        ns = "http://schemas.android.com/apk/res/android"
        name_key = "{%s}name" % ns
        level_key = "{%s}protectionLevel" % ns
        perm_key = "{%s}permission" % ns
        read_key = "{%s}readPermission" % ns
        write_key = "{%s}writePermission" % ns

        weak = {}
        for perm in manifest.findall(".//permission"):
            pname = perm.get(name_key)
            if not pname:
                continue
            level = (perm.get(level_key) or "normal").lower()
            if "signature" not in level:
                weak[pname] = level or "normal"
        if not weak:
            return
        reported = 0
        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for node in manifest.findall(".//" + kind):
                if reported >= _MAX_MATCHES_PER_PATTERN:
                    return
                component = node.get(name_key)
                for guard in (node.get(perm_key), node.get(read_key), node.get(write_key)):
                    if guard and guard in weak:
                        reported += 1
                        yield Finding(
                            check=self.name,
                            title=f"Exported {kind} guarded by weak custom permission",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category="MASVS-PLATFORM",
                            cwe="CWE-280",
                            description=f"The {kind} '{component}' is protected by the app-defined permission "
                            f"'{guard}' whose protectionLevel is '{weak[guard]}'. 'normal' is auto-granted to "
                            "any installed app and 'dangerous' is obtainable via a prompt, so the guard does "
                            "not actually restrict access from other apps.",
                            remediation="Declare custom permissions that guard sensitive components with "
                            "protectionLevel=\"signature\".",
                            location="AndroidManifest.xml",
                            evidence=f"{kind} {component} permission={guard} protectionLevel={weak[guard]}",
                            references=_MASVS_REF,
                        )
                        break


_WEBVIEW_JS_BRIDGE = ("addJavascriptInterface", "setJavaScriptEnabled")
_WEBVIEW_FILE_ACCESS = ("setAllowUniversalAccessFromFileURLs", "setAllowFileAccessFromFileURLs")


@register
class ApkWebView(Check):
    name = "apk.webview_config"
    title = "Insecure WebView configuration"
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
        found = set()
        with archive:
            for name in archive.namelist()[:_MAX_FILES_SCANNED]:
                if not (name == "classes.dex" or (name.startswith("classes") and name.endswith(".dex"))):
                    continue
                try:
                    info = archive.getinfo(name)
                    if info.file_size > _MAX_BYTES_PER_ENTRY:
                        continue
                    text = _decode(archive.read(name))
                except (OSError, zipfile.BadZipFile, RuntimeError, KeyError):
                    continue
                for keyword in _WEBVIEW_JS_BRIDGE + _WEBVIEW_FILE_ACCESS:
                    if keyword in text:
                        found.add(keyword)

        if all(k in found for k in _WEBVIEW_JS_BRIDGE):
            yield Finding(
                check=self.name,
                title="WebView exposes a native JavaScript bridge",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="MASVS-PLATFORM",
                cwe="CWE-749",
                description="The app calls both addJavascriptInterface and setJavaScriptEnabled, exposing "
                "native methods to JavaScript running in a WebView. If the WebView loads any untrusted or "
                "cleartext content, this bridge can be abused to invoke app code.",
                remediation="Avoid addJavascriptInterface for untrusted content; annotate exposed methods "
                "with @JavascriptInterface, target modern SDKs, and load only trusted HTTPS content.",
                location="classes.dex",
                evidence="addJavascriptInterface + setJavaScriptEnabled present",
                references=_MASVS_REF,
            )
        for keyword in _WEBVIEW_FILE_ACCESS:
            if keyword in found:
                yield Finding(
                    check=self.name,
                    title=f"WebView enables {keyword}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="MASVS-PLATFORM",
                    cwe="CWE-749",
                    description=f"The app references {keyword}, which relaxes WebView file-access rules. "
                    "Enabling file:// access from web content can allow cross-origin reads of local files "
                    "and exfiltration of app-private data.",
                    remediation="Leave file access settings at their secure defaults (false) unless strictly "
                    "required, and never combine them with loading remote content.",
                    location="classes.dex",
                    evidence=f"{keyword} referenced in dex",
                    references=_MASVS_REF,
                )
