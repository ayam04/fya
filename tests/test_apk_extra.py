from __future__ import annotations

import zipfile
from xml.etree import ElementTree as ET

from fya.checks.apk import ApkManifest
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile

_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <permission android:name="com.x.CUSTOM" android:protectionLevel="normal"/>
  <application>
    <activity android:name=".DeepActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="app.example.com"/>
      </intent-filter>
    </activity>
    <activity android:name=".VerifiedActivity">
      <intent-filter android:autoVerify="true">
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="safe.example.com"/>
      </intent-filter>
    </activity>
    <service android:name=".Svc" android:permission="com.x.CUSTOM"/>
  </application>
</manifest>"""


class _FakeApk:
    def __init__(self, xml):
        self._root = ET.fromstring(xml)

    def get_android_manifest_xml(self):
        return self._root


def _apk_with_dex(tmp_path, dex_bytes):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", dex_bytes)
    return str(path)


def test_webview_js_bridge_fires(tmp_path):
    path = _apk_with_dex(tmp_path, b"dex\n...Landroid/webkit/WebView;addJavascriptInterface..setJavaScriptEnabled..")
    result = run_scan(detect_target(path), profile=Profile.SAFE, detect_external=False, categories={"apk"})
    assert any(f.check == "apk.webview_config" and "bridge" in f.title.lower() for f in result.findings)


def test_webview_clean_apk(tmp_path):
    path = _apk_with_dex(tmp_path, b"nothing security relevant in this dex blob")
    result = run_scan(detect_target(path), profile=Profile.SAFE, detect_external=False, categories={"apk"})
    assert not any(f.check == "apk.webview_config" for f in result.findings)


def test_deeplinks_flag_unverified_only():
    findings = list(ApkManifest()._deeplinks(_FakeApk(_MANIFEST), "app.apk"))
    hosts = " ".join(f.evidence for f in findings)
    assert "app.example.com" in hosts
    assert "safe.example.com" not in hosts  # autoVerify=true must not be flagged


def test_weak_custom_permission_fires():
    findings = list(ApkManifest()._weak_custom_permissions(_FakeApk(_MANIFEST), "app.apk"))
    assert any("com.x.CUSTOM" in f.evidence for f in findings)


def test_signature_permission_not_flagged():
    manifest = _MANIFEST.replace('protectionLevel="normal"', 'protectionLevel="signature"')
    findings = list(ApkManifest()._weak_custom_permissions(_FakeApk(manifest), "app.apk"))
    assert not findings
