from __future__ import annotations

import sys
import types
from xml.etree import ElementTree as ET

from fya.checks.apk import ApkManifest
from fya.models import Profile, ScanContext, Severity, Target, TargetKind

_MANIFEST_XML = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application>
    <activity android:name="com.example.app.OpenActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
      </intent-filter>
    </activity>
    <activity android:name="com.example.app.PrivateActivity" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"""


class _FakeApk:
    def __init__(self, *args, **kwargs):
        self._root = ET.fromstring(_MANIFEST_XML)

    def get_android_manifest_xml(self):
        return self._root

    def get_attribute_value(self, tag, attr):
        return None

    def get_permissions(self):
        return []

    def get_min_sdk_version(self):
        return None

    def get_activities(self):
        return []

    def get_services(self):
        return []

    def get_receivers(self):
        return []

    def get_providers(self):
        return []


def _make_module_tree(apk_cls):
    androguard = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    apk_mod = types.ModuleType("androguard.core.apk")
    apk_mod.APK = apk_cls
    androguard.core = core
    core.apk = apk_mod
    return {
        "androguard": androguard,
        "androguard.core": core,
        "androguard.core.apk": apk_mod,
    }


class _RaisingApkModule(types.ModuleType):
    def __getattr__(self, item):
        raise ImportError("androguard not available")


def _make_ctx(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"not-a-real-apk")
    target = Target(raw=str(apk_path), kind=TargetKind.APK, apk_path=str(apk_path))
    return ScanContext(target=target, profile=Profile.PASSIVE)


def test_implicit_exported_detection(tmp_path, monkeypatch):
    modules = _make_module_tree(_FakeApk)
    for mod_name, mod in modules.items():
        monkeypatch.setitem(sys.modules, mod_name, mod)

    ctx = _make_ctx(tmp_path)
    findings = list(ApkManifest().run(ctx))

    exported = [f for f in findings if "Exported" in f.title]
    assert len(exported) == 1
    finding = exported[0]
    assert "OpenActivity" in finding.evidence
    assert "PrivateActivity" not in finding.evidence
    assert finding.severity is Severity.MEDIUM
    assert "exported by default" in finding.evidence


def test_graceful_degradation_without_androguard(tmp_path, monkeypatch):
    raising = _RaisingApkModule("androguard.core.apk")
    monkeypatch.setitem(sys.modules, "androguard", types.ModuleType("androguard"))
    monkeypatch.setitem(sys.modules, "androguard.core", types.ModuleType("androguard.core"))
    monkeypatch.setitem(sys.modules, "androguard.core.apk", raising)

    ctx = _make_ctx(tmp_path)
    findings = list(ApkManifest().run(ctx))

    assert len(findings) == 1
    only = findings[0]
    assert only.severity is Severity.INFO
    assert "androguard not installed" in only.title
