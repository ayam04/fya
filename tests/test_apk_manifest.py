from __future__ import annotations

import struct
import sys
import types
import zipfile
from xml.etree import ElementTree as ET

from fya.checks._apk_common import iter_entries, read_axml
from fya.checks.apk import ApkManifest
from fya.detect import detect_target
from fya.engine import run_scan
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


# ---------------------------------------------------------------------------
# AXML encoder: builds real binary XML so the shipped decoder is exercised
# ---------------------------------------------------------------------------

_START_NS = 0x0100
_END_NS = 0x0101
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103
_CDATA = 0x0104


class _Pool:
    def __init__(self):
        self.items = []
        self.index = {}

    def add(self, value):
        if value not in self.index:
            self.index[value] = len(self.items)
            self.items.append(value)
        return self.index[value]


def _split_key(key):
    if key.startswith("{"):
        uri, _, name = key[1:].partition("}")
        return uri, name
    return "", key


def _node_header(ctype, size):
    return struct.pack("<HHIII", ctype, 16, size, 1, 0xFFFFFFFF)


def _encode_pool(items):
    data = b""
    offsets = []
    for text in items:
        offsets.append(len(data))
        data += struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    count = len(items)
    strings_start = 28 + 4 * count
    size = strings_start + len(data)
    header = struct.pack("<HHIIIIII", 0x0001, 28, size, count, 0, 0, strings_start, 0)
    return header + b"".join(struct.pack("<I", off) for off in offsets) + data


def _encode_element(elem, pool):
    uri, name = _split_key(elem.tag)
    ns_idx = pool.add(uri) if uri else 0xFFFFFFFF
    name_idx = pool.add(name)
    attrs = b""
    count = 0
    for key, value in elem.attrib.items():
        a_uri, a_name = _split_key(key)
        a_ns = pool.add(a_uri) if a_uri else 0xFFFFFFFF
        a_name_idx = pool.add(a_name)
        value_idx = pool.add(value)
        attrs += struct.pack("<IIIHBBI", a_ns, a_name_idx, value_idx, 8, 0, 3, value_idx)
        count += 1
    size = 36 + 20 * count
    body = struct.pack("<IIHHHHHH", ns_idx, name_idx, 20, 20, count, 0, 0, 0)
    out = _node_header(_START_ELEMENT, size) + body + attrs
    text = (elem.text or "").strip()
    if text:
        text_idx = pool.add(text)
        out += (
            _node_header(_CDATA, 28)
            + struct.pack("<I", text_idx)
            + struct.pack("<HBBI", 8, 0, 3, text_idx)
        )
    for child in elem:
        out += _encode_element(child, pool)
    out += _node_header(_END_ELEMENT, 24) + struct.pack("<II", ns_idx, name_idx)
    return out


def _encode_axml(xml_text):
    root = ET.fromstring(xml_text)
    pool = _Pool()
    uris = []
    for elem in root.iter():
        for key in elem.attrib:
            uri, _name = _split_key(key)
            if uri and uri not in uris:
                uris.append(uri)

    body = b""
    for uri in uris:
        body += _node_header(_START_NS, 24) + struct.pack(
            "<II", pool.add("android"), pool.add(uri)
        )
    body += _encode_element(root, pool)
    for uri in reversed(uris):
        body += _node_header(_END_NS, 24) + struct.pack("<II", pool.add("android"), pool.add(uri))

    pool_chunk = _encode_pool(pool.items)
    total = 8 + len(pool_chunk) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool_chunk + body


# ---------------------------------------------------------------------------
# APK builders
# ---------------------------------------------------------------------------


def _build_apk(tmp_path, filename, manifest=None, res_xml=None, raw=None, dex=b"dex-blob"):
    path = tmp_path / filename
    with zipfile.ZipFile(path, "w") as zf:
        if manifest is not None:
            zf.writestr("AndroidManifest.xml", _encode_axml(manifest))
        for name, text in (res_xml or {}).items():
            zf.writestr(name, _encode_axml(text))
        for name, payload in (raw or {}).items():
            zf.writestr(name, payload)
        if dex is not None:
            zf.writestr("classes.dex", dex)
    return str(path)


def _inject_signing_block(path, block_ids):
    with open(path, "rb") as fh:
        data = fh.read()
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]

    pairs = b""
    for block_id in block_ids:
        payload = b"\x00" * 16
        pairs += struct.pack("<Q", 4 + len(payload)) + struct.pack("<I", block_id) + payload
    block_size = len(pairs) + 8 + 16
    block = (
        struct.pack("<Q", block_size)
        + pairs
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    new = data[:cd_offset] + block + data[cd_offset:]
    new_eocd = eocd + len(block)
    new = (
        new[: new_eocd + 16]
        + struct.pack("<I", cd_offset + len(block))
        + new[new_eocd + 20 :]
    )
    with open(path, "wb") as fh:
        fh.write(new)
    return path


def _scan(path):
    return run_scan(
        detect_target(path),
        profile=Profile.PASSIVE,
        detect_external=False,
        categories={"apk"},
    )


def _of(result, check):
    return [f for f in result.findings if f.check == check]


_MIN_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.min">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false"/>
</manifest>"""


# ---------------------------------------------------------------------------
# helper-level tests
# ---------------------------------------------------------------------------


def test_read_axml_round_trip_and_rejects_malformed():
    blob = _encode_axml(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.rt">
  <application android:allowBackup="true"><activity android:name=".A"/></application>
</manifest>"""
    )
    root = read_axml(blob)
    assert root is not None
    assert root.tag == "manifest"
    assert root.get("package") == "com.rt"
    app = root.find("application")
    assert app.get("{http://schemas.android.com/apk/res/android}allowBackup") == "true"

    # A truncated chunk must yield None, never an exception.
    assert read_axml(blob[: len(blob) // 2]) is None
    assert read_axml(b"\x03\x00\x08\x00\xff\xff\xff\xff") is None
    assert read_axml(b"") is None
    assert read_axml(b"not xml at all") is None


def test_iter_entries_applies_predicate_before_the_cap(tmp_path):
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(50):
            zf.writestr("filler/%03d.bin" % i, b"x")
        zf.writestr("res/xml/wanted.xml", b"payload")
    with zipfile.ZipFile(path) as zf:
        got = list(iter_entries(zf, lambda n: n.startswith("res/xml/"), max_entries=2))
    assert got == [("res/xml/wanted.xml", b"payload")]


# ---------------------------------------------------------------------------
# apk.network_security_config
# ---------------------------------------------------------------------------

_NSC_BAD = """<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="user"/>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">api.example.com</domain>
    <trust-anchors>
      <certificates src="@raw/mycert"/>
    </trust-anchors>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>"""

_NSC_GOOD = """<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2035-01-01">
      <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
      <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
    </pin-set>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>"""


def test_network_security_config_fires(tmp_path):
    path = _build_apk(
        tmp_path,
        "nsc_bad.apk",
        manifest=_MIN_MANIFEST,
        res_xml={"res/xml/network_security_config.xml": _NSC_BAD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.network_security_config")
    titles = [f.title for f in found]

    user_ca = [f for f in found if "user-installed CAs" in f.title]
    assert len(user_ca) == 1, titles
    assert user_ca[0].severity is Severity.HIGH

    cleartext = [f for f in found if "permits cleartext" in f.title]
    assert len(cleartext) == 1, titles
    assert cleartext[0].severity is Severity.MEDIUM
    assert "api.example.com" in cleartext[0].evidence

    assert any("custom trust anchor" in t for t in titles), titles
    assert any("No certificate pinning" in t for t in titles), titles


def test_network_security_config_silent_on_hardened_app(tmp_path):
    path = _build_apk(
        tmp_path,
        "nsc_good.apk",
        manifest=_MIN_MANIFEST,
        res_xml={"res/xml/network_security_config.xml": _NSC_GOOD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.network_security_config") == []


def test_network_security_config_ignores_unrelated_res_xml(tmp_path):
    path = _build_apk(
        tmp_path,
        "nsc_none.apk",
        manifest=_MIN_MANIFEST,
        res_xml={
            "res/xml/preferences.xml": "<PreferenceScreen><CheckBoxPreference/></PreferenceScreen>",
        },
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.network_security_config") == []


# ---------------------------------------------------------------------------
# apk.provider_exposure
# ---------------------------------------------------------------------------

_PROVIDER_BAD = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <provider android:name=".ReadOnlyGuard" android:authorities="com.example.app.ro"
              android:exported="true" android:readPermission="com.example.app.READ"/>
    <provider android:name=".GrantAll" android:authorities="com.example.app.grant"
              android:exported="true" android:grantUriPermissions="true"/>
    <provider android:name=".GrantWide" android:authorities="com.example.app.wide"
              android:exported="true" android:grantUriPermissions="true">
      <grant-uri-permission android:pathPattern=".*"/>
    </provider>
    <provider android:name=".MultiProc" android:authorities="com.example.app.mp"
              android:exported="true" android:permission="com.example.app.P"
              android:multiprocess="true"/>
    <provider android:name="androidx.core.content.FileProvider"
              android:authorities="com.example.app.files" android:exported="false"
              android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/file_paths"/>
    </provider>
  </application>
</manifest>"""

_PROVIDER_GOOD = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.safe">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <provider android:name=".Internal" android:authorities="com.example.safe.i"
              android:exported="false"/>
    <provider android:name="androidx.startup.InitializationProvider"
              android:authorities="com.example.safe.androidx-startup"
              android:exported="true" android:readPermission="android.permission.DUMP"/>
    <provider android:name=".SafeFileProvider" android:authorities="com.example.safe.files"
              android:exported="false" android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/file_paths"/>
    </provider>
  </application>
</manifest>"""

_PATHS_BAD = """<paths>
  <root-path name="everything" path="/"/>
  <files-path name="images" path="images/"/>
</paths>"""

_PATHS_GOOD = """<paths>
  <files-path name="images" path="images/"/>
  <cache-path name="tmp" path="share/"/>
</paths>"""


def test_provider_exposure_fires(tmp_path):
    path = _build_apk(
        tmp_path,
        "prov_bad.apk",
        manifest=_PROVIDER_BAD,
        res_xml={"res/xml/file_paths.xml": _PATHS_BAD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.provider_exposure")
    titles = [f.title for f in found]

    read_only = [f for f in found if "guards reads but not writes" in f.title]
    assert len(read_only) == 1, titles
    assert read_only[0].severity is Severity.HIGH
    assert "ReadOnlyGuard" in read_only[0].evidence

    # Only an explicit wildcard <grant-uri-permission> is a HIGH finding.
    grants = [f for f in found if "grants URI permissions for every path" in f.title]
    assert len(grants) == 1, titles
    assert grants[0].severity is Severity.HIGH
    assert "GrantWide" in grants[0].evidence

    # A bare grantUriPermissions="true" grants nothing by itself: LOW, not HIGH.
    bare = [f for f in found if "enables URI permission grants" in f.title]
    assert len(bare) == 1, titles
    assert bare[0].severity is Severity.LOW
    assert "GrantAll" in bare[0].evidence

    roots = [f for f in found if "entire storage root" in f.title]
    assert len(roots) == 1, titles
    assert "root-path" in roots[0].evidence

    multi = [f for f in found if "multiprocess" in f.title]
    assert len(multi) == 1, titles
    assert multi[0].severity is Severity.LOW


def test_provider_exposure_silent_on_safe_app(tmp_path):
    path = _build_apk(
        tmp_path,
        "prov_good.apk",
        manifest=_PROVIDER_GOOD,
        res_xml={"res/xml/file_paths.xml": _PATHS_GOOD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.provider_exposure") == []


_PROVIDER_GUARDED = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.guard">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <provider android:name=".GuardedProvider" android:authorities="com.example.guard.g"
              android:exported="true" android:permission="com.example.guard.PRIVATE"
              android:grantUriPermissions="true"/>
    <provider android:name=".BothSides" android:authorities="com.example.guard.b"
              android:exported="true" android:readPermission="com.example.guard.R"
              android:writePermission="com.example.guard.W"
              android:grantUriPermissions="true"/>
  </application>
</manifest>"""


def test_provider_exposure_ignores_permission_guarded_grants(tmp_path):
    """grantUriPermissions on a permission-guarded provider is the documented shape."""
    path = _build_apk(tmp_path, "prov_guarded.apk", manifest=_PROVIDER_GUARDED)
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.provider_exposure") == []


_PROVIDER_ONE_PATHS = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.pick">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <provider android:name="androidx.core.content.FileProvider"
              android:authorities="com.example.pick.files" android:exported="false"
              android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/my_paths"/>
    </provider>
  </application>
</manifest>"""

_PATHS_SCOPED = """<paths>
  <files-path name="shared" path="shared/"/>
</paths>"""

_PATHS_LIB_WIDE = """<paths>
  <external-path name="external_files" path="."/>
</paths>"""


def test_provider_exposure_ignores_unreferenced_paths_file(tmp_path):
    """A bundled SDK's own <paths> doc is not this provider's exposure."""
    path = _build_apk(
        tmp_path,
        "prov_lib_paths.apk",
        manifest=_PROVIDER_ONE_PATHS,
        res_xml={
            "res/xml/my_paths.xml": _PATHS_SCOPED,
            "res/xml/imagepicker_provider_paths.xml": _PATHS_LIB_WIDE,
        },
    )
    result = _scan(path)
    assert not result.errors, result.errors
    titles = [f.title for f in _of(result, "apk.provider_exposure")]
    assert titles == [], titles


def test_provider_exposure_reads_the_referenced_paths_file(tmp_path):
    """The referenced doc is still scanned, and external roots get external wording."""
    path = _build_apk(
        tmp_path,
        "prov_own_paths.apk",
        manifest=_PROVIDER_ONE_PATHS,
        res_xml={
            "res/xml/my_paths.xml": _PATHS_LIB_WIDE,
            "res/xml/imagepicker_provider_paths.xml": _PATHS_LIB_WIDE,
        },
    )
    result = _scan(path)
    assert not result.errors, result.errors
    roots = [f for f in _of(result, "apk.provider_exposure") if "storage root" in f.title]
    assert len(roots) == 1, [f.location for f in roots]
    assert roots[0].location.startswith("res/xml/my_paths.xml")
    assert "androidx.core.content.FileProvider" in roots[0].evidence
    assert "shared external storage" in roots[0].description
    assert "shared_prefs" not in roots[0].description


# ---------------------------------------------------------------------------
# apk.backup_rules
# ---------------------------------------------------------------------------

_BACKUP_DEFAULT_ON = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.backup">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29"/>
  <application/>
</manifest>"""

_BACKUP_RULES_DECLARED = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.backup2">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
  <application android:allowBackup="true" android:fullBackupContent="@xml/backup_rules"/>
</manifest>"""

_BACKUP_SAFE = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.backup3">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false"
               android:dataExtractionRules="@xml/data_extraction_rules"/>
</manifest>"""

_RULES_BAD = """<full-backup-content>
  <include domain="sharedpref" path="."/>
  <include domain="database" path="."/>
  <exclude domain="database" path="secret.db"/>
</full-backup-content>"""

_RULES_GOOD = """<data-extraction-rules>
  <cloud-backup>
    <include domain="sharedpref" path="prefs.xml"/>
    <exclude domain="sharedpref" path="auth.xml"/>
  </cloud-backup>
  <device-transfer>
    <include domain="sharedpref" path="prefs.xml"/>
    <exclude domain="sharedpref" path="auth.xml"/>
  </device-transfer>
</data-extraction-rules>"""


def test_backup_rules_fires_on_absent_allow_backup(tmp_path):
    path = _build_apk(tmp_path, "backup_default.apk", manifest=_BACKUP_DEFAULT_ON)
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.backup_rules")
    assert [f.title for f in found] == ["Backup enabled by default (android:allowBackup absent)"]
    assert found[0].severity is Severity.MEDIUM
    assert "targetSdkVersion=29" in found[0].evidence

    # Mutually exclusive with apk.manifest's explicit-true finding by construction.
    assert not [f for f in result.findings if f.title == "Application data backup is allowed"]


def test_backup_rules_fires_on_wholesale_include(tmp_path):
    path = _build_apk(
        tmp_path,
        "backup_rules.apk",
        manifest=_BACKUP_RULES_DECLARED,
        res_xml={"res/xml/backup_rules.xml": _RULES_BAD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.backup_rules")
    titles = [f.title for f in found]
    assert "Backup rules include the whole sharedpref store" in titles, titles
    # database has a sibling <exclude>, so it must not be reported.
    assert "Backup rules include the whole database store" not in titles, titles


_BACKUP_OWN_RULES = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.backup4">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="true"
               android:dataExtractionRules="@xml/mine"/>
</manifest>"""


def test_backup_rules_ignores_unreferenced_rules_file(tmp_path):
    """A merged library's backup rules doc is not the app's declared rules file."""
    path = _build_apk(
        tmp_path,
        "backup_lib.apk",
        manifest=_BACKUP_OWN_RULES,
        res_xml={
            "res/xml/mine.xml": _RULES_GOOD,
            "res/xml/lib_backup.xml": _RULES_BAD,
        },
    )
    result = _scan(path)
    assert not result.errors, result.errors
    titles = [f.title for f in _of(result, "apk.backup_rules")]
    assert titles == [], titles


def test_backup_rules_silent_on_scoped_rules(tmp_path):
    path = _build_apk(
        tmp_path,
        "backup_safe.apk",
        manifest=_BACKUP_SAFE,
        res_xml={"res/xml/data_extraction_rules.xml": _RULES_GOOD},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.backup_rules") == []


# ---------------------------------------------------------------------------
# apk.deeplink_surface
# ---------------------------------------------------------------------------

_DEEPLINK_BAD = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.deep">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <activity android:name=".OpenActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp"/>
        <data android:scheme="https"/>
      </intent-filter>
    </activity>
    <activity android:name=".WildActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="*.example.com"
              android:pathPattern=".*"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""

_DEEPLINK_GOOD = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.deepsafe">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <permission android:name="com.example.deepsafe.SIG" android:protectionLevel="signature"/>
  <application android:allowBackup="false">
    <activity android:name=".WebActivity">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/open"/>
      </intent-filter>
    </activity>
    <activity android:name=".InternalActivity" android:permission="com.example.deepsafe.SIG">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="deepsafe" android:host="internal"/>
      </intent-filter>
    </activity>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def test_deeplink_surface_fires(tmp_path):
    path = _build_apk(tmp_path, "deep_bad.apk", manifest=_DEEPLINK_BAD)
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.deeplink_surface")
    titles = [f.title for f in found]

    hostless = [f for f in found if "no host" in f.title]
    assert len(hostless) == 1, titles
    assert hostless[0].severity is Severity.HIGH

    # The second <data> child must still be read (the existing check breaks early).
    custom = [f for f in found if "custom URI scheme" in f.title]
    assert len(custom) == 1, titles
    assert "myapp://" in custom[0].evidence
    # myapp:// pins neither host nor path, so it stays MEDIUM.
    assert custom[0].severity is Severity.MEDIUM

    wild = [f for f in found if "wildcard host" in f.title]
    assert len(wild) == 1, titles
    assert wild[0].severity is Severity.HIGH


def test_deeplink_surface_silent_on_safe_app(tmp_path):
    path = _build_apk(tmp_path, "deep_good.apk", manifest=_DEEPLINK_GOOD)
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.deeplink_surface") == []


_DEEPLINK_HOSTLESS = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.hostless">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <activity android:name=".DeadActivity" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
      </intent-filter>
    </activity>
    <activity android:name=".OffActivity" android:enabled="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
      </intent-filter>
    </activity>
    <activity android:name=".A">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
      </intent-filter>
    </activity>
    <activity android:name=".B">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def test_deeplink_surface_skips_unreachable_activities_and_dedupes_per_component(tmp_path):
    path = _build_apk(tmp_path, "deep_hostless.apk", manifest=_DEEPLINK_HOSTLESS)
    result = _scan(path)
    assert not result.errors, result.errors
    hostless = [f for f in _of(result, "apk.deeplink_surface") if "no host" in f.title]
    evidence = " ".join(f.evidence for f in hostless)
    # Both live activities are reported, neither unreachable one is.
    assert len(hostless) == 2, [f.evidence for f in hostless]
    assert "com.example.hostless.A" in evidence
    assert "com.example.hostless.B" in evidence
    assert "DeadActivity" not in evidence
    assert "OffActivity" not in evidence


_DEEPLINK_MIME = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.viewer">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <activity android:name=".PdfViewer">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="http" android:mimeType="application/pdf"/>
        <data android:scheme="https" android:mimeType="application/pdf"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def test_deeplink_surface_ignores_content_type_handlers(tmp_path):
    """A hostless filter that only matches a mimeType is not an open URL entry point."""
    path = _build_apk(tmp_path, "deep_mime.apk", manifest=_DEEPLINK_MIME)
    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.deeplink_surface") == []


_DEEPLINK_SDK_SCHEMES = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.oauth">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <application android:allowBackup="false">
    <activity android:name=".AuthActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="com.example.oauth" android:host="oauth"/>
        <data android:scheme="fb1234567890" android:host="authorize"/>
        <data android:scheme="stripesdk" android:host="pay"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""


def test_deeplink_surface_collapses_custom_schemes_per_component(tmp_path):
    path = _build_apk(tmp_path, "deep_oauth.apk", manifest=_DEEPLINK_SDK_SCHEMES)
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.deeplink_surface")
    assert len(found) == 1, [f.title for f in found]
    only = found[0]
    assert "custom URI scheme" in only.title
    # Host-pinned vendor callback schemes are an observation, not a MEDIUM finding.
    assert only.severity is Severity.LOW
    for scheme in ("com.example.oauth://", "fb1234567890://", "stripesdk://"):
        assert scheme in only.evidence


# ---------------------------------------------------------------------------
# apk.signing_scheme
# ---------------------------------------------------------------------------

_LOW_SDK_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
 package="com.example.old">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29"/>
  <application android:allowBackup="false"/>
</manifest>"""

_V1_SF = b"Signature-Version: 1.0\r\nCreated-By: 1.0 (Android)\r\n"
_RELEASE_DER = b"\x30\x82\x01\x0a" + b"CN=Example Release, O=Example Ltd" + b"\x00" * 32
_DEBUG_DER = b"\x30\x82\x01\x0a" + b"CN=Android Debug, O=Android" + b"\x00" * 32


def test_signing_scheme_flags_v1_only_janus(tmp_path):
    path = _build_apk(
        tmp_path,
        "v1_only.apk",
        manifest=_LOW_SDK_MANIFEST,
        raw={"META-INF/CERT.SF": _V1_SF, "META-INF/CERT.RSA": _RELEASE_DER},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.signing_scheme")
    janus = [f for f in found if "v1 JAR signing only" in f.title]
    assert len(janus) == 1, [f.title for f in found]
    assert janus[0].severity is Severity.HIGH
    assert "minSdkVersion=21" in janus[0].evidence


def test_signing_scheme_flags_debug_certificate(tmp_path):
    path = _build_apk(
        tmp_path,
        "debug_signed.apk",
        manifest=_MIN_MANIFEST,
        raw={"META-INF/CERT.SF": _V1_SF, "META-INF/CERT.RSA": _DEBUG_DER},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    found = _of(result, "apk.signing_scheme")
    debug = [f for f in found if "debug certificate" in f.title]
    assert len(debug) == 1, [f.title for f in found]
    assert debug[0].severity is Severity.HIGH
    assert debug[0].location == "META-INF/CERT.RSA"


def test_signing_scheme_flags_unsigned_archive(tmp_path):
    path = _build_apk(tmp_path, "unsigned.apk", manifest=_MIN_MANIFEST)
    result = _scan(path)
    assert not result.errors, result.errors
    titles = [f.title for f in _of(result, "apk.signing_scheme")]
    assert titles == ["APK carries no signature at all"], titles


def test_signing_scheme_silent_on_v2_v3_signed_apk(tmp_path):
    path = _build_apk(
        tmp_path,
        "v3_signed.apk",
        manifest=_MIN_MANIFEST,
        raw={"META-INF/CERT.SF": _V1_SF, "META-INF/CERT.RSA": _RELEASE_DER},
    )
    _inject_signing_block(path, [0x7109871A, 0xF05368C0])
    # The archive must still be a readable zip after the block insertion.
    with zipfile.ZipFile(path) as zf:
        assert "AndroidManifest.xml" in zf.namelist()

    result = _scan(path)
    assert not result.errors, result.errors
    assert _of(result, "apk.signing_scheme") == []
