from __future__ import annotations

import base64
import struct
import zipfile

from fya.checks.apk_dex import axml_attributes, dex_method_refs, dex_strings
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Confidence, Profile, Severity

# --------------------------------------------------------------------------- #
# Minimal DEX / AXML builders (enough of the format for the readers under test)
# --------------------------------------------------------------------------- #


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _build_dex(strings, types=(), methods=(), classes=()):
    strings = list(strings)
    types = list(types)
    methods = list(methods)
    classes = list(classes)
    n, t, m, c = len(strings), len(types), len(methods), len(classes)

    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n
    method_ids_off = type_ids_off + 4 * t
    class_defs_off = method_ids_off + 8 * m
    typelist_off = class_defs_off + 32 * c

    typelists = b""
    typelist_map = []
    for _desc, interfaces in classes:
        if interfaces:
            typelist_map.append(typelist_off + len(typelists))
            blob = struct.pack("<I", len(interfaces))
            for iface in interfaces:
                blob += struct.pack("<H", types.index(iface))
            if len(blob) % 4:
                blob += b"\x00" * (4 - len(blob) % 4)
            typelists += blob
        else:
            typelist_map.append(0)

    data_off = typelist_off + len(typelists)
    string_data = b""
    string_map = []
    for value in strings:
        string_map.append(data_off + len(string_data))
        string_data += _uleb(len(value)) + value.encode("utf-8") + b"\x00"

    body = b"".join(struct.pack("<I", off) for off in string_map)
    body += b"".join(struct.pack("<I", strings.index(desc)) for desc in types)
    for owner, name in methods:
        body += struct.pack("<HHI", types.index(owner), 0, strings.index(name))
    for index, (desc, _interfaces) in enumerate(classes):
        body += struct.pack(
            "<IIIIIIII",
            types.index(desc),
            1,
            0xFFFFFFFF,
            typelist_map[index],
            0xFFFFFFFF,
            0,
            0,
            0,
        )
    body += typelists + string_data

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"

    def put(off, value):
        header[off : off + 4] = struct.pack("<I", value)

    put(0x20, 0x70 + len(body))
    put(0x24, 0x70)
    put(0x28, 0x12345678)
    put(0x38, n)
    put(0x3C, string_ids_off if n else 0)
    put(0x40, t)
    put(0x44, type_ids_off if t else 0)
    put(0x58, m)
    put(0x5C, method_ids_off if m else 0)
    put(0x60, c)
    put(0x64, class_defs_off if c else 0)
    put(0x6C, data_off)
    return bytes(header) + body


def _axml_pool(items):
    offsets = []
    blob = b""
    for value in items:
        offsets.append(len(blob))
        blob += struct.pack("<H", len(value)) + value.encode("utf-16-le") + b"\x00\x00"
    while len(blob) % 4:
        blob += b"\x00"
    strings_start = 28 + 4 * len(items)
    size = strings_start + len(blob)
    head = struct.pack("<HHIIIIII", 0x0001, 28, size, len(items), 0, 0, strings_start, 0)
    return head + b"".join(struct.pack("<I", off) for off in offsets) + blob


def _axml_start(name_idx, attrs):
    blob = b"".join(
        struct.pack("<IIIHBBI", 0xFFFFFFFF, nidx, 0xFFFFFFFF, 8, 0, dtype, value)
        for nidx, dtype, value in attrs
    )
    size = 16 + 20 + len(blob)
    out = struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF)
    out += struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, 20, 20, len(attrs), 0, 0, 0)
    return out + blob


def _axml_end(name_idx):
    return struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx)


def _build_axml(test_only=None, min_sdk=None):
    pool = ["minSdkVersion", "testOnly", "application", "uses-sdk", "manifest"]
    resmap = [0x0101020C, 0x01010272]
    body = _axml_pool(pool)
    body += struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(resmap))
    body += b"".join(struct.pack("<I", value) for value in resmap)
    if min_sdk is not None:
        body += _axml_start(3, [(0, 0x10, min_sdk)]) + _axml_end(3)
    if test_only is not None:
        body += _axml_start(2, [(1, 0x12, 0xFFFFFFFF if test_only else 0)]) + _axml_end(2)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _apk(tmp_path, name, dexes=None, manifest=b"<manifest/>", extra=None):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        for entry, data in (dexes or {}).items():
            zf.writestr(entry, data)
        for entry, data in (extra or {}).items():
            zf.writestr(entry, data)
    return str(path)


def _scan(path):
    return run_scan(
        detect_target(path), profile=Profile.SAFE, detect_external=False, categories={"apk"}
    )


def _findings(result, check):
    return [f for f in result.findings if f.check == check]


# --------------------------------------------------------------------------- #
# Readers
# --------------------------------------------------------------------------- #


def test_dex_readers_round_trip():
    dex = _build_dex(
        strings=["Lcom/example/App;", "onCreate", "hello world"],
        types=["Lcom/example/App;"],
        methods=[("Lcom/example/App;", "onCreate")],
    )
    assert "hello world" in dex_strings(dex)
    assert dex_method_refs(dex) == {"Lcom/example/App;->onCreate"}


def test_dex_readers_reject_non_dex():
    assert dex_strings(b"not a dex at all") == []
    assert dex_method_refs(b"") == set()


def test_axml_reader_extracts_attributes():
    attrs = axml_attributes(_build_axml(test_only=True, min_sdk=21))
    assert attrs.get(0x01010272) == "true"
    assert attrs.get(0x0101020C) == "21"


# --------------------------------------------------------------------------- #
# apk.insecure_tls_code
# --------------------------------------------------------------------------- #

_TLS_VULN_DEX = _build_dex(
    strings=[
        "Landroid/net/SSLCertificateSocketFactory;",
        "getInsecure",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "Landroid/webkit/SslErrorHandler;",
        "proceed",
        "Lcom/example/MyWebViewClient;",
        "onReceivedSslError",
        "Lcom/example/TrustAll;",
        "Ljavax/net/ssl/X509TrustManager;",
        "checkServerTrusted",
    ],
    types=[
        "Landroid/net/SSLCertificateSocketFactory;",
        "Landroid/webkit/SslErrorHandler;",
        "Lcom/example/MyWebViewClient;",
        "Lcom/example/TrustAll;",
        "Ljavax/net/ssl/X509TrustManager;",
    ],
    methods=[
        ("Landroid/net/SSLCertificateSocketFactory;", "getInsecure"),
        ("Landroid/webkit/SslErrorHandler;", "proceed"),
        ("Lcom/example/MyWebViewClient;", "onReceivedSslError"),
        ("Lcom/example/TrustAll;", "checkServerTrusted"),
    ],
    classes=[("Lcom/example/TrustAll;", ["Ljavax/net/ssl/X509TrustManager;"])],
)

_TLS_SAFE_DEX = _build_dex(
    strings=[
        "Lcom/example/App;",
        "onCreate",
        "Ljava/lang/String;",
        "AES/GCM/NoPadding",
        "Ljavax/net/ssl/X509TrustManager;",
        "Lokhttp3/internal/tls/OkHostnameVerifier;",
        "Ljava/security/cert/CertificateException;",
        "verify",
    ],
    types=[
        "Lcom/example/App;",
        "Ljava/lang/String;",
        "Ljavax/net/ssl/X509TrustManager;",
        "Lokhttp3/internal/tls/OkHostnameVerifier;",
        "Ljava/security/cert/CertificateException;",
    ],
    methods=[
        ("Lcom/example/App;", "onCreate"),
        ("Lokhttp3/internal/tls/OkHostnameVerifier;", "verify"),
    ],
    classes=[("Lokhttp3/internal/tls/OkHostnameVerifier;", ["Ljavax/net/ssl/X509TrustManager;"])],
)


def test_insecure_tls_code_fires(tmp_path):
    path = _apk(tmp_path, "tlsvuln.apk", {"classes.dex": _TLS_VULN_DEX})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = _findings(result, "apk.insecure_tls_code")
    assert findings
    titles = " | ".join(f.title for f in findings)
    assert "getInsecure" in titles
    assert "Hostname verification disabled" in titles
    assert "WebView continues past TLS certificate errors" in titles
    assert "X509TrustManager" in titles
    assert any(f.severity is Severity.CRITICAL for f in findings)
    # A missing CertificateException type is only a hint (a Kotlin or delegating trust
    # manager never names the type either), so the trust manager leg stays MEDIUM.
    trust = [f for f in findings if "X509TrustManager" in f.title]
    assert trust and trust[0].severity is Severity.MEDIUM
    assert trust[0].confidence is Confidence.MEDIUM


def test_insecure_tls_code_ignores_bundled_apache_httpclient(tmp_path):
    # An app that merely packages org.apache.http.legacy *defines* the allow-all
    # verifier, SSLSocketFactory.setHostnameVerifier and the ALLOW_ALL_HOSTNAME_VERIFIER
    # field name. None of that is a call site in app code.
    types = [
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
        "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;",
        "Lcom/example/App;",
    ]
    dex = _build_dex(
        strings=types
        + ["ALLOW_ALL_HOSTNAME_VERIFIER", "setHostnameVerifier", "<init>", "onCreate"],
        types=types,
        methods=[
            ("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier"),
            ("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;", "<init>"),
            ("Lcom/example/App;", "onCreate"),
        ],
        classes=[(types[0], []), (types[1], [])],
    )
    path = _apk(tmp_path, "apachebundle.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.insecure_tls_code")


def test_insecure_tls_code_fires_on_apache_verifier_call_site(tmp_path):
    # Same references, but the dex does not define the Apache classes: this dex calls them.
    types = [
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
        "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;",
        "Lcom/example/App;",
    ]
    dex = _build_dex(
        strings=types + ["setHostnameVerifier", "<init>", "onCreate"],
        types=types,
        methods=[
            ("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier"),
            ("Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;", "<init>"),
            ("Lcom/example/App;", "onCreate"),
        ],
        classes=[(types[2], [])],
    )
    path = _apk(tmp_path, "apachecall.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [
        f for f in _findings(result, "apk.insecure_tls_code") if "Hostname verification" in f.title
    ]
    assert findings
    assert findings[0].confidence is Confidence.HIGH


def test_insecure_tls_code_lowers_confidence_for_obfuscated_trust_manager(tmp_path):
    types = ["La/b/c;", "Ljavax/net/ssl/X509TrustManager;"]
    dex = _build_dex(
        strings=types + ["checkServerTrusted"],
        types=types,
        methods=[("La/b/c;", "checkServerTrusted")],
        classes=[("La/b/c;", ["Ljavax/net/ssl/X509TrustManager;"])],
    )
    path = _apk(tmp_path, "obftm.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [
        f for f in _findings(result, "apk.insecure_tls_code") if "X509TrustManager" in f.title
    ]
    assert findings
    assert findings[0].confidence is Confidence.LOW
    assert findings[0].severity is Severity.MEDIUM


def test_insecure_tls_code_silent_on_safe_app(tmp_path):
    path = _apk(tmp_path, "tlssafe.apk", {"classes.dex": _TLS_SAFE_DEX})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.insecure_tls_code")


def test_insecure_tls_code_ignores_non_dex_entries(tmp_path):
    # The literal strings appear in an asset, not in the dex string table.
    path = _apk(
        tmp_path,
        "tlsasset.apk",
        {"classes.dex": _TLS_SAFE_DEX},
        extra={"assets/notes.txt": b"getInsecure ALLOW_ALL_HOSTNAME_VERIFIER onReceivedSslError"},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.insecure_tls_code")


# --------------------------------------------------------------------------- #
# apk.weak_crypto
# --------------------------------------------------------------------------- #

_CRYPTO_TYPES = [
    "Ljavax/crypto/Cipher;",
    "Ljava/security/MessageDigest;",
    "Ljava/security/SecureRandom;",
    "Ljavax/crypto/spec/SecretKeySpec;",
    "Lcom/example/Crypto;",
]

_CRYPTO_VULN_DEX = _build_dex(
    strings=_CRYPTO_TYPES
    + [
        "getInstance",
        "setSeed",
        "<init>",
        "encrypt",
        "AES/ECB/PKCS5Padding",
        "DES",
        "MD5",
        "MySecretKey12345",
    ],
    types=_CRYPTO_TYPES,
    methods=[
        ("Ljavax/crypto/Cipher;", "getInstance"),
        ("Ljava/security/MessageDigest;", "getInstance"),
        ("Ljava/security/SecureRandom;", "setSeed"),
        ("Ljavax/crypto/spec/SecretKeySpec;", "<init>"),
        ("Lcom/example/Crypto;", "encrypt"),
    ],
)

_CRYPTO_SAFE_DEX = _build_dex(
    strings=_CRYPTO_TYPES[:2]
    + ["Lcom/example/Crypto;", "getInstance", "encrypt", "AES/GCM/NoPadding", "SHA-256"],
    types=_CRYPTO_TYPES[:2] + ["Lcom/example/Crypto;"],
    methods=[
        ("Ljavax/crypto/Cipher;", "getInstance"),
        ("Ljava/security/MessageDigest;", "getInstance"),
        ("Lcom/example/Crypto;", "encrypt"),
    ],
)


def test_weak_crypto_fires(tmp_path):
    path = _apk(tmp_path, "cryptovuln.apk", {"classes.dex": _CRYPTO_VULN_DEX})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = _findings(result, "apk.weak_crypto")
    assert findings
    titles = " | ".join(f.title for f in findings)
    assert "AES/ECB/PKCS5Padding" in titles
    assert "'DES'" in titles
    assert "MD5" in titles
    assert "SecureRandom is explicitly seeded" in titles
    assert "hardcoded symmetric key material" in titles
    des = [f for f in findings if "'DES'" in f.title]
    assert des and des[0].severity is Severity.HIGH


def test_weak_crypto_silent_on_modern_crypto(tmp_path):
    path = _apk(tmp_path, "cryptosafe.apk", {"classes.dex": _CRYPTO_SAFE_DEX})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.weak_crypto")


def test_weak_crypto_needs_the_api_not_just_the_string(tmp_path):
    # 'DES' and 'MD5' are present as strings but no crypto API is referenced.
    dex = _build_dex(
        strings=["Lcom/example/App;", "onCreate", "DES", "MD5", "AES"],
        types=["Lcom/example/App;"],
        methods=[("Lcom/example/App;", "onCreate")],
    )
    path = _apk(tmp_path, "cryptostring.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.weak_crypto")


def test_weak_crypto_bare_aes_is_not_reported_when_a_transformation_exists(tmp_path):
    # Textbook-correct app: AES/GCM/NoPadding plus SecretKeySpec(key, "AES") and
    # KeyGenerator.getInstance("AES"), both of which require the bare "AES" string.
    types = _CRYPTO_TYPES[:1] + [
        "Ljavax/crypto/KeyGenerator;",
        "Ljavax/crypto/spec/SecretKeySpec;",
        "Lcom/example/Crypto;",
    ]
    dex = _build_dex(
        strings=types + ["getInstance", "<init>", "encrypt", "AES", "AES/GCM/NoPadding"],
        types=types,
        methods=[
            ("Ljavax/crypto/Cipher;", "getInstance"),
            ("Ljavax/crypto/KeyGenerator;", "getInstance"),
            ("Ljavax/crypto/spec/SecretKeySpec;", "<init>"),
            ("Lcom/example/Crypto;", "encrypt"),
        ],
    )
    path = _apk(tmp_path, "aesgcm.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.weak_crypto")


def test_weak_crypto_bare_aes_fires_without_any_transformation(tmp_path):
    types = _CRYPTO_TYPES[:1] + ["Lcom/example/Crypto;"]
    dex = _build_dex(
        strings=types + ["getInstance", "encrypt", "AES"],
        types=types,
        methods=[
            ("Ljavax/crypto/Cipher;", "getInstance"),
            ("Lcom/example/Crypto;", "encrypt"),
        ],
    )
    path = _apk(tmp_path, "aesbare.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = _findings(result, "apk.weak_crypto")
    assert findings
    assert "JCE default mode" in findings[0].title
    assert findings[0].confidence is Confidence.LOW


def test_weak_crypto_ignores_algorithm_and_resource_names_as_key_material(tmp_path):
    # Correct key derivation: SecretKeyFactory + SecretKeySpec, no hardcoded key.
    types = _CRYPTO_TYPES[3:] + ["Ljavax/crypto/SecretKeyFactory;"]
    dex = _build_dex(
        strings=types
        + [
            "getInstance",
            "<init>",
            "encrypt",
            "PBKDF2WithHmacSHA1",
            "PBEWithMD5AndDES",
            "abc_text_size_body_1",
            "material_grey_850",
        ],
        types=types,
        methods=[
            ("Ljavax/crypto/spec/SecretKeySpec;", "<init>"),
            ("Ljavax/crypto/SecretKeyFactory;", "getInstance"),
            ("Lcom/example/Crypto;", "encrypt"),
        ],
    )
    path = _apk(tmp_path, "kdf.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.weak_crypto")


def test_weak_crypto_reports_base64_key_material(tmp_path):
    key = base64.b64encode(bytes(range(32))).decode()
    types = _CRYPTO_TYPES[3:]
    dex = _build_dex(
        strings=types + ["<init>", "encrypt", key],
        types=types,
        methods=[
            ("Ljavax/crypto/spec/SecretKeySpec;", "<init>"),
            ("Lcom/example/Crypto;", "encrypt"),
        ],
    )
    path = _apk(tmp_path, "b64key.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = _findings(result, "apk.weak_crypto")
    assert findings
    assert "hardcoded symmetric key material" in findings[0].title


def test_weak_crypto_downgrades_confidence_when_provider_bundled(tmp_path):
    types = _CRYPTO_TYPES + ["Lorg/bouncycastle/crypto/engines/DESEngine;"]
    dex = _build_dex(
        strings=types + ["getInstance", "DES", "process"],
        types=types,
        methods=[
            ("Ljavax/crypto/Cipher;", "getInstance"),
            ("Lorg/bouncycastle/crypto/engines/DESEngine;", "process"),
        ],
    )
    path = _apk(tmp_path, "cryptoprovider.apk", {"classes.dex": dex})
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [f for f in _findings(result, "apk.weak_crypto") if "'DES'" in f.title]
    assert findings
    assert findings[0].confidence is Confidence.LOW


# --------------------------------------------------------------------------- #
# apk.build_hardening
# --------------------------------------------------------------------------- #

_DEBUG_MARKER = '~~R8{"compilation-mode":"debug","min-api":21,"version":"8.2.42"}'
_RELEASE_MARKER = '~~R8{"compilation-mode":"release","min-api":24,"version":"8.2.42"}'
_D8_MARKER = '~~D8{"min-api":24,"version":"8.2.42"}'

_TEST_ONLY_MANIFEST = (
    b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">'
    b'<uses-sdk android:minSdkVersion="24"/>'
    b'<application android:testOnly="true"/>'
    b"</manifest>"
)
_CLEAN_MANIFEST = (
    b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">'
    b'<uses-sdk android:minSdkVersion="24"/>'
    b"<application/>"
    b"</manifest>"
)


def _marker_dex(marker, class_names=()):
    types = list(class_names)
    return _build_dex(
        strings=types + ["Lcom/example/App;", "onCreate", marker],
        types=types + ["Lcom/example/App;"],
        methods=[("Lcom/example/App;", "onCreate")],
        classes=[(name, []) for name in types],
    )


def test_build_hardening_fires(tmp_path):
    path = _apk(
        tmp_path,
        "buildvuln.apk",
        {"classes.dex": _marker_dex(_DEBUG_MARKER)},
        manifest=_TEST_ONLY_MANIFEST,
        extra={"META-INF/proguard/mapping.txt": b"com.example.App -> a.a:\n"},
    )
    result = _scan(path)
    assert not result.errors, result.errors
    findings = _findings(result, "apk.build_hardening")
    assert findings
    titles = " | ".join(f.title for f in findings)
    assert "compiled in debug mode" in titles
    assert "android:testOnly" in titles
    assert "mapping file packaged" in titles
    mapping = [f for f in findings if "mapping file packaged" in f.title]
    assert mapping and mapping[0].severity is Severity.HIGH


def test_build_hardening_silent_on_release_build(tmp_path):
    path = _apk(
        tmp_path,
        "buildsafe.apk",
        {"classes.dex": _marker_dex(_RELEASE_MARKER)},
        manifest=_CLEAN_MANIFEST,
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.build_hardening")


def test_build_hardening_d8_without_r8(tmp_path):
    names = ["Lcom/example/LongClassName%02d;" % i for i in range(12)]
    path = _apk(
        tmp_path,
        "buildd8.apk",
        {"classes.dex": _marker_dex(_D8_MARKER, names)},
        manifest=_CLEAN_MANIFEST,
    )
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [f for f in _findings(result, "apk.build_hardening") if "D8" in f.title]
    assert findings
    assert findings[0].severity is Severity.LOW
    assert findings[0].confidence is Confidence.HIGH


def test_build_hardening_d8_suppressed_when_already_obfuscated(tmp_path):
    names = ["Lcom/example/%s;" % chr(ord("a") + i) for i in range(12)]
    path = _apk(
        tmp_path,
        "buildobf.apk",
        {"classes.dex": _marker_dex(_D8_MARKER, names)},
        manifest=_CLEAN_MANIFEST,
    )
    result = _scan(path)
    assert not result.errors, result.errors
    assert not _findings(result, "apk.build_hardening")


def test_build_hardening_reads_binary_manifest(tmp_path):
    path = _apk(
        tmp_path,
        "buildaxml.apk",
        {"classes.dex": _marker_dex(_RELEASE_MARKER)},
        manifest=_build_axml(test_only=True, min_sdk=24),
    )
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [f for f in _findings(result, "apk.build_hardening") if "testOnly" in f.title]
    assert findings


def test_build_hardening_min_api_mismatch(tmp_path):
    path = _apk(
        tmp_path,
        "buildmismatch.apk",
        {"classes.dex": _marker_dex(_RELEASE_MARKER)},
        manifest=_build_axml(min_sdk=21),
    )
    result = _scan(path)
    assert not result.errors, result.errors
    findings = [f for f in _findings(result, "apk.build_hardening") if "min-api" in f.title]
    assert findings
    assert findings[0].severity is Severity.INFO


def test_checks_survive_an_archive_full_of_resource_entries(tmp_path):
    # A real APK carries tens of thousands of res/ entries. The dex and the mapping
    # file live behind them in the central directory, so a walk that caps the raw
    # entry list instead of the matching entries goes silently blind.
    path = tmp_path / "big.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", _TEST_ONLY_MANIFEST)
        for i in range(6000):
            zf.writestr("res/drawable/img%05d.png" % i, b"x")
        zf.writestr("classes.dex", _TLS_VULN_DEX)
        zf.writestr("classes2.dex", _marker_dex(_DEBUG_MARKER))
        zf.writestr("META-INF/proguard/mapping.txt", b"com.example.App -> a.a:\n")
    result = _scan(str(path))
    assert not result.errors, result.errors
    assert _findings(result, "apk.insecure_tls_code")
    build_titles = " | ".join(f.title for f in _findings(result, "apk.build_hardening"))
    assert "compiled in debug mode" in build_titles
    assert "mapping file packaged" in build_titles


def test_build_hardening_handles_broken_archive(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"not a zip file")
    result = _scan(str(path))
    assert not _findings(result, "apk.build_hardening")
    assert not _findings(result, "apk.weak_crypto")
    assert not _findings(result, "apk.insecure_tls_code")
