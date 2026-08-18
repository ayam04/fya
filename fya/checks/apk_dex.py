"""DEX-level static analysis for APK targets.

Everything in here is structural: the DEX string table, type table, method reference
table and class definition table are parsed directly out of the raw ``classes*.dex``
bytes (read-only, bounds checked) instead of running substring matches over a
``utf-8``-with-errors-ignored decode of the whole blob. That means a finding only
fires when an *exact* string is present in the string pool **and** the corresponding
API is present in the method reference table, which is what keeps these checks quiet
on benign apps.

The DEX/AXML readers below (``dex_strings``, ``dex_types``, ``dex_method_refs``,
``dex_class_defs``, ``axml_attributes``) are intentionally dependency free and are
the shared primitives the checks in this module are built on.
"""

from __future__ import annotations

import base64
import json
import math
import re
import zipfile
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from xml.etree import ElementTree as ET

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from ._apk_common import iter_entries as _iter_matching_entries
from ._apk_common import open_apk

_MASVS_REF = ["https://mas.owasp.org/MASVS/", "https://mas.owasp.org/MASTG/"]

_DEX_ENTRY = re.compile(r"(?:.*/)?classes\d*\.dex\Z")
_MAPPING_ENTRY = re.compile(r"(?:META-INF/)?(?:proguard/)?mapping\.txt\Z")

_MAX_DEX_BYTES = 64 * 1024 * 1024
_MAX_DEX_ENTRIES = 12
_MAX_ZIP_ENTRIES = 4000
_MAX_STRINGS = 300_000
_MAX_TYPES = 200_000
_MAX_FIELDS = 300_000
_MAX_METHODS = 300_000
_MAX_CLASS_DEFS = 100_000
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024

_MAX_TLS_FINDINGS = 6
_MAX_CRYPTO_FINDINGS = 8
_MAX_KEY_FINDINGS = 3
_MAX_BUILD_FINDINGS = 5

# Class descriptor prefixes owned by the platform, the JDK or a well known third
# party library. A trust manager or hostname verifier living under one of these is
# library code the app merely bundles, not something the app author wrote.
_FRAMEWORK_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Ldalvik/",
    "Ljava/",
    "Ljavax/",
    "Ljunit/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lsun/",
    "Lcom/android/",
    "Lcom/google/",
    "Lcom/squareup/",
    "Lcom/facebook/react/",
    "Lio/flutter/",
    "Lio/grpc/",
    "Lio/netty/",
    "Lokhttp3/",
    "Lokio/",
    "Lorg/apache/",
    "Lorg/bouncycastle/",
    "Lorg/chromium/",
    "Lorg/conscrypt/",
    "Lorg/jetbrains/",
    "Lorg/json/",
    "Lorg/spongycastle/",
    "Lretrofit2/",
)


# --------------------------------------------------------------------------- #
# Low level readers
# --------------------------------------------------------------------------- #


def _u16(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off : off + 2], "little")


def _u32(data: bytes, off: int) -> Optional[int]:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off : off + 4], "little")


def _is_dex(data: bytes) -> bool:
    return len(data) >= 0x70 and data.startswith(b"dex\n")


def dex_strings(data: bytes) -> List[str]:
    """Decode the DEX string table (``string_ids`` at 0x38/0x3C, ULEB128 + MUTF-8)."""
    out: List[str] = []
    if not _is_dex(data):
        return out
    size = _u32(data, 0x38) or 0
    off = _u32(data, 0x3C) or 0
    if not size or not off:
        return out
    for i in range(min(size, _MAX_STRINGS)):
        p = _u32(data, off + i * 4)
        if p is None or p <= 0 or p >= len(data):
            out.append("")
            continue
        cursor = p
        limit = min(len(data), p + 5)
        while cursor < limit and (data[cursor] & 0x80):
            cursor += 1
        cursor += 1
        if cursor >= len(data):
            out.append("")
            continue
        end = data.find(b"\x00", cursor)
        if end < 0:
            out.append("")
            continue
        out.append(data[cursor:end].decode("utf-8", "replace"))
    return out


def dex_types(data: bytes, strings: Optional[Sequence[str]] = None) -> List[str]:
    """Decode the DEX type descriptor table (``type_ids`` at 0x40/0x44)."""
    pool = dex_strings(data) if strings is None else strings
    out: List[str] = []
    if not _is_dex(data):
        return out
    size = _u32(data, 0x40) or 0
    off = _u32(data, 0x44) or 0
    if not size or not off:
        return out
    for i in range(min(size, _MAX_TYPES)):
        idx = _u32(data, off + i * 4)
        if idx is None or idx >= len(pool):
            out.append("")
            continue
        out.append(pool[idx])
    return out


def dex_field_names(data: bytes, strings: Optional[Sequence[str]] = None) -> Set[str]:
    """Decode ``field_ids`` (0x50/0x54) into the set of field *name* strings.

    Field names are the bulk of the identifier-looking strings in a DEX (``R``
    resource ids, constants, member names), so knowing them lets string based
    heuristics discard an identifier that is only ever a field name.
    """
    pool = dex_strings(data) if strings is None else strings
    out: Set[str] = set()
    if not _is_dex(data):
        return out
    size = _u32(data, 0x50) or 0
    off = _u32(data, 0x54) or 0
    if not size or not off:
        return out
    for i in range(min(size, _MAX_FIELDS)):
        name_idx = _u32(data, off + i * 8 + 4)
        if name_idx is None or name_idx >= len(pool):
            continue
        name = pool[name_idx]
        if name:
            out.add(name)
    return out


def dex_method_pairs(
    data: bytes,
    strings: Optional[Sequence[str]] = None,
    types: Optional[Sequence[str]] = None,
) -> List[Tuple[str, str]]:
    """Decode ``method_ids`` (0x58/0x5C) into ``(class descriptor, method name)`` pairs."""
    pool = dex_strings(data) if strings is None else strings
    type_pool = dex_types(data, pool) if types is None else types
    out: List[Tuple[str, str]] = []
    if not _is_dex(data):
        return out
    size = _u32(data, 0x58) or 0
    off = _u32(data, 0x5C) or 0
    if not size or not off:
        return out
    for i in range(min(size, _MAX_METHODS)):
        base = off + i * 8
        class_idx = _u16(data, base)
        name_idx = _u32(data, base + 4)
        if class_idx is None or name_idx is None:
            continue
        if class_idx >= len(type_pool) or name_idx >= len(pool):
            continue
        owner = type_pool[class_idx]
        name = pool[name_idx]
        if owner and name:
            out.append((owner, name))
    return out


def dex_method_refs(data: bytes) -> Set[str]:
    """Every method reference in the DEX rendered as ``Ltype;->name``."""
    return {"%s->%s" % (owner, name) for owner, name in dex_method_pairs(data)}


def dex_class_defs(
    data: bytes, types: Optional[Sequence[str]] = None
) -> List[Tuple[str, Tuple[str, ...]]]:
    """Decode ``class_defs`` (0x60/0x64) into ``(descriptor, implemented interfaces)``."""
    type_pool = dex_types(data) if types is None else types
    out: List[Tuple[str, Tuple[str, ...]]] = []
    if not _is_dex(data):
        return out
    size = _u32(data, 0x60) or 0
    off = _u32(data, 0x64) or 0
    if not size or not off:
        return out
    for i in range(min(size, _MAX_CLASS_DEFS)):
        base = off + i * 32
        class_idx = _u32(data, base)
        interfaces_off = _u32(data, base + 12)
        if class_idx is None or class_idx >= len(type_pool):
            continue
        interfaces: List[str] = []
        if interfaces_off:
            count = _u32(data, interfaces_off) or 0
            for k in range(min(count, 4096)):
                idx = _u16(data, interfaces_off + 4 + k * 2)
                if idx is not None and idx < len(type_pool) and type_pool[idx]:
                    interfaces.append(type_pool[idx])
        out.append((type_pool[class_idx], tuple(interfaces)))
    return out


class _DexImage:
    """One parsed ``classes*.dex``: strings, types, method refs and class defs."""

    def __init__(self, data: bytes) -> None:
        self.strings = dex_strings(data)
        self.string_set = set(self.strings)
        self.types = dex_types(data, self.strings)
        self.type_set = set(self.types)
        self.field_names = dex_field_names(data, self.strings)
        self.method_pairs = dex_method_pairs(data, self.strings, self.types)
        self.methods = {"%s->%s" % (owner, name) for owner, name in self.method_pairs}
        self.method_names = {name for _owner, name in self.method_pairs}
        self.classes = dex_class_defs(data, self.types)
        self.defined_classes = {descriptor for descriptor, _ifaces in self.classes}


def _is_framework_class(descriptor: str) -> bool:
    return descriptor.startswith(_FRAMEWORK_PREFIXES)


def _looks_obfuscated(descriptor: str) -> bool:
    """True when a class descriptor's own name is a 1-2 character (renamed) identifier."""
    tail = descriptor[:-1] if descriptor.endswith(";") else descriptor
    tail = tail.rsplit("/", 1)[-1]
    return 1 <= len(tail) <= 2


def _short_class_ratio(image: _DexImage) -> Optional[float]:
    """Fraction of class descriptors whose final segment is 1-2 characters.

    Computed over the classes actually *defined* in this dex when there are enough
    of them (that is the population an obfuscator renames); otherwise over the whole
    type table. Returns ``None`` when the sample is too small to mean anything.
    """
    descriptors = [d for d, _ifaces in image.classes if d.startswith("L") and d.endswith(";")]
    if len(descriptors) < 10:
        descriptors = [d for d in image.types if d.startswith("L") and d.endswith(";")]
    if len(descriptors) < 10:
        return None
    short = 0
    for descriptor in descriptors:
        tail = descriptor[:-1].rsplit("/", 1)[-1]
        if 1 <= len(tail) <= 2:
            short += 1
    return short / float(len(descriptors))


# --------------------------------------------------------------------------- #
# Archive access
# --------------------------------------------------------------------------- #


def iter_entries(
    apk_path: str, pattern: "re.Pattern", max_bytes: int
) -> Iterator[Tuple[str, bytes]]:
    """Yield ``(name, bytes)`` for archive entries matching *pattern*, size capped.

    Delegates to :func:`fya.checks._apk_common.iter_entries`, which applies the
    predicate *before* the entry cap. A real APK carries tens of thousands of
    ``res/`` entries, so capping the raw ``namelist()`` instead would push
    ``classes2.dex`` past the cutoff and make every check here silently blind.
    """
    archive = open_apk(apk_path)
    if archive is None:
        return
    with archive:
        for name, data in _iter_matching_entries(
            archive, pattern.match, max_entries=_MAX_ZIP_ENTRIES, max_bytes=max_bytes
        ):
            yield name, data


def _iter_dex_images(apk_path: str) -> Iterator[Tuple[str, _DexImage]]:
    seen = 0
    for name, data in iter_entries(apk_path, _DEX_ENTRY, _MAX_DEX_BYTES):
        if seen >= _MAX_DEX_ENTRIES:
            return
        if not _is_dex(data):
            continue
        seen += 1
        yield name, _DexImage(data)


def _zip_names(apk_path: str, pattern: "re.Pattern") -> List[str]:
    """Entry names matching *pattern*, filtered before the entry cap is applied."""
    archive = open_apk(apk_path)
    if archive is None:
        return []
    with archive:
        try:
            names = [name for name in archive.namelist() if pattern.match(name)]
        except (OSError, zipfile.BadZipFile, RuntimeError):
            return []
    return names[:_MAX_ZIP_ENTRIES]


# --------------------------------------------------------------------------- #
# Binary AndroidManifest.xml (AXML) reader
# --------------------------------------------------------------------------- #

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_RES_MIN_SDK = 0x0101020C
_RES_TEST_ONLY = 0x01010272

_AXML_MAGIC = 0x0003
_AXML_STRING_POOL = 0x0001
_AXML_RESOURCE_MAP = 0x0180
_AXML_START_ELEMENT = 0x0102


def _axml_len8(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        return 0, pos
    first = data[pos]
    if first & 0x80:
        second = data[pos + 1] if pos + 1 < len(data) else 0
        return ((first & 0x7F) << 8) | second, pos + 2
    return first, pos + 1


def _axml_len16(data: bytes, pos: int) -> Tuple[int, int]:
    value = _u16(data, pos)
    if value is None:
        return 0, pos
    if value & 0x8000:
        low = _u16(data, pos + 2) or 0
        return ((value & 0x7FFF) << 16) | low, pos + 4
    return value, pos + 2


def _axml_string_pool(data: bytes, off: int, csize: int) -> List[str]:
    out: List[str] = []
    count = _u32(data, off + 8) or 0
    flags = _u32(data, off + 16) or 0
    strings_start = _u32(data, off + 20) or 0
    utf8 = bool(flags & 0x100)
    limit = min(len(data), off + csize)
    for i in range(min(count, 100_000)):
        rel = _u32(data, off + 28 + i * 4)
        if rel is None:
            break
        pos = off + strings_start + rel
        if pos < 0 or pos >= limit:
            out.append("")
            continue
        if utf8:
            _chars, pos = _axml_len8(data, pos)
            nbytes, pos = _axml_len8(data, pos)
            out.append(data[pos : min(pos + nbytes, limit)].decode("utf-8", "replace"))
        else:
            nchars, pos = _axml_len16(data, pos)
            out.append(data[pos : min(pos + nchars * 2, limit)].decode("utf-16-le", "replace"))
    return out


def _axml_value(dtype: int, value: int, raw_idx: int, strings: Sequence[str]) -> str:
    if dtype == 0x12:  # TYPE_INT_BOOLEAN
        return "true" if value else "false"
    if dtype == 0x10:  # TYPE_INT_DEC
        return str(value)
    if dtype == 0x03 and value < len(strings):  # TYPE_STRING
        return strings[value]
    if raw_idx < len(strings):
        return strings[raw_idx]
    return str(value)


def axml_attributes(data: bytes, max_elements: int = 2000) -> Dict[int, str]:
    """Map ``android:`` attribute resource id -> first value seen in a binary manifest."""
    out: Dict[int, str] = {}
    if len(data) < 8 or _u16(data, 0) != _AXML_MAGIC:
        return out
    total = _u32(data, 4) or 0
    end = min(len(data), total) if total else len(data)
    pos = _u16(data, 2) or 8
    strings: List[str] = []
    resmap: List[int] = []
    elements = 0
    while pos + 8 <= end:
        ctype = _u16(data, pos)
        hsize = _u16(data, pos + 2)
        csize = _u32(data, pos + 4)
        if ctype is None or hsize is None or csize is None or csize < 8:
            break
        if pos + csize > end:
            break
        if ctype == _AXML_STRING_POOL:
            strings = _axml_string_pool(data, pos, csize)
        elif ctype == _AXML_RESOURCE_MAP:
            base = pos + max(hsize, 8)
            count = max(0, csize - max(hsize, 8)) // 4
            resmap = [(_u32(data, base + i * 4) or 0) for i in range(min(count, 20_000))]
        elif ctype == _AXML_START_ELEMENT:
            elements += 1
            if elements > max_elements:
                break
            _axml_element_attrs(data, pos, hsize or 16, csize, strings, resmap, out)
        pos += csize
    return out


def _axml_element_attrs(
    data: bytes,
    pos: int,
    hsize: int,
    csize: int,
    strings: Sequence[str],
    resmap: Sequence[int],
    out: Dict[int, str],
) -> None:
    body = pos + hsize
    attr_start = _u16(data, body + 8)
    attr_size = _u16(data, body + 10)
    attr_count = _u16(data, body + 12)
    if not attr_size or not attr_count:
        return
    base = body + (attr_start or 20)
    chunk_end = pos + csize
    for i in range(min(attr_count, 512)):
        entry = base + i * attr_size
        if entry + 20 > chunk_end or entry + 20 > len(data):
            return
        name_idx = _u32(data, entry + 4)
        raw_idx = _u32(data, entry + 8)
        dtype = data[entry + 15]
        value = _u32(data, entry + 16) or 0
        if name_idx is None or name_idx >= len(resmap):
            continue
        res_id = resmap[name_idx]
        if not res_id or res_id in out:
            continue
        out[res_id] = _axml_value(dtype, value, raw_idx if raw_idx is not None else 0, strings)


def _plain_manifest_attrs(raw: bytes) -> Dict[int, str]:
    out: Dict[int, str] = {}
    try:
        root = ET.fromstring(raw.decode("utf-8", "replace"))
    except ET.ParseError:
        return out

    def _get(node, attr: str) -> Optional[str]:
        if node is None:
            return None
        return node.get("{%s}%s" % (_ANDROID_NS, attr), node.get(attr))

    value = _get(root.find("application"), "testOnly")
    if value is not None:
        out[_RES_TEST_ONLY] = value
    value = _get(root.find("uses-sdk"), "minSdkVersion")
    if value is not None:
        out[_RES_MIN_SDK] = value
    return out


def manifest_attributes(apk_path: str) -> Dict[int, str]:
    """Attribute resource id -> value for AndroidManifest.xml (binary or plain XML)."""
    for _name, raw in iter_entries(
        apk_path, re.compile(r"AndroidManifest\.xml\Z"), _MAX_MANIFEST_BYTES
    ):
        if raw[:1] == b"<":
            return _plain_manifest_attrs(raw)
        return axml_attributes(raw)
    return {}


# --------------------------------------------------------------------------- #
# apk.insecure_tls_code
# --------------------------------------------------------------------------- #

_GET_INSECURE = "Landroid/net/SSLCertificateSocketFactory;->getInsecure"
_APACHE_SSL_FACTORY = "Lorg/apache/http/conn/ssl/SSLSocketFactory;"
_APACHE_SET_VERIFIER = "Lorg/apache/http/conn/ssl/SSLSocketFactory;->setHostnameVerifier"
_SSL_ERROR_PROCEED = "Landroid/webkit/SslErrorHandler;->proceed"
_X509_TRUST_MANAGER = "Ljavax/net/ssl/X509TrustManager;"
_CERT_EXCEPTION = "Ljava/security/cert/CertificateException;"


@register
class ApkInsecureTlsCode(Check):
    name = "apk.insecure_tls_code"
    title = "Certificate or hostname validation disabled in application code"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        emitted = 0
        for dex_name, image in _iter_dex_images(apk_path):
            if emitted >= _MAX_TLS_FINDINGS:
                return
            for finding in self._analyse(dex_name, image):
                yield finding
                emitted += 1
                if emitted >= _MAX_TLS_FINDINGS:
                    return

    def _analyse(self, dex_name: str, image: _DexImage) -> Iterable[Finding]:
        yield from self._get_insecure(dex_name, image)
        yield from self._hostname_verifier(dex_name, image)
        yield from self._webview_ssl_error(dex_name, image)
        yield from self._trust_managers(dex_name, image)

    def _get_insecure(self, dex_name: str, image: _DexImage) -> Iterable[Finding]:
        if _GET_INSECURE not in image.methods:
            return
        yield Finding(
            check=self.name,
            title="Trust-everything socket factory (SSLCertificateSocketFactory.getInsecure)",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="MASVS-NETWORK",
            cwe="CWE-295",
            description="The DEX method reference table contains "
            "android.net.SSLCertificateSocketFactory.getInsecure(). Sockets created by that "
            "factory perform no certificate or hostname validation at all, so any attacker on "
            "the network path can present a self-signed certificate and read or modify the "
            "app's TLS traffic. The API is documented as never safe for production use.",
            remediation="Delete the getInsecure() call and use the default "
            "SSLSocketFactory/HttpsURLConnection stack. If a self-signed certificate is needed "
            "for a test environment, gate it behind a debug build variant, never ship it.",
            location="%s:getInsecure" % dex_name,
            evidence="method ref %s" % _GET_INSECURE,
            references=_MASVS_REF,
        )

    def _hostname_verifier(self, dex_name: str, image: _DexImage) -> Iterable[Finding]:
        # A method_id exists for every method a dex *defines* as well as for every
        # method it calls, and a field name string lands in the pool for a field
        # definition too. Bundling Apache HttpClient therefore supplies all three
        # signals on its own, so only references this dex does not itself define
        # count as an app-side call site.
        signal = None
        confidence = Confidence.HIGH
        for owner, method in sorted(image.method_pairs):
            if method != "<init>" or not owner.endswith("AllowAllHostnameVerifier;"):
                continue
            if owner in image.defined_classes:
                continue
            signal = "method ref %s-><init>" % owner
            break
        bundles_apache = _APACHE_SSL_FACTORY in image.defined_classes
        if signal is None and not bundles_apache:
            if _APACHE_SET_VERIFIER in image.methods:
                signal = "method ref %s" % _APACHE_SET_VERIFIER
            elif "ALLOW_ALL_HOSTNAME_VERIFIER" in image.string_set:
                # A field *name* string: the app reads the constant somewhere.
                signal = "string ALLOW_ALL_HOSTNAME_VERIFIER"
                confidence = Confidence.MEDIUM
        if signal is None:
            return
        yield Finding(
            check=self.name,
            title="Hostname verification disabled (allow-all verifier)",
            severity=Severity.HIGH,
            confidence=confidence,
            category="MASVS-NETWORK",
            cwe="CWE-297",
            description="The DEX references an allow-all hostname verifier through a class it "
            "does not itself define, so the reference is a call site here rather than a "
            "definition inside a bundled copy of Apache HttpClient. With hostname verification "
            "switched off, a certificate that is validly signed for any domain is accepted for "
            "every host the app talks to, which lets an attacker holding any trusted "
            "certificate impersonate the app's backend.",
            remediation="Remove the custom HostnameVerifier and keep the platform default "
            "(StrictHostnameVerifier / OkHttp's default). Use certificate pinning through the "
            "network security configuration if extra assurance is required.",
            location="%s:hostname_verifier" % dex_name,
            evidence=signal,
            references=_MASVS_REF,
        )

    def _webview_ssl_error(self, dex_name: str, image: _DexImage) -> Iterable[Finding]:
        if _SSL_ERROR_PROCEED not in image.methods:
            return
        owner = None
        for cls, method in image.method_pairs:
            if method == "onReceivedSslError" and not cls.startswith("Landroid/"):
                owner = cls
                break
        if owner is None:
            return
        yield Finding(
            check=self.name,
            title="WebView continues past TLS certificate errors",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="MASVS-NETWORK",
            cwe="CWE-295",
            description="The app defines %s with an onReceivedSslError handler and the DEX "
            "references SslErrorHandler.proceed(). A WebViewClient that calls proceed() from "
            "onReceivedSslError loads pages whose certificate failed validation, silently "
            "downgrading every page the WebView renders to an interceptable channel."
            % owner,
            remediation="Call SslErrorHandler.cancel() and surface the failure to the user. "
            "Never call proceed() unconditionally; if a specific certificate must be trusted, "
            "pin it in the network security configuration instead.",
            location="%s:onReceivedSslError" % dex_name,
            evidence="%s->onReceivedSslError with %s" % (owner, _SSL_ERROR_PROCEED),
            references=_MASVS_REF,
        )

    def _trust_managers(self, dex_name: str, image: _DexImage) -> Iterable[Finding]:
        has_cert_exception = _CERT_EXCEPTION in image.type_set
        seen: Set[str] = set()
        for descriptor, interfaces in image.classes:
            if _X509_TRUST_MANAGER not in interfaces:
                continue
            if not descriptor or _is_framework_class(descriptor) or descriptor in seen:
                continue
            seen.add(descriptor)
            if has_cert_exception:
                extra = (
                    "The dex references CertificateException, so the implementation may well "
                    "reject bad chains; review checkServerTrusted before acting."
                )
            else:
                extra = (
                    "No CertificateException type is referenced in this dex, which is a weak "
                    "hint that nothing rejects a chain. It is only a hint: a Kotlin trust "
                    "manager, or one that delegates to the platform default and lets its "
                    "exception propagate, never names the type either. The method body was not "
                    "inspected."
                )
            confidence = Confidence.MEDIUM
            if _looks_obfuscated(descriptor):
                confidence = Confidence.LOW
                extra += (
                    " The class name has been renamed by a minifier, so the prefix based "
                    "framework filter cannot tell app code from a bundled library here."
                )
            yield Finding(
                check=self.name,
                title="Application-defined X509TrustManager",
                severity=Severity.MEDIUM,
                confidence=confidence,
                category="MASVS-NETWORK",
                cwe="CWE-295",
                description="%s implements javax.net.ssl.X509TrustManager. A custom trust "
                "manager replaces the platform's certificate validation, and an empty "
                "checkServerTrusted accepts every certificate presented to the app. %s"
                % (descriptor, extra),
                remediation="Prefer the network security configuration (trust anchors and "
                "certificate pinning) over a custom TrustManager. If one is unavoidable, "
                "delegate to the default X509TrustManager and throw CertificateException on "
                "failure.",
                location="%s:trustmanager:%s" % (dex_name, descriptor),
                evidence="%s implements %s (CertificateException present: %s)"
                % (descriptor, _X509_TRUST_MANAGER, "yes" if has_cert_exception else "no"),
                references=_MASVS_REF,
            )


# --------------------------------------------------------------------------- #
# apk.weak_crypto
# --------------------------------------------------------------------------- #

_CIPHER_GET_INSTANCE = "Ljavax/crypto/Cipher;->getInstance"
_DIGEST_GET_INSTANCE = "Ljava/security/MessageDigest;->getInstance"
_SECURE_RANDOM_SET_SEED = "Ljava/security/SecureRandom;->setSeed"
_SECRET_KEY_SPEC_INIT = "Ljavax/crypto/spec/SecretKeySpec;-><init>"

_WEAK_CIPHER_ALGOS = {
    "AES/ECB/PKCS5Padding": (Severity.MEDIUM, "ECB mode encrypts identical blocks identically"),
    "AES/ECB/NoPadding": (Severity.MEDIUM, "ECB mode encrypts identical blocks identically"),
    "DES/ECB/PKCS5Padding": (Severity.HIGH, "DES has a 56-bit key and is brute forceable"),
    "DES": (Severity.HIGH, "DES has a 56-bit key and is brute forceable"),
    "DESede": (Severity.HIGH, "3DES is deprecated and vulnerable to Sweet32"),
    "RC4": (Severity.HIGH, "RC4 keystream biases allow plaintext recovery"),
    "ARC4": (Severity.HIGH, "RC4 keystream biases allow plaintext recovery"),
    "Blowfish": (Severity.MEDIUM, "Blowfish has a 64-bit block and is superseded by AES"),
    "RC2": (Severity.MEDIUM, "RC2 is a broken legacy cipher"),
}

_WEAK_DIGESTS = ("MD5", "SHA-1", "SHA1")

_PROVIDER_MARKERS = ("bouncycastle", "spongycastle", "crypto/tink", "conscrypt")

_KEY_MATERIAL = re.compile(r"^[A-Za-z0-9+/=_-]{16,44}$")
# Raw byte counts a symmetric key can actually have.
_KEY_LENGTHS = (16, 24, 32)
_MIN_KEY_ENTROPY = 3.0
# snake_case identifiers: Android resource names, generated constants, log tags.
_SNAKE_IDENT = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$")
# JCA/JSSE algorithm, transformation and spec names. They are ordinary mixed
# alphanumerics of key-ish length ("PBEWithMD5AndDES" is exactly 16 characters),
# so without this they read as key material on apps doing key derivation right.
_JCA_ALGORITHM = re.compile(
    r"^(?:AES|ARC4|Blowfish|ChaCha|DESede|DES|DH|DSA|ECDH|ECDSA|EC|HMAC|Hmac|MD\d|PBE|PBKDF|"
    r"PKCS|Poly|RC\d|RSA|SHA|SSL|TLS|X509|X\.509)"
)
_ALGORITHM_WORDS = ("With", "Padding", "Hmac", "HMAC")


def _bundles_crypto_provider(image: _DexImage) -> bool:
    for descriptor in image.types:
        lowered = descriptor.lower()
        for marker in _PROVIDER_MARKERS:
            if marker in lowered:
                return True
    return False


def _has_aes_transformation(image: _DexImage) -> bool:
    """True when the dex names a full AES transformation ('AES/GCM/NoPadding', 'AES_128/...')."""
    for value in image.strings:
        if value.startswith("AES/") or value.startswith("AES_"):
            return True
    return False


def _shannon_entropy(value: str) -> float:
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(value))
    return -sum((n / total) * math.log(n / total, 2) for n in counts.values())


def _base64_key_bytes(value: str) -> Optional[int]:
    """Length in bytes of *value* decoded as base64, or None when it is not base64."""
    if len(value) % 4:
        return None
    try:
        return len(base64.b64decode(value.replace("-", "+").replace("_", "/"), validate=True))
    except (ValueError, TypeError):
        return None


def _looks_like_key_material(value: str, image: _DexImage) -> bool:
    """True when *value* has the shape of a real symmetric key, not an identifier.

    The gate is deliberately narrow: an identifier-shaped string is a false
    positive machine (algorithm names, resource names and member names all look
    like mixed alphanumerics of the right length), so the string has to be an
    actual key length either raw or once base64 decoded, must not be a name the
    dex uses elsewhere, and must carry some entropy.
    """
    if not _KEY_MATERIAL.match(value):
        return False
    if value in _WEAK_CIPHER_ALGOS or value in image.method_names:
        return False
    if value in image.field_names or ("L%s;" % value) in image.type_set:
        return False
    if _JCA_ALGORITHM.match(value) or any(word in value for word in _ALGORITHM_WORDS):
        return False
    if _SNAKE_IDENT.match(value):
        return False
    decoded = _base64_key_bytes(value)
    if len(value) not in _KEY_LENGTHS and decoded not in _KEY_LENGTHS:
        return False
    if "/" in value and decoded is None:
        return False
    return _shannon_entropy(value) >= _MIN_KEY_ENTROPY


@register
class ApkWeakCrypto(Check):
    name = "apk.weak_crypto"
    title = "Weak or misused cryptography in DEX"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        emitted = 0
        seen_algorithms: Set[str] = set()
        keys_emitted = 0
        for dex_name, image in _iter_dex_images(apk_path):
            if emitted >= _MAX_CRYPTO_FINDINGS:
                return
            bundled = _bundles_crypto_provider(image)
            algo_confidence = Confidence.LOW if bundled else Confidence.MEDIUM
            ciphers = self._ciphers(dex_name, image, seen_algorithms, algo_confidence, bundled)
            for finding in ciphers:
                yield finding
                emitted += 1
                if emitted >= _MAX_CRYPTO_FINDINGS:
                    return
            digests = self._digests(dex_name, image, seen_algorithms, algo_confidence, bundled)
            for finding in digests:
                yield finding
                emitted += 1
                if emitted >= _MAX_CRYPTO_FINDINGS:
                    return
            for finding in self._secure_random(dex_name, image, seen_algorithms):
                yield finding
                emitted += 1
                if emitted >= _MAX_CRYPTO_FINDINGS:
                    return
            for finding in self._hardcoded_keys(dex_name, image, _MAX_KEY_FINDINGS - keys_emitted):
                yield finding
                emitted += 1
                keys_emitted += 1
                if emitted >= _MAX_CRYPTO_FINDINGS:
                    return

    def _provider_note(self, bundled: bool) -> str:
        if not bundled:
            return ""
        return (
            " This dex also bundles a full crypto provider, which legitimately names every "
            "algorithm it supports, so confidence is reduced to low."
        )

    def _ciphers(
        self,
        dex_name: str,
        image: _DexImage,
        seen: Set[str],
        confidence: Confidence,
        bundled: bool,
    ) -> Iterable[Finding]:
        if _CIPHER_GET_INSTANCE not in image.methods:
            return
        for algorithm in sorted(_WEAK_CIPHER_ALGOS):
            if algorithm in seen or algorithm not in image.string_set:
                continue
            seen.add(algorithm)
            severity, reason = _WEAK_CIPHER_ALGOS[algorithm]
            yield Finding(
                check=self.name,
                title="Weak cipher transformation '%s'" % algorithm,
                severity=severity,
                confidence=confidence,
                category="MASVS-CRYPTO",
                cwe="CWE-327",
                description="The DEX string table contains the exact transformation '%s' and the "
                "method reference table contains Cipher.getInstance, so the app requests that "
                "transformation at runtime. %s.%s"
                % (algorithm, reason, self._provider_note(bundled)),
                remediation="Use an authenticated modern transformation such as "
                "AES/GCM/NoPadding with a 256-bit key and a unique random IV per message, and "
                "delete the legacy algorithm from the code base.",
                location="%s:cipher:%s" % (dex_name, algorithm),
                evidence="string '%s' + %s" % (algorithm, _CIPHER_GET_INSTANCE),
                references=_MASVS_REF,
            )
        # The bare string "AES" is mandatory for SecretKeySpec(key, "AES") and
        # KeyGenerator.getInstance("AES"), so on its own it says nothing at all.
        # It is only evidence of a mode-less Cipher.getInstance when this dex
        # names no full AES transformation anywhere that the call could use.
        if "AES" not in seen and "AES" in image.string_set and not _has_aes_transformation(image):
            seen.add("AES")
            yield Finding(
                check=self.name,
                title="Cipher.getInstance(\"AES\") relies on the JCE default mode",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="MASVS-CRYPTO",
                cwe="CWE-327",
                description="The DEX contains Cipher.getInstance and the bare algorithm string "
                "'AES', and no 'AES/<mode>/<padding>' transformation string anywhere in the same "
                "dex, so the bare name is the only AES algorithm string that call has available. "
                "Requesting 'AES' without a mode makes the JCE fall back to ECB on Android, "
                "which leaks plaintext structure because identical plaintext blocks produce "
                "identical ciphertext blocks. Confirm the argument by hand: the same string is "
                "also the algorithm name SecretKeySpec and KeyGenerator take.%s"
                % self._provider_note(bundled),
                remediation="Always name the full transformation, for example "
                "AES/GCM/NoPadding, and never rely on the provider default mode.",
                location="%s:cipher:AES" % dex_name,
                evidence="string 'AES' + %s, no AES transformation string in %s"
                % (_CIPHER_GET_INSTANCE, dex_name),
                references=_MASVS_REF,
            )

    def _digests(
        self,
        dex_name: str,
        image: _DexImage,
        seen: Set[str],
        confidence: Confidence,
        bundled: bool,
    ) -> Iterable[Finding]:
        if _DIGEST_GET_INSTANCE not in image.methods:
            return
        for digest in _WEAK_DIGESTS:
            key = "digest:%s" % digest
            if key in seen or digest not in image.string_set:
                continue
            seen.add(key)
            yield Finding(
                check=self.name,
                title="Broken hash algorithm '%s' requested" % digest,
                severity=Severity.LOW,
                confidence=confidence,
                category="MASVS-CRYPTO",
                cwe="CWE-328",
                description="The DEX contains the exact string '%s' together with "
                "MessageDigest.getInstance. %s is collision-prone and must not back signatures, "
                "integrity checks, password storage or token derivation. This is a review "
                "prompt rather than a confirmed defect: the same call is often a non-security "
                "checksum such as a cache key.%s" % (digest, digest, self._provider_note(bundled)),
                remediation="Use SHA-256 or stronger for integrity, HMAC-SHA256 for "
                "authentication, and a memory-hard KDF (Argon2, scrypt, PBKDF2) for passwords.",
                location="%s:digest:%s" % (dex_name, digest),
                evidence="string '%s' + %s" % (digest, _DIGEST_GET_INSTANCE),
                references=_MASVS_REF,
            )

    def _secure_random(
        self, dex_name: str, image: _DexImage, seen: Set[str]
    ) -> Iterable[Finding]:
        if _SECURE_RANDOM_SET_SEED not in image.methods or "securerandom.setSeed" in seen:
            return
        seen.add("securerandom.setSeed")
        yield Finding(
            check=self.name,
            title="SecureRandom is explicitly seeded",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="MASVS-CRYPTO",
            cwe="CWE-335",
            description="The DEX references SecureRandom.setSeed. Seeding a SecureRandom with "
            "an application-supplied value (a constant, a timestamp or a device identifier) "
            "makes the generated stream predictable, which undermines every key, IV, nonce or "
            "token derived from it.",
            remediation="Construct SecureRandom with no arguments and never call setSeed; the "
            "platform seeds it from the kernel entropy pool.",
            location="%s:securerandom" % dex_name,
            evidence="method ref %s" % _SECURE_RANDOM_SET_SEED,
            references=_MASVS_REF,
        )

    def _hardcoded_keys(self, dex_name: str, image: _DexImage, budget: int) -> Iterable[Finding]:
        if budget <= 0 or _SECRET_KEY_SPEC_INIT not in image.methods:
            return
        emitted = 0
        for value in image.strings:
            if emitted >= budget:
                return
            if not _looks_like_key_material(value, image):
                continue
            emitted += 1
            redacted = value[:6] + "..." if len(value) > 6 else "..."
            yield Finding(
                check=self.name,
                title="Possible hardcoded symmetric key material",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="MASVS-CRYPTO",
                cwe="CWE-321",
                description="The DEX references SecretKeySpec.<init> and contains a %d character "
                "string that has the shape of raw or base64 key material. A key compiled into "
                "the APK is readable by anyone who unzips it, so any data it protects is "
                "effectively unprotected." % len(value),
                remediation="Derive keys at runtime from a user secret or the Android Keystore, "
                "store key handles rather than key bytes, and rotate any key that shipped in a "
                "released build.",
                location="%s:secretkeyspec:%s" % (dex_name, redacted),
                evidence="candidate key '%s' with %s" % (redacted, _SECRET_KEY_SPEC_INIT),
                references=_MASVS_REF,
            )


# --------------------------------------------------------------------------- #
# apk.build_hardening
# --------------------------------------------------------------------------- #

_R8_MARKER = "~~R8{"
_D8_MARKER = "~~D8{"


def _parse_markers(strings: Iterable[str]) -> List[Tuple[str, dict]]:
    out: List[Tuple[str, dict]] = []
    for value in strings:
        if not (value.startswith(_R8_MARKER) or value.startswith(_D8_MARKER)):
            continue
        try:
            parsed = json.loads(value[4:])
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            out.append((value[:4], parsed))
    return out


@register
class ApkBuildHardening(Check):
    name = "apk.build_hardening"
    title = "Debug-mode compile, no R8 shrinking/obfuscation, testOnly, or shipped mapping file"
    target_kinds = (TargetKind.APK,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        apk_path = ctx.target.apk_path
        if not apk_path:
            return
        emitted = 0
        markers: List[Tuple[str, str, dict]] = []
        ratio: Optional[float] = None
        for dex_name, image in _iter_dex_images(apk_path):
            for tool, payload in _parse_markers(image.strings):
                markers.append((dex_name, tool, payload))
            if ratio is None:
                ratio = _short_class_ratio(image)

        manifest = manifest_attributes(apk_path)

        for finding in self._debug_markers(markers):
            yield finding
            emitted += 1
            if emitted >= _MAX_BUILD_FINDINGS:
                return
        for finding in self._d8_only(markers, ratio):
            yield finding
            emitted += 1
            if emitted >= _MAX_BUILD_FINDINGS:
                return
        for finding in self._test_only(manifest):
            yield finding
            emitted += 1
            if emitted >= _MAX_BUILD_FINDINGS:
                return
        for finding in self._mapping_file(apk_path):
            yield finding
            emitted += 1
            if emitted >= _MAX_BUILD_FINDINGS:
                return
        for finding in self._min_api_mismatch(markers, manifest):
            yield finding
            emitted += 1
            if emitted >= _MAX_BUILD_FINDINGS:
                return

    def _debug_markers(self, markers: Sequence[Tuple[str, str, dict]]) -> Iterable[Finding]:
        for dex_name, tool, payload in markers:
            if str(payload.get("compilation-mode", "")).lower() != "debug":
                continue
            yield Finding(
                check=self.name,
                title="Application was compiled in debug mode",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MASVS-RESILIENCE",
                cwe="CWE-489",
                description="The %s build marker embedded in %s records "
                "compilation-mode=debug. A debug compile keeps line numbers, local variable "
                "names and assertions in the shipped DEX and skips release optimisation, which "
                "makes the app markedly easier to reverse engineer and often indicates a "
                "non-release artefact reached distribution." % (tool, dex_name),
                remediation="Publish artefacts built by the release variant (R8 in release "
                "mode) and fail the pipeline when a debug-compiled DEX reaches a store build.",
                location="%s:%s-marker" % (dex_name, tool.strip("~")),
                evidence="%s compilation-mode=debug version=%s"
                % (tool, payload.get("version", "unknown")),
                references=_MASVS_REF,
            )
            return

    def _d8_only(
        self, markers: Sequence[Tuple[str, str, dict]], ratio: Optional[float]
    ) -> Iterable[Finding]:
        tools = {tool for _dex, tool, _payload in markers}
        if "~~D8" not in tools or "~~R8" in tools:
            return
        if ratio is not None and ratio > 0.30:
            # Already obfuscated by some other tool: the D8 marker alone proves nothing.
            return
        if ratio is None:
            confidence = Confidence.MEDIUM
            corroboration = "the dex is too small to measure class-name obfuscation"
        elif ratio < 0.05:
            confidence = Confidence.HIGH
            corroboration = "%.0f%% of class names are 1-2 characters, so nothing was renamed" % (
                ratio * 100
            )
        else:
            confidence = Confidence.MEDIUM
            corroboration = "%.0f%% of class names are 1-2 characters" % (ratio * 100)
        dex_name = markers[0][0] if markers else "classes.dex"
        yield Finding(
            check=self.name,
            title="DEX built by D8 without R8 shrinking or obfuscation",
            severity=Severity.LOW,
            confidence=confidence,
            category="MASVS-RESILIENCE",
            cwe="CWE-656",
            description="A D8 build marker is present and no R8 marker is, so the app was "
            "dexed without the shrinking, optimisation and identifier renaming R8 performs; %s. "
            "Unobfuscated code with full class, method and field names lowers the cost of "
            "reverse engineering business logic and locating security controls." % corroboration,
            remediation="Enable R8 for release builds (minifyEnabled true with a reviewed "
            "keep-rule set) and verify the shipped DEX carries an R8 marker.",
            location="%s:d8-only" % dex_name,
            evidence="D8 marker present, no R8 marker in any dex",
            references=_MASVS_REF,
        )

    def _test_only(self, manifest: Dict[int, str]) -> Iterable[Finding]:
        value = manifest.get(_RES_TEST_ONLY)
        if value is None or str(value).strip().lower() != "true":
            return
        yield Finding(
            check=self.name,
            title="Application manifest declares android:testOnly",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="MASVS-RESILIENCE",
            cwe="CWE-489",
            description="android:testOnly is true in AndroidManifest.xml. testOnly builds are "
            "produced for instrumentation, are installable only with 'adb install -t', and are "
            "commonly paired with debug signing and test-only endpoints. Shipping one indicates "
            "a non-release artefact escaped the build pipeline.",
            remediation="Remove android:testOnly from release builds and gate publishing on a "
            "manifest assertion so a testOnly artefact can never be uploaded.",
            location="AndroidManifest.xml",
            evidence="application@android:testOnly=true",
            references=_MASVS_REF,
        )

    def _mapping_file(self, apk_path: str) -> Iterable[Finding]:
        for name in _zip_names(apk_path, _MAPPING_ENTRY):
            yield Finding(
                check=self.name,
                title="ProGuard/R8 mapping file packaged in the APK",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="MASVS-RESILIENCE",
                cwe="CWE-540",
                description="The archive contains %s, the obfuscation mapping produced at build "
                "time. It maps every renamed class, method and field back to its original name, "
                "so anyone who unzips the APK can undo the obfuscation completely and read the "
                "code as if it had never been minified." % name,
                remediation="Stop copying mapping.txt into the packaged assets, keep it in the "
                "build artefact store for crash de-obfuscation only, and add a packaging check "
                "that fails the build if it reappears.",
                location=name,
                evidence="zip entry %s" % name,
                references=_MASVS_REF,
            )
            return

    def _min_api_mismatch(
        self, markers: Sequence[Tuple[str, str, dict]], manifest: Dict[int, str]
    ) -> Iterable[Finding]:
        raw = manifest.get(_RES_MIN_SDK)
        if raw is None:
            return
        try:
            min_sdk = int(str(raw).strip())
        except (TypeError, ValueError):
            return
        for dex_name, tool, payload in markers:
            marker_api = payload.get("min-api")
            if not isinstance(marker_api, int) or marker_api == min_sdk:
                continue
            yield Finding(
                check=self.name,
                title="Build marker min-api disagrees with manifest minSdkVersion",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                category="MASVS-RESILIENCE",
                description="The %s marker in %s records min-api=%d while AndroidManifest.xml "
                "declares minSdkVersion=%d. The DEX was therefore compiled for a different API "
                "floor than the one the manifest advertises, which usually means a stale or "
                "externally produced DEX was merged into the package."
                % (tool, dex_name, marker_api, min_sdk),
                remediation="Rebuild the package so the dexing min-api and the manifest "
                "minSdkVersion come from the same build configuration.",
                location="%s:min-api" % dex_name,
                evidence="marker min-api=%d, manifest minSdkVersion=%d" % (marker_api, min_sdk),
                references=_MASVS_REF,
            )
            return
