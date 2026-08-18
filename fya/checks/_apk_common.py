"""Shared, dependency-free helpers for APK static analysis.

Everything here is stdlib only.

* :func:`read_axml` decodes Android binary XML (AXML) chunks so ``res/xml``
  resources can be inspected without androguard.
* :func:`manifest_tree` returns the decoded ``AndroidManifest.xml`` as an
  ``ElementTree`` root, preferring androguard when it is importable and falling
  back to :func:`read_axml`.
* :func:`iter_entries` walks a zip applying the caller's predicate *before* the
  entry cap, so a large APK's tail is never silently truncated the way a
  ``namelist()[:N]`` slice truncates it.

Nothing here raises: malformed input yields ``None`` / an empty iterator.
"""

from __future__ import annotations

import os
import struct
import zipfile
from typing import Callable, Dict, Iterator, List, Optional, Tuple
from xml.etree import ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"

MAX_ENTRIES = 20000
MAX_ENTRY_BYTES = 64 * 1024 * 1024

_TYPE_STRING_POOL = 0x0001
_TYPE_XML = 0x0003
_TYPE_START_NS = 0x0100
_TYPE_END_NS = 0x0101
_TYPE_START_ELEMENT = 0x0102
_TYPE_END_ELEMENT = 0x0103
_TYPE_CDATA = 0x0104
_TYPE_RESOURCE_MAP = 0x0180

_UTF8_FLAG = 1 << 8
_NO_ENTRY = 0xFFFFFFFF

_VAL_REFERENCE = 0x01
_VAL_ATTRIBUTE = 0x02
_VAL_STRING = 0x03
_VAL_FLOAT = 0x04
_VAL_INT_DEC = 0x10
_VAL_INT_HEX = 0x11
_VAL_INT_BOOL = 0x12

_MAX_STRINGS = 200_000
_MAX_ATTRS = 512
_MAX_DEPTH = 256
_MAX_ELEMENTS = 60_000
_MANIFEST_CACHE_SIZE = 8

# Best-effort framework attribute resource ids. Only consulted when an
# attribute's name string is empty in the pool (common with obfuscated or
# hand-built manifests); a normal build carries the real name string.
_ATTR_IDS: Dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010004: "manageSpaceActivity",
    0x01010005: "allowClearUserData",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000A: "permissionGroup",
    0x0101000B: "sharedUserId",
    0x0101000C: "hasCode",
    0x0101000D: "persistent",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010012: "taskAffinity",
    0x01010013: "multiprocess",
    0x01010014: "finishOnTaskLaunch",
    0x01010015: "clearTaskOnLaunch",
    0x01010016: "stateNotNeeded",
    0x01010017: "excludeFromRecents",
    0x01010018: "authorities",
    0x01010019: "syncable",
    0x0101001A: "initOrder",
    0x0101001B: "grantUriPermissions",
    0x0101001C: "priority",
    0x0101001D: "launchMode",
    0x0101001E: "screenOrientation",
    0x0101001F: "configChanges",
    0x01010020: "description",
    0x01010021: "targetPackage",
    0x01010022: "handleProfiling",
    0x01010023: "functionalTest",
    0x01010024: "value",
    0x01010025: "resource",
    0x01010026: "mimeType",
    0x01010027: "scheme",
    0x01010028: "host",
    0x01010029: "port",
    0x0101002A: "path",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x0101002D: "action",
    0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x0101027F: "backupAgent",
    0x01010280: "allowBackup",
    0x010104EB: "fullBackupContent",
    0x010104EC: "usesCleartextTraffic",
    0x010104EE: "autoVerify",
    0x01010527: "networkSecurityConfig",
}


def local_name(tag: str) -> str:
    """Strip a ``{namespace}`` prefix from an ElementTree tag or attribute key."""
    if tag and tag.startswith("{"):
        end = tag.find("}")
        if end != -1:
            return tag[end + 1 :]
    return tag or ""


def attr(node, name: str) -> Optional[str]:
    """Read ``android:name`` and fall back to the un-namespaced ``name``.

    res/xml resources (network security config, FileProvider paths, backup
    rules) use un-namespaced attributes while the manifest uses the android
    namespace, so every caller wants both spellings.
    """
    if node is None:
        return None
    value = node.get("{%s}%s" % (ANDROID_NS, name))
    if value is None:
        value = node.get(name)
    return value


def is_true(value) -> bool:
    return str(value).strip().lower() == "true"


def open_apk(apk_path: str) -> Optional[zipfile.ZipFile]:
    """Open an APK as a zip, or return None when it is not readable."""
    if not apk_path:
        return None
    try:
        return zipfile.ZipFile(apk_path)
    except (OSError, zipfile.BadZipFile):
        return None


def iter_entries(
    zf: zipfile.ZipFile,
    predicate: Callable[[str], object],
    max_entries: int = MAX_ENTRIES,
    max_bytes: int = MAX_ENTRY_BYTES,
) -> Iterator[Tuple[str, bytes]]:
    """Yield ``(name, data)`` for entries matching ``predicate``.

    The predicate is applied to the entry name *before* the ``max_entries``
    counter moves, so the cap bounds how many interesting entries are read
    rather than how deep into the archive the walk gets. Entries larger than
    ``max_bytes`` and entries that fail to decompress are skipped silently.
    """
    try:
        infos = zf.infolist()
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return
    seen = 0
    for info in infos:
        name = info.filename
        try:
            if not predicate(name):
                continue
        except Exception:
            continue
        seen += 1
        if seen > max_entries:
            return
        if info.file_size > max_bytes:
            continue
        try:
            data = zf.read(name)
        except (OSError, zipfile.BadZipFile, RuntimeError, KeyError, NotImplementedError):
            continue
        yield name, data


def read_axml(data: bytes) -> Optional[ET.Element]:
    """Decode Android binary XML into an ElementTree root, or None.

    Returns None for anything malformed: a bad magic, a chunk whose declared
    size does not fit the buffer, an oversized string pool, or a document with
    more than one root. Plain-text XML is accepted too, which keeps the helper
    useful against already-decoded manifests.
    """
    if not data:
        return None
    try:
        return _decode_axml(bytes(data))
    except Exception:
        return None


def manifest_tree(apk_path: str) -> Optional[ET.Element]:
    """Return the decoded ``AndroidManifest.xml`` root element, or None."""
    if not apk_path:
        return None
    key = _cache_key(apk_path)
    if key is not None and key in _MANIFEST_CACHE:
        return _MANIFEST_CACHE[key]
    root = _load_manifest(apk_path)
    if key is not None:
        if len(_MANIFEST_CACHE) >= _MANIFEST_CACHE_SIZE:
            _MANIFEST_CACHE.clear()
        _MANIFEST_CACHE[key] = root
    return root


_MANIFEST_CACHE: Dict[tuple, Optional[ET.Element]] = {}


def _cache_key(apk_path: str) -> Optional[tuple]:
    try:
        stat = os.stat(apk_path)
    except OSError:
        return None
    return (os.path.abspath(apk_path), stat.st_size, stat.st_mtime_ns)


def _load_manifest(apk_path: str) -> Optional[ET.Element]:
    root = _manifest_via_androguard(apk_path)
    if root is not None and local_name(root.tag) == "manifest":
        return root
    zf = open_apk(apk_path)
    if zf is None:
        return None
    with zf:
        try:
            info = zf.getinfo("AndroidManifest.xml")
        except KeyError:
            return None
        if info.file_size > MAX_ENTRY_BYTES:
            return None
        try:
            data = zf.read("AndroidManifest.xml")
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
            return None
    return read_axml(data)


def _manifest_via_androguard(apk_path: str) -> Optional[ET.Element]:
    try:
        from androguard.core.apk import APK
    except Exception:
        return None
    try:
        import logging

        logging.getLogger("androguard").setLevel(logging.ERROR)
        try:
            from loguru import logger

            logger.disable("androguard")
        except Exception:
            pass
        return APK(apk_path).get_android_manifest_xml()
    except Exception:
        return None


# --------------------------------------------------------------------------
# AXML decoding
# --------------------------------------------------------------------------


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def _decode_axml(data: bytes) -> Optional[ET.Element]:
    if len(data) < 8:
        return None
    magic, header_size, total = struct.unpack_from("<HHI", data, 0)
    if magic != _TYPE_XML:
        return _parse_plain_xml(data)
    if total < 8 or total > len(data):
        total = len(data)
    pos = header_size if 8 <= header_size <= total else 8

    pool: List[str] = []
    res_ids: List[int] = []
    stack: List[ET.Element] = []
    root: Optional[ET.Element] = None
    elements = 0

    while pos + 8 <= total:
        ctype, chunk_header, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > total:
            return None
        chunk_end = pos + csize
        body = pos + (chunk_header if chunk_header >= 16 else 16)

        if ctype == _TYPE_STRING_POOL:
            parsed = _parse_string_pool(data, pos, csize)
            if parsed is None:
                return None
            pool = parsed
        elif ctype == _TYPE_RESOURCE_MAP:
            count = (csize - 8) // 4
            if count > _MAX_STRINGS:
                return None
            res_ids = list(struct.unpack_from("<%dI" % count, data, pos + 8)) if count else []
        elif ctype == _TYPE_START_ELEMENT:
            if body + 16 > chunk_end:
                return None
            elem = _build_element(data, pool, res_ids, body, chunk_end)
            if elem is None:
                return None
            elements += 1
            if elements > _MAX_ELEMENTS:
                return None
            if stack:
                stack[-1].append(elem)
            elif root is None:
                root = elem
            else:
                return None
            stack.append(elem)
            if len(stack) > _MAX_DEPTH:
                return None
        elif ctype == _TYPE_END_ELEMENT:
            if stack:
                stack.pop()
        elif ctype == _TYPE_CDATA:
            if stack and body + 4 <= chunk_end:
                _append_text(stack[-1], _pool_get(pool, _u32(data, body)))
        elif ctype in (_TYPE_START_NS, _TYPE_END_NS):
            pass
        pos = chunk_end

    return root


def _build_element(
    data: bytes, pool: List[str], res_ids: List[int], body: int, chunk_end: int
) -> Optional[ET.Element]:
    ns_idx = _u32(data, body)
    name_idx = _u32(data, body + 4)
    attr_start = _u16(data, body + 8)
    attr_size = _u16(data, body + 10)
    attr_count = _u16(data, body + 12)

    name = _pool_get(pool, name_idx)
    if not name:
        return None
    ns_uri = _pool_get(pool, ns_idx)
    tag = "{%s}%s" % (ns_uri, name) if ns_uri else name
    try:
        elem = ET.Element(tag)
    except (TypeError, ValueError):
        return None

    if attr_size < 20:
        attr_size = 20
    if attr_count > _MAX_ATTRS:
        attr_count = _MAX_ATTRS
    apos = body + attr_start
    for _ in range(attr_count):
        if apos < body or apos + 20 > chunk_end:
            break
        a_ns = _u32(data, apos)
        a_name = _u32(data, apos + 4)
        a_raw = _u32(data, apos + 8)
        a_type = data[apos + 15]
        a_data = _u32(data, apos + 16)
        key = _attr_key(pool, res_ids, a_ns, a_name)
        if key:
            elem.set(key, _attr_value(pool, a_raw, a_type, a_data))
        apos += attr_size
    return elem


def _append_text(elem: ET.Element, text: str) -> None:
    if not text:
        return
    if len(elem):
        last = elem[-1]
        last.tail = (last.tail or "") + text
    else:
        elem.text = (elem.text or "") + text


def _attr_key(pool: List[str], res_ids: List[int], ns_idx: int, name_idx: int) -> str:
    name = _pool_get(pool, name_idx)
    uri = _pool_get(pool, ns_idx)
    if not name:
        rid = res_ids[name_idx] if 0 <= name_idx < len(res_ids) else 0
        name = _ATTR_IDS.get(rid, "")
        if name and not uri:
            uri = ANDROID_NS
    if not name:
        return ""
    if uri:
        return "{%s}%s" % (uri, name)
    return name


def _attr_value(pool: List[str], raw: int, dtype: int, value: int) -> str:
    if raw != _NO_ENTRY and 0 <= raw < len(pool):
        return pool[raw]
    if dtype == _VAL_STRING:
        return _pool_get(pool, value)
    if dtype == _VAL_INT_BOOL:
        return "true" if value else "false"
    if dtype == _VAL_INT_DEC:
        return str(value - 0x100000000 if value >= 0x80000000 else value)
    if dtype == _VAL_INT_HEX:
        return "0x%08x" % value
    if dtype in (_VAL_REFERENCE, _VAL_ATTRIBUTE):
        return "@0x%08x" % value
    if dtype == _VAL_FLOAT:
        try:
            return str(struct.unpack("<f", struct.pack("<I", value))[0])
        except struct.error:
            return ""
    return str(value)


def _pool_get(pool: List[str], idx: int) -> str:
    if idx == _NO_ENTRY or idx < 0 or idx >= len(pool):
        return ""
    return pool[idx]


def _parse_string_pool(data: bytes, off: int, size: int) -> Optional[List[str]]:
    if size < 28 or off + size > len(data):
        return None
    count, _styles, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, off + 8)
    if count > _MAX_STRINGS:
        return None
    index_at = off + 28
    if count and index_at + count * 4 > off + size:
        return None
    if strings_start > size:
        return None
    utf8 = bool(flags & _UTF8_FLAG)
    base = off + strings_start
    end = off + size
    out: List[str] = []
    for i in range(count):
        rel = struct.unpack_from("<I", data, index_at + i * 4)[0]
        start = base + rel
        if rel > size or start + 2 > end:
            out.append("")
            continue
        out.append(_read_pool_string(data, start, end, utf8))
    return out


def _read_pool_string(data: bytes, pos: int, end: int, utf8: bool) -> str:
    if utf8:
        _chars, pos = _len8(data, pos, end)
        nbytes, pos = _len8(data, pos, end)
        if nbytes < 0 or pos + nbytes > end:
            return ""
        return data[pos : pos + nbytes].decode("utf-8", "replace")
    nchars, pos = _len16(data, pos, end)
    if nchars < 0 or pos + nchars * 2 > end:
        return ""
    return data[pos : pos + nchars * 2].decode("utf-16-le", "replace")


def _len8(data: bytes, pos: int, end: int) -> Tuple[int, int]:
    if pos >= end:
        return -1, pos
    value = data[pos]
    pos += 1
    if value & 0x80:
        if pos >= end:
            return -1, pos
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _len16(data: bytes, pos: int, end: int) -> Tuple[int, int]:
    if pos + 2 > end:
        return -1, pos
    value = _u16(data, pos)
    pos += 2
    if value & 0x8000:
        if pos + 2 > end:
            return -1, pos
        value = ((value & 0x7FFF) << 16) | _u16(data, pos)
        pos += 2
    return value, pos


def _parse_plain_xml(data: bytes) -> Optional[ET.Element]:
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n")
    if not head.startswith(b"<"):
        return None
    try:
        return ET.fromstring(data.decode("utf-8", "replace"))
    except ET.ParseError:
        return None
