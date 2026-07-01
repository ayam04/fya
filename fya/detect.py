from __future__ import annotations

import ipaddress
import os
import zipfile
from urllib.parse import urlparse

from .models import Target, TargetKind

_LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_local(hostname: str) -> bool:
    if not hostname:
        return False
    if hostname in _LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return hostname.endswith(".local")


def _looks_like_apk(path: str) -> bool:
    if path.lower().endswith(".apk"):
        return True
    if os.path.isfile(path) and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                return "AndroidManifest.xml" in zf.namelist()
        except zipfile.BadZipFile:
            return False
    return False


def detect_target(raw: str) -> Target:
    candidate = raw.strip()
    if _looks_like_apk(candidate):
        return Target(raw=raw, kind=TargetKind.APK, apk_path=os.path.abspath(candidate))
    return _web_target(candidate)


def _web_target(raw: str) -> Target:
    candidate = raw
    if "://" not in candidate:
        hostname = candidate.split("/")[0].split(":")[0]
        scheme = "http" if is_local(hostname) else "https"
        candidate = f"{scheme}://{raw}"
    parsed = urlparse(candidate)
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme == "http" else 443
    url = candidate.rstrip("/") or candidate
    return Target(
        raw=raw,
        kind=TargetKind.WEB,
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=port,
        url=url,
    )
