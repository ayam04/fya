from __future__ import annotations

from fya.detect import detect_target, is_local
from fya.models import TargetKind


def test_detect_url_is_web():
    target = detect_target("https://example.com/path")
    assert target.kind is TargetKind.WEB
    assert target.host == "example.com"


def test_detect_apk_path_is_apk(fake_apk):
    target = detect_target(fake_apk)
    assert target.kind is TargetKind.APK
    assert target.apk_path


def test_base_url_normalization():
    target = detect_target("https://example.com:8443/path/")
    assert target.base_url() == "https://example.com:8443"

    default_https = detect_target("https://example.com/")
    assert default_https.base_url() == "https://example.com"

    default_http = detect_target("http://localhost/")
    assert default_http.base_url() == "http://localhost"


def test_is_local():
    assert is_local("localhost") is True
    assert is_local("127.0.0.1") is True
    assert is_local("10.0.0.5") is True
    assert is_local("example.com") is False
