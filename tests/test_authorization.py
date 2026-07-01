from __future__ import annotations

from fya.authorization import authorize
from fya.detect import detect_target


def test_remote_https_refused_without_authorization():
    target = detect_target("https://example.com")
    allowed, _reason = authorize(target, authorized=False)
    assert allowed is False


def test_remote_https_allowed_with_authorization():
    target = detect_target("https://example.com")
    allowed, _reason = authorize(target, authorized=True)
    assert allowed is True


def test_localhost_allowed():
    target = detect_target("http://localhost:8080")
    allowed, _reason = authorize(target, authorized=False)
    assert allowed is True


def test_apk_allowed(fake_apk):
    target = detect_target(fake_apk)
    allowed, _reason = authorize(target, authorized=False)
    assert allowed is True
