from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import threading

import pytest
from flask import Flask, Response
from werkzeug.serving import make_server

from fya.checks.web_crypto_audit import (
    _VIEWSTATE_FMT,
    JWTHeaderInjection,
    MixedContent,
    TLSCertificateStrength,
    _viewstate_verdict,
)
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Confidence, Profile, ScanContext, Severity, Target, TargetKind

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_ALG = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _seg(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _make_jwt(header, payload, secret) -> str:
    signing_input = f"{_seg(header)}.{_seg(payload)}"
    mac = hmac.new(secret.encode(), signing_input.encode(), _ALG[header["alg"]]).digest()
    sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    return f"{signing_input}.{sig}"


# Scope every scan to this module's checks: a unit test for one check must not depend on
# the other ~90 checks crawling the same dev server (that made results load-dependent).
_CHECKS = {
    "tls.certificate_strength",
    "web.jwt_header_injection",
    "web.jwt_weak_secret",
    "web.mixed_content",
    "web.serialized_objects",
}


def _scan(base):
    target = detect_target(base)
    return run_scan(
        target, profile=Profile.AGGRESSIVE, detect_external=False, categories=_CHECKS
    )


# ---------------------------------------------------------------------------
# web.jwt_weak_secret
# ---------------------------------------------------------------------------


def test_jwt_weak_secret_fires(serve_app):
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": 1, "role": "admin"}, "secret")
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(f"<html><body><p>session={token}</p></body></html>")

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.jwt_weak_secret" in names
    assert not result.errors, result.errors


def test_jwt_weak_secret_silent_on_strong_secret(serve_app):
    strong = "9f2c8e1a7b6d4f3e0a1c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071"
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": 1}, strong)
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(f"<html><body><p>session={token}</p></body></html>")

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.jwt_weak_secret" not in names
    assert "web.jwt_header_injection" not in names
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.jwt_header_injection
# ---------------------------------------------------------------------------


def test_jwt_header_injection_fires(serve_app):
    header = {"alg": "HS256", "typ": "JWT", "jku": "http://evil.example/jwks.json"}
    token = _make_jwt(header, {"sub": 1}, "unrelated-random-signing-key-value")
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(f"<html><body><p>id_token={token}</p></body></html>")

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.jwt_header_injection" in names
    assert not result.errors, result.errors


def test_jwt_header_injection_fires_on_off_domain_https_jku(serve_app):
    header = {"alg": "HS256", "typ": "JWT", "jku": "https://evil.example/jwks.json"}
    token = _make_jwt(header, {"sub": 1}, "unrelated-random-signing-key-value")
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(f"<html><body><p>id_token={token}</p></body></html>")

    result = _scan(serve_app(app))
    findings = [f for f in result.findings if f.check == "web.jwt_header_injection"]
    assert findings
    assert not result.errors, result.errors


def test_jwt_key_url_on_same_registrable_domain_is_not_reported():
    # Pointing jku at your own identity provider is the correct architecture, not a finding.
    assert (
        JWTHeaderInjection._url_verdict(
            "https://login.example.com/.well-known/jwks.json", "www.example.com"
        )
        is None
    )
    assert (
        JWTHeaderInjection._url_verdict("https://sso.example.co.uk/jwks.json", "www.example.co.uk")
        is None
    )


def test_jwt_key_url_off_domain_is_low_and_unconfirmed():
    verdict = JWTHeaderInjection._url_verdict("https://evil.example/jwks.json", "shop.example")
    assert verdict is not None
    text, severity, confidence = verdict
    assert "evil.example" in text
    assert severity is Severity.LOW
    assert confidence is Confidence.LOW


def test_jwt_key_url_plaintext_http_stays_medium():
    verdict = JWTHeaderInjection._url_verdict("http://shop.example/jwks.json", "shop.example")
    assert verdict is not None
    text, severity, confidence = verdict
    assert "plaintext" in text
    assert severity is Severity.MEDIUM
    assert confidence is Confidence.MEDIUM


def test_jwt_header_injection_silent_on_clean_header(serve_app):
    header = {"alg": "HS256", "typ": "JWT", "kid": "2024-signing-key-1"}
    token = _make_jwt(header, {"sub": 1}, "unrelated-random-signing-key-value")
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(f"<html><body><p>id_token={token}</p></body></html>")

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.jwt_header_injection" not in names
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.serialized_objects
# ---------------------------------------------------------------------------


def test_serialized_objects_fires(serve_app):
    java_blob = base64.b64encode(b"\xac\xed\x00\x05t\x00\x0asome-object" + b"\x01" * 16).decode()
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            "<html><body><form>"
            f'<input type="hidden" name="state" value="{java_blob}">'
            '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKLTEyMzQ1Njc4OWRk">'
            '</form><a href="/p?data=a:2:{i:0;i:42;i:1;i:7;}">next</a>'
            "</body></html>"
        )

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.serialized_objects" in names
    assert not result.errors, result.errors


def test_serialized_objects_ignores_viewstate_siblings(serve_app):
    # A stock ASP.NET WebForms page with ViewState disabled: __VIEWSTATEGENERATOR is an
    # 8-hex-digit page identity hash and __EVENTVALIDATION is always MAC'd - neither is a
    # serialized object graph, and an empty __VIEWSTATE carries nothing at all.
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            "<html><body><form>"
            '<input type="hidden" name="__VIEWSTATE" value="">'
            '<input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">'
            '<input type="hidden" name="__EVENTVALIDATION" value="/wEdAAK1234567890abcdefghij">'
            "</form></body></html>"
        )

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.serialized_objects" not in names
    assert not result.errors, result.errors


def test_serialized_objects_unencrypted_viewstate_is_a_single_low_finding(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            "<html><body><form>"
            '<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKLTEyMzQ1Njc4OWRk">'
            '<input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">'
            "</form></body></html>"
        )

    result = _scan(serve_app(app))
    findings = [f for f in result.findings if f.check == "web.serialized_objects"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert findings[0].confidence is Confidence.LOW
    assert "__VIEWSTATE]" in findings[0].location
    assert not result.errors, result.errors


def test_viewstate_verdict_requires_the_exact_field_and_plaintext_marker():
    plain = base64.b64encode(b"\xff\x01\x0f\x0f\x05\na-plain-viewstate-blob").decode()
    assert _viewstate_verdict("hidden:__VIEWSTATE", plain) == _VIEWSTATE_FMT
    assert _viewstate_verdict("hidden:__VIEWSTATE", "") is None
    assert _viewstate_verdict("hidden:__VIEWSTATEGENERATOR", plain) is None
    assert _viewstate_verdict("hidden:__EVENTVALIDATION", plain) is None
    encrypted = base64.b64encode(bytes(range(3, 48))).decode()
    assert _viewstate_verdict("hidden:__VIEWSTATE", encrypted) is None


def test_serialized_objects_silent_on_clean_app(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            "<html><body><form>"
            '<input type="hidden" name="csrf" value="abc123token">'
            '<input type="hidden" name="page" value="42">'
            '</form><a href="/p?data=hello&amp;lang=en">next</a>'
            "</body></html>"
        )

    result = _scan(serve_app(app))
    names = {f.check for f in result.findings}
    assert "web.serialized_objects" not in names
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.mixed_content (direct invocation: requires an https origin)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body, url):
        self.text = body
        self.url = url
        self.status_code = 200
        self.headers = {"content-type": "text/html"}
        self.cookies = []


class _FakeHTTP:
    def __init__(self, response):
        self._response = response

    def get(self, url, **kwargs):
        return self._response


def _https_ctx(body):
    target = Target(
        raw="https://shop.example",
        kind=TargetKind.WEB,
        scheme="https",
        host="shop.example",
        port=443,
        url="https://shop.example/",
    )
    resp = _FakeResponse(body, "https://shop.example/")
    return ScanContext(target=target, profile=Profile.AGGRESSIVE, http=_FakeHTTP(resp))


def test_mixed_content_fires():
    body = (
        "<html><head>"
        '<script src="http://cdn.evil.example/tracker.js"></script>'
        '<link rel="stylesheet" href="http://cdn.evil.example/app.css">'
        "</head><body>"
        '<img src="http://img.evil.example/pixel.png">'
        "</body></html>"
    )
    findings = list(MixedContent().run(_https_ctx(body)))
    checks = {f.check for f in findings}
    assert "web.mixed_content" in checks
    severities = {f.severity.value for f in findings}
    assert "high" in severities


def test_mixed_content_favicon_and_image_preload_are_passive():
    body = (
        "<html><head>"
        '<link rel="icon" href="http://static.example/favicon.ico">'
        '<link rel="preload" as="image" href="http://static.example/hero.jpg">'
        "</head><body></body></html>"
    )
    findings = list(MixedContent().run(_https_ctx(body)))
    assert len(findings) == 2
    assert {f.severity for f in findings} == {Severity.LOW}
    assert all("active" not in f.evidence for f in findings)


def test_mixed_content_executable_preloads_stay_active():
    body = (
        "<html><head>"
        '<link rel="preload" as="script" href="http://cdn.evil.example/late.js">'
        '<link rel="modulepreload" href="http://cdn.evil.example/mod.mjs">'
        "</head><body></body></html>"
    )
    findings = list(MixedContent().run(_https_ctx(body)))
    assert len(findings) == 2
    assert {f.severity for f in findings} == {Severity.HIGH}
    assert all("active" in f.evidence for f in findings)


def test_mixed_content_evidence_names_what_matched():
    body = (
        "<html><head>"
        '<script src="http://cdn.evil.example/tracker.js"></script>'
        '<link rel="stylesheet" href="http://cdn.evil.example/app.css">'
        "</head><body>"
        '<iframe src="http://cdn.evil.example/frame.html"></iframe>'
        "</body></html>"
    )
    findings = list(MixedContent().run(_https_ctx(body)))
    kinds = {f.evidence.split(" -> ")[1].split(" subresource")[0] for f in findings}
    assert kinds == {"active (script)", "active (stylesheet)", "active (iframe)"}


def test_mixed_content_silent_on_all_https():
    body = (
        "<html><head>"
        '<script src="https://cdn.example/tracker.js"></script>'
        '<link rel="stylesheet" href="/app.css">'
        "</head><body>"
        '<img src="https://img.example/pixel.png">'
        '<a href="http://external.example/page">plain link is ignored</a>'
        "</body></html>"
    )
    findings = list(MixedContent().run(_https_ctx(body)))
    assert not findings


# ---------------------------------------------------------------------------
# tls.certificate_strength (direct invocation against a live TLS server)
# ---------------------------------------------------------------------------


class _TLSServer(threading.Thread):
    def __init__(self, app, ssl_context):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=ssl_context)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


def _make_cert(tmp_path, hash_alg, key_bits=2048):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hash_alg)
    )
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile)


def _serve_tls(tmp_path, hash_alg, key_bits=2048):
    certfile, keyfile = _make_cert(tmp_path, hash_alg, key_bits=key_bits)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        pass
    context.load_cert_chain(certfile, keyfile)
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    server = _TLSServer(app, context)
    server.start()
    return server


def _tls_ctx(port):
    target = Target(
        raw=f"https://127.0.0.1:{port}",
        kind=TargetKind.WEB,
        scheme="https",
        host="127.0.0.1",
        port=port,
        url=f"https://127.0.0.1:{port}/",
    )
    return ScanContext(target=target, profile=Profile.AGGRESSIVE, http=None)


def test_certificate_strength_fires_on_undersized_key():
    pytest.importorskip("cryptography")
    import tempfile
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes

    tmp = Path(tempfile.mkdtemp())
    server = _serve_tls(tmp, hashes.SHA256(), key_bits=1024)
    try:
        findings = list(TLSCertificateStrength().run(_tls_ctx(server.port)))
    finally:
        server.stop()
        server.join(timeout=5)
    checks = {f.check for f in findings}
    assert "tls.certificate_strength" in checks
    assert any("1024" in f.evidence for f in findings)


def test_certificate_strength_silent_on_strong_cert():
    pytest.importorskip("cryptography")
    import tempfile
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes

    tmp = Path(tempfile.mkdtemp())
    server = _serve_tls(tmp, hashes.SHA256())
    try:
        findings = list(TLSCertificateStrength().run(_tls_ctx(server.port)))
    finally:
        server.stop()
        server.join(timeout=5)
    assert not findings
