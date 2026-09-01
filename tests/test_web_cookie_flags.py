from __future__ import annotations

from flask import Flask, make_response

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile, Severity


def test_cookie_flags_with_httponly_and_secure(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        resp = make_response("ok")
        resp.set_cookie(
            "session",
            "abc",
            httponly=True,
            secure=True,
        )
        return resp

    base_url = serve_app(app)
    target = detect_target(base_url)

    result = run_scan(
        target,
        profile=Profile.PASSIVE,
        detect_external=False,
    )

    findings = [
        f for f in result.findings
        if f.check == "web.cookie_flags"
    ]

    assert not findings


def test_cookie_flags_missing_httponly(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        resp = make_response("ok")
        resp.set_cookie(
            "session",
            "abc",
            secure=True,
        )
        return resp

    base_url = serve_app(app)
    target = detect_target(base_url)

    result = run_scan(
        target,
        profile=Profile.PASSIVE,
        detect_external=False,
    )

    findings = [
        f for f in result.findings
        if f.check == "web.cookie_flags"
    ]

    assert any("HttpOnly" in f.title for f in findings)
    assert all(f.severity == Severity.LOW for f in findings)


def test_cookie_flags_missing_both(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        resp = make_response("ok")
        resp.set_cookie("session", "abc")
        return resp

    base_url = serve_app(app)
    target = detect_target(base_url)

    result = run_scan(
        target,
        profile=Profile.PASSIVE,
        detect_external=False,
    )

    findings = [
        f for f in result.findings
        if f.check == "web.cookie_flags"
    ]

    assert any("HttpOnly" in f.title for f in findings)

    # HTTP targets should not be reported for missing Secure.
    assert not any("Secure" in f.title for f in findings)