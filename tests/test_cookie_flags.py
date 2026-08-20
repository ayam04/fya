from __future__ import annotations

from flask import Flask, make_response

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


def test_cookie_flags_missing_flags(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        response = make_response("ok")
        response.set_cookie("session", "abc")
        return response

    target_url = serve_app(app)
    target = detect_target(target_url)

    result = run_scan(
        target,
        profile=Profile.PASSIVE,
        detect_external=False,
    )

    findings = [
        f for f in result.findings
        if f.check == "web.cookie_flags"
    ]

    assert findings
    assert any("httponly" in f.title.lower() for f in findings)