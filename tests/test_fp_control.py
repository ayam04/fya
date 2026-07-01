from __future__ import annotations

import os
import sys
import threading

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.secure_app import create_app
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile


class _SecureServerThread(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


@pytest.fixture
def secure_server():
    app = create_app()
    thread = _SecureServerThread(app)
    thread.start()
    base_url = f"http://127.0.0.1:{thread.port}"
    try:
        yield base_url
    finally:
        thread.stop()
        thread.join(timeout=5)


_ACTIVE_CHECKS = {
    "web.reflected_xss",
    "web.sql_injection",
    "web.ssti",
    "web.crlf",
    "web.host_header",
    "web.open_redirect",
    "web.cors_misconfig",
    "web.csrf",
}


def test_secure_app_no_active_findings(secure_server):
    target = detect_target(secure_server)
    result = run_scan(target, profile=Profile.AGGRESSIVE, detect_external=False)

    fired = sorted({f.check for f in result.findings if f.check in _ACTIVE_CHECKS})
    offending = [
        f"{f.check}: {f.title} @ {f.location}"
        for f in result.findings
        if f.check in _ACTIVE_CHECKS
    ]

    assert not fired, "active checks fired on hardened app: " + " | ".join(offending)
