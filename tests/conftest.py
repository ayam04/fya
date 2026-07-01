from __future__ import annotations

import os
import sys
import threading
import zipfile

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.vulnerable_app import create_app


class _ServerThread(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


@pytest.fixture
def live_server():
    app = create_app()
    thread = _ServerThread(app)
    thread.start()
    base_url = f"http://127.0.0.1:{thread.port}"
    try:
        yield base_url
    finally:
        thread.stop()
        thread.join(timeout=5)


@pytest.fixture
def fake_apk(tmp_path):
    apk_path = tmp_path / "sample.apk"
    payload = (
        b"config: aws_key=AKIAIOSFODNN7EXAMPLE\n"
        b"endpoint: http://insecure.example/api/v1\n"
    )
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        zf.writestr("assets/config.properties", payload)
    return str(apk_path)
