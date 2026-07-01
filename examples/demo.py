from __future__ import annotations

import os
import threading
import zipfile

from rich.console import Console
from werkzeug.serving import make_server

from fya import report
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile
from vulnerable_app import create_app

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "..", "docs")
PORT = 5099


def _serve():
    server = make_server("127.0.0.1", PORT, create_app())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _capture(result, filename, title):
    console = Console(record=True, width=100)
    report.render_console(result, console)
    path = os.path.join(DOCS, filename)
    console.save_svg(path, title=title)
    return path


def _sample_apk():
    path = os.path.join(HERE, "_demo_sample.apk")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00PLACEHOLDER")
        archive.writestr(
            "assets/config.properties",
            "aws_key=AKIAIOSFODNN7EXAMPLE\napi_base=http://insecure.example/v1\n",
        )
        archive.writestr("res/raw/beacon.txt", "http://tracking.example/beacon")
    return path


def main():
    server = _serve()
    try:
        web = run_scan(
            detect_target(f"http://127.0.0.1:{PORT}"),
            profile=Profile.AGGRESSIVE,
            detect_external=False,
        )
    finally:
        server.shutdown()

    apk_path = _sample_apk()
    try:
        apk = run_scan(detect_target(apk_path), profile=Profile.SAFE, detect_external=False)
    finally:
        os.remove(apk_path)

    written = [
        _capture(web, "demo-web-scan.svg", f"fya scan http://127.0.0.1:{PORT} --profile aggressive"),
        _capture(apk, "demo-apk-scan.svg", "fya scan app-release.apk"),
    ]
    html_path = os.path.join(DOCS, "sample-report.html")
    report.write_report(web, "html", html_path)
    written.append(html_path)

    for path in written:
        print("wrote", os.path.relpath(path, os.path.join(HERE, "..")))


if __name__ == "__main__":
    main()
