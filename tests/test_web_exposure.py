from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, Response, jsonify

from fya.checks.web_exposure import BackupFiles
from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile, ScanContext, Target, TargetKind

# Scope every scan to this module's checks: a unit test for one check must not depend on
# the other ~90 checks crawling the same dev server (that made results load-dependent).
_CHECKS = {
    "api.actuator_exposure",
    "api.oidc_misconfig",
    "api.soap_wsdl_exposure",
    "web.backup_files",
    "web.debug_info_pages",
}


def _scan(base_url):
    target = detect_target(base_url)
    return run_scan(
        target, profile=Profile.AGGRESSIVE, detect_external=False, categories=_CHECKS
    )


def _names(result):
    return {finding.check for finding in result.findings}


def _index(app, body="<html><body><h1>app</h1></body></html>"):
    @app.route("/")
    def index():
        return Response(body, mimetype="text/html")

    return app


# ---------------------------------------------------------------------------
# api.actuator_exposure
# ---------------------------------------------------------------------------


def test_actuator_exposure_fires(serve_app):
    app = _index(Flask("actuator_vuln"))

    @app.route("/actuator/env")
    def env():
        return jsonify({
            "activeProfiles": ["prod"],
            "propertySources": [
                {"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "hunter2"}}}
            ],
        })

    @app.route("/actuator/heapdump")
    def heapdump():
        return Response(b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 4096,
                        mimetype="application/octet-stream")

    @app.route("/actuator/threaddump")
    def threaddump():
        return jsonify({"threads": [{"threadName": "main", "threadState": "RUNNABLE"}]})

    @app.route("/actuator/beans")
    def beans():
        return jsonify({"contexts": {"application": {"beans": {"dataSource": {}}}}})

    result = _scan(serve_app(app))
    assert "api.actuator_exposure" in _names(result)
    hits = [f for f in result.findings if f.check == "api.actuator_exposure"]
    locations = " ".join(f.location for f in hits)
    assert "/actuator/env" in locations
    assert "/actuator/heapdump" in locations
    assert not result.errors, result.errors


def test_actuator_exposure_silent_on_hardened_app(serve_app):
    app = _index(Flask("actuator_safe"))

    @app.route("/actuator/health")
    def health():
        return jsonify({"status": "UP"})

    @app.route("/actuator/env")
    def env():
        return Response('{"error": "Unauthorized"}', status=401, mimetype="application/json")

    @app.route("/actuator/beans")
    def beans():
        # 200, JSON, but no actuator-shaped keys.
        return jsonify({"status": "UP", "groups": []})

    @app.route("/actuator/heapdump")
    def heapdump():
        # 200 octet-stream but far too small to be a heap dump.
        return Response(b"not-a-dump", mimetype="application/octet-stream")

    @app.route("/env")
    def bare_env():
        return jsonify({"status": "ok"})

    result = _scan(serve_app(app))
    assert "api.actuator_exposure" not in _names(result)
    assert not result.errors, result.errors


def test_actuator_heapdump_fires_without_content_length(serve_app):
    app = _index(Flask("actuator_chunked"))

    @app.route("/actuator/heapdump")
    def heapdump():
        def stream():
            yield b"JAVA PROFILE 1.0.2\x00"
            yield b"\x00" * 65536

        # A streamed body is sent chunked, with no content-length header at all.
        return Response(stream(), mimetype="application/octet-stream")

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "api.actuator_exposure"]
    assert hits, sorted(_names(result))
    assert any("/actuator/heapdump" in f.location for f in hits)
    assert not result.errors, result.errors


def test_actuator_heapdump_ignores_generic_binary_download(serve_app):
    app = _index(Flask("actuator_binary"))

    body = b"%PDF-1.7\n" + b"A" * 8000

    @app.route("/heapdump")
    @app.route("/actuator/heapdump")
    def report():
        # A large octet-stream download that is not a JVM dump: content type and size
        # alone must never be reported as an exposed heap dump.
        return Response(body, mimetype="application/octet-stream")

    result = _scan(serve_app(app))
    assert "api.actuator_exposure" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.debug_info_pages
# ---------------------------------------------------------------------------

_PHPINFO_BODY = (
    "<html><head><title>phpinfo()</title></head><body>"
    "<h1>PHP Version 8.1.2</h1><table><tr><td>System </td><td>Linux web01</td></tr>"
    "<tr><td>Configuration</td><td>/etc/php/8.1/apache2/php.ini</td></tr></table></body></html>"
)

_STATUS_BODY = (
    "<html><head><title>Apache Status</title></head><body>"
    "<h1>Apache Server Status for web01</h1>"
    "<dl><dt>Server uptime: 4 days 2 hours</dt><dt>Total accesses: 91231</dt></dl>"
    "</body></html>"
)

_CONSOLE_BODY = (
    "<html><head><title>Console // Werkzeug Debugger</title></head><body>"
    "<div class=\"console-mode\"><p>The Werkzeug debugger interactive console.</p>"
    "<script>var CONSOLE_MODE = true, EVALEX = true;</script>"
    "<form action=\"?__debugger__=yes&cmd=pinauth\"></form></div></body></html>"
)


def test_debug_info_pages_fires(serve_app):
    app = _index(Flask("debug_vuln"))

    @app.route("/phpinfo.php")
    def phpinfo():
        return Response(_PHPINFO_BODY, mimetype="text/html")

    @app.route("/server-status")
    def server_status():
        return Response(_STATUS_BODY, mimetype="text/html")

    @app.route("/console")
    def console():
        return Response(_CONSOLE_BODY, mimetype="text/html")

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "web.debug_info_pages"]
    assert hits, sorted(_names(result))
    locations = " ".join(f.location for f in hits)
    assert "/phpinfo.php" in locations
    assert "/console" in locations
    assert "/server-status" in locations
    assert not result.errors, result.errors


def test_debug_info_pages_silent_on_safe_app(serve_app):
    app = _index(Flask("debug_safe"))

    @app.route("/phpinfo.php")
    def phpinfo():
        # 200 but no phpinfo table: a near-miss placeholder page.
        return Response("<html><body>PHP Version info is disabled.</body></html>",
                        mimetype="text/html")

    @app.route("/server-status")
    def server_status():
        return Response("<html><body>status: ok</body></html>", mimetype="text/html")

    @app.route("/server-info")
    def server_info():
        return Response("<html><body>Server Settings are private.</body></html>",
                        mimetype="text/html")

    @app.route("/console")
    def console():
        return Response("<html><body><form>admin console login</form></body></html>",
                        mimetype="text/html")

    result = _scan(serve_app(app))
    assert "web.debug_info_pages" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.backup_files
# ---------------------------------------------------------------------------


def test_backup_files_fires(serve_app):
    app = _index(Flask("backup_vuln"), "<html><body><a href=\"/config.php\">config</a></body></html>")

    @app.route("/config.php")
    def config_live():
        return Response("<html><body>configured</body></html>", mimetype="text/html")

    @app.route("/config.php.bak")
    def config_backup():
        return Response(
            "<?php\n$DB_PASSWORD = 'hunter2';\n$api_key = 'AKIA0000';\n",
            mimetype="text/plain",
        )

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "web.backup_files"]
    assert hits, sorted(_names(result))
    assert any("/config.php.bak" in f.location for f in hits)
    assert not result.errors, result.errors


def test_backup_files_silent_when_backup_matches_live_file(serve_app):
    app = _index(Flask("backup_safe"))

    source = "import os\n\ndef handler(event):\n    return os.environ.get('MODE')\n"

    @app.route("/app.py")
    def live():
        return Response(source, mimetype="text/plain")

    @app.route("/app.py.bak")
    def same_as_live():
        # Identical to the live file: the baseline diff must suppress this.
        return Response(source, mimetype="text/plain")

    @app.route("/settings.py.bak")
    def html_rewrite():
        # A catch-all style HTML page: rejected on content type and leading '<'.
        return Response("<html><body>not found</body></html>", mimetype="text/html")

    result = _scan(serve_app(app))
    assert "web.backup_files" not in _names(result)
    assert not result.errors, result.errors


def test_backup_files_fires_on_python_source(serve_app):
    app = _index(Flask("backup_python"))

    @app.route("/settings.py")
    def live():
        return Response("<html><body>settings</body></html>", mimetype="text/html")

    @app.route("/settings.py.bak")
    def backup():
        return Response(
            "import os\n\n\ndef load():\n    return os.environ['MODE']\n",
            mimetype="text/plain",
        )

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "web.backup_files"]
    assert hits, sorted(_names(result))
    assert any("/settings.py.bak" in f.location for f in hits)
    assert not result.errors, result.errors


def test_backup_files_silent_on_prose_mentioning_source_keywords(serve_app):
    app = _index(Flask("backup_prose"))

    @app.route("/config.php")
    def live():
        return Response("<html><body>configured</body></html>", mimetype="text/html")

    @app.route("/config.php.bak")
    def notes():
        # Plain text that trips the old bare substring markers ("import ", "def ",
        # "SECRET", "api_key") without being source code at all.
        return Response(
            "Release notes for the config UI.\n"
            "Please import the SECRET rotation policy before Friday.\n"
            "def not merge this by hand; the api_key rotation is automated.\n",
            mimetype="text/plain",
        )

    result = _scan(serve_app(app))
    assert "web.backup_files" not in _names(result)
    assert not result.errors, result.errors


# The live-file differential is what makes this a HIGH finding, and it is the first thing
# lost when ctx.http.get returns None (exhausted --max-requests budget, transient network
# error). These two use a stub transport because that failure cannot be produced by a
# server: any real response, including a 404, is a usable baseline.
_PHP_BACKUP = b"<?php\n$DB_PASSWORD = 'hunter2';\n"


class _StubResponse:
    def __init__(self, body, ctype="text/plain", status=200):
        self.content = body
        self.text = body.decode("utf-8", "replace")
        self.status_code = status
        self.headers = {"content-type": ctype}


class _StubHTTP:
    """Serves a fixed path map; every other URL fails the way an exhausted budget does."""

    def __init__(self, bodies):
        self.bodies = bodies

    def marker(self):
        return "fya0000test"

    def get(self, url, **kwargs):
        entry = self.bodies.get(urlsplit(url).path)
        return None if entry is None else _StubResponse(*entry)


def _stub_ctx(bodies):
    target = Target(
        raw="http://127.0.0.1:1/",
        kind=TargetKind.WEB,
        scheme="http",
        host="127.0.0.1",
        port=1,
        url="http://127.0.0.1:1/",
    )
    return ScanContext(target=target, profile=Profile.SAFE, http=_StubHTTP(bodies))


def test_backup_files_silent_when_live_baseline_is_unavailable():
    ctx = _stub_ctx({"/config.php.bak": (_PHP_BACKUP,)})
    assert list(BackupFiles().run(ctx)) == []


def test_backup_files_fires_when_live_baseline_differs():
    ctx = _stub_ctx({
        "/config.php.bak": (_PHP_BACKUP,),
        "/config.php": (b"<html><body>configured</body></html>", "text/html"),
    })
    findings = list(BackupFiles().run(ctx))
    assert [f.location for f in findings] == ["http://127.0.0.1:1/config.php.bak"]


# ---------------------------------------------------------------------------
# api.oidc_misconfig
# ---------------------------------------------------------------------------


def test_oidc_misconfig_fires(serve_app):
    app = _index(Flask("oidc_vuln"))

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "issuer": "http://idp.internal/",
            "authorization_endpoint": "http://idp.internal/authorize",
            "token_endpoint": "http://idp.internal/token",
            "jwks_uri": "http://idp.internal/jwks.json",
            "response_types_supported": ["code", "token", "id_token token"],
            "id_token_signing_alg_values_supported": ["none", "HS256"],
            "grant_types_supported": ["authorization_code", "password"],
        })

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "api.oidc_misconfig"]
    assert hits, sorted(_names(result))
    titles = " ".join(f.title for f in hits)
    assert "cleartext" in titles
    assert "none" in titles
    assert not result.errors, result.errors


def test_oidc_misconfig_silent_on_hardened_provider(serve_app):
    app = _index(Flask("oidc_safe"))

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "issuer": "https://idp.example.test/",
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks.json",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        })

    result = _scan(serve_app(app))
    assert "api.oidc_misconfig" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# api.soap_wsdl_exposure
# ---------------------------------------------------------------------------

_WSDL_BODY = (
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<wsdl:definitions xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\" "
    "xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\" targetNamespace=\"urn:billing\">"
    "<wsdl:message name=\"GetInvoiceRequest\"/>"
    "<wsdl:portType name=\"BillingPort\">"
    "<wsdl:operation name=\"GetInvoice\"/></wsdl:portType>"
    "<wsdl:service name=\"BillingService\"/></wsdl:definitions>"
)


def test_soap_wsdl_exposure_fires(serve_app):
    app = _index(Flask("wsdl_vuln"))

    @app.route("/services")
    def services():
        return Response(_WSDL_BODY, mimetype="text/xml")

    result = _scan(serve_app(app))
    hits = [f for f in result.findings if f.check == "api.soap_wsdl_exposure"]
    assert hits, sorted(_names(result))
    assert any("/services?wsdl" in f.location for f in hits)
    assert not result.errors, result.errors


def test_soap_wsdl_exposure_silent_without_a_contract(serve_app):
    app = _index(Flask("wsdl_safe"))

    @app.route("/services")
    def services():
        return Response("<html><body>Service catalogue</body></html>", mimetype="text/html")

    @app.route("/soap")
    def soap():
        return jsonify({"status": "ok"})

    @app.route("/ws")
    def ws():
        return Response("<html><body>websocket endpoint</body></html>", mimetype="text/html")

    result = _scan(serve_app(app))
    assert "api.soap_wsdl_exposure" not in _names(result)
    assert not result.errors, result.errors
