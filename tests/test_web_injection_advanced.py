from __future__ import annotations

import base64
import re

from flask import Flask, Response, jsonify, request

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile

# Scope every scan to this module's checks: a unit test for one check must not depend on
# the other ~90 checks crawling the same dev server (that made results load-dependent).
_CHECKS = {
    "web.blind_sql_injection",
    "web.command_injection",
    "web.json_nosql_operators",
    "web.lfi_wrappers",
    "web.xxe_injection",
}


def _scan(base):
    target = detect_target(base)
    return run_scan(
        target, profile=Profile.AGGRESSIVE, detect_external=False, categories=_CHECKS
    )


def _names(result):
    return {f.check for f in result.findings}


# ---------------------------------------------------------------------------
# web.command_injection
# ---------------------------------------------------------------------------

_MULT_RE = re.compile(r"(\d+)\s*\\?\*\s*(\d+)")


def test_command_injection_fires(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response('<a href="/run?cmd=1">run</a>')

    @app.route("/run")
    def run():
        # Simulate a shell: echo only the argument before the first metacharacter,
        # then evaluate an injected arithmetic expression WITHOUT reflecting the payload.
        cmd = request.args.get("cmd", "")
        prefix = re.split(r"[;|&`$]", cmd, maxsplit=1)[0]
        out = "output for " + prefix
        m = _MULT_RE.search(cmd)
        if m:
            out += "\n" + str(int(m.group(1)) * int(m.group(2)))
        return Response(out, mimetype="text/plain")

    result = _scan(serve_app(app))
    assert "web.command_injection" in _names(result)
    assert not result.errors, result.errors


def test_command_injection_silent_on_reflection(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response('<a href="/echo?cmd=1">echo</a>')

    @app.route("/echo")
    def echo():
        # Safe: reflects the raw value, never executes it.
        return Response("you sent: " + request.args.get("cmd", ""), mimetype="text/plain")

    result = _scan(serve_app(app))
    assert "web.command_injection" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.blind_sql_injection
# ---------------------------------------------------------------------------

_BOOL_RE = re.compile(r"AND\s+'?\"?(\d+)\"?'?\s*=\s*'?\"?(\d+)\"?'?", re.IGNORECASE)


def test_blind_sql_injection_fires(serve_app):
    app = Flask(__name__)
    rows = "".join(f"<li>item {i}</li>" for i in range(60))

    @app.route("/")
    def index():
        return Response('<a href="/items?id=1">items</a>')

    @app.route("/items")
    def items():
        # Generic page, no DB error text. Boolean tautology decides the result set.
        value = request.args.get("id", "")
        truthy = True
        m = _BOOL_RE.search(value)
        if m:
            truthy = m.group(1) == m.group(2)
        if truthy:
            return Response(f"<html><body><ul>{rows}</ul></body></html>")
        return Response("<html><body>no results</body></html>")

    result = _scan(serve_app(app))
    assert "web.blind_sql_injection" in _names(result)
    assert not result.errors, result.errors


def test_blind_sql_injection_silent_on_constant(serve_app):
    app = Flask(__name__)
    body = "<html><body>" + ("x" * 800) + "</body></html>"

    @app.route("/")
    def index():
        return Response('<a href="/items?id=1">items</a>')

    @app.route("/items")
    def items():
        # Constant response regardless of input: no boolean differential.
        return Response(body)

    result = _scan(serve_app(app))
    assert "web.blind_sql_injection" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.xxe_injection
# ---------------------------------------------------------------------------

_ENTITY_RE = re.compile(r'<!ENTITY e (?:"([^"]*)"|SYSTEM "([^"]*)")>')
_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"
_WININI = "[fonts]\nfor 8514/a systems=vga850.fon\n"


def test_xxe_injection_fires(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response("<html>home</html>")

    @app.route("/api", methods=["POST", "GET"])
    def api():
        # Simulate an XML parser that resolves entities including external SYSTEM ones.
        body = request.get_data(as_text=True) or ""
        m = _ENTITY_RE.search(body)
        value = ""
        if m:
            if m.group(1) is not None:
                value = m.group(1)
            else:
                uri = m.group(2) or ""
                if uri.endswith("/etc/passwd"):
                    value = _PASSWD
                elif uri.endswith("win.ini"):
                    value = _WININI
        return Response(f"<r>{value}</r>", mimetype="application/xml")

    result = _scan(serve_app(app))
    assert "web.xxe_injection" in _names(result)
    assert not result.errors, result.errors


def test_xxe_injection_silent_when_external_blocked(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response("<html>home</html>")

    @app.route("/api", methods=["POST", "GET"])
    def api():
        # Secure parser: expands internal entities but refuses external SYSTEM ones.
        body = request.get_data(as_text=True) or ""
        m = _ENTITY_RE.search(body)
        value = m.group(1) if (m and m.group(1) is not None) else ""
        return Response(f"<r>{value}</r>", mimetype="application/xml")

    result = _scan(serve_app(app))
    assert "web.xxe_injection" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.lfi_wrappers
# ---------------------------------------------------------------------------

_PHP_SOURCE = "<?php $db = 'secret'; echo 'hello world from the include target'; ?>\n"


def test_lfi_wrappers_fires(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response('<a href="/view?file=index.php">view</a>')

    @app.route("/view")
    def view():
        f = request.args.get("file", "")
        if f.startswith("php://filter") and "base64-encode" in f:
            return Response(base64.b64encode(_PHP_SOURCE.encode()).decode(), mimetype="text/plain")
        return Response("page: " + f, mimetype="text/plain")

    result = _scan(serve_app(app))
    assert "web.lfi_wrappers" in _names(result)
    assert not result.errors, result.errors


def test_lfi_wrappers_silent_on_reflection(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response('<a href="/view?file=index.php">view</a>')

    @app.route("/view")
    def view():
        # Reflects the raw value; wrappers are never interpreted.
        return Response("page: " + request.args.get("file", ""), mimetype="text/plain")

    result = _scan(serve_app(app))
    assert "web.lfi_wrappers" not in _names(result)
    assert not result.errors, result.errors


# ---------------------------------------------------------------------------
# web.json_nosql_operators
# ---------------------------------------------------------------------------


def test_json_nosql_operators_fires(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            '<form action="/login" method="post">'
            '<input name="username"><input name="password"></form>'
        )

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        user = data.get("username")
        if isinstance(user, dict):
            # Operator injection reaches the query as an operator -> auth bypass.
            return jsonify({"token": "abcdef", "ok": True}), 200
        return jsonify({"error": "invalid credentials"}), 401

    result = _scan(serve_app(app))
    assert "web.json_nosql_operators" in _names(result)
    assert not result.errors, result.errors


def test_json_nosql_operators_silent_when_typed(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            '<form action="/login" method="post">'
            '<input name="username"><input name="password"></form>'
        )

    @app.route("/login", methods=["POST"])
    def login():
        # Rejects everything the same way regardless of operator vs scalar.
        return jsonify({"error": "invalid credentials"}), 401

    result = _scan(serve_app(app))
    assert "web.json_nosql_operators" not in _names(result)
    assert not result.errors, result.errors


def test_json_nosql_operators_silent_on_type_validation(serve_app):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return Response(
            '<form action="/login" method="post">'
            '<input name="username"><input name="password"></form>'
        )

    @app.route("/login", methods=["POST"])
    def login():
        # Pydantic/FastAPI shape: the operator object fails type validation BEFORE the
        # handler, so it gets a different status (422) than the scalar baseline (401).
        # Rejecting the operator is the secure behaviour and must never be reported.
        data = request.get_json(silent=True) or {}
        if not isinstance(data.get("username"), str):
            return jsonify({"detail": [{"msg": "Input should be a valid string"}]}), 422
        return jsonify({"error": "invalid credentials"}), 401

    result = _scan(serve_app(app))
    assert "web.json_nosql_operators" not in _names(result)
    assert not result.errors, result.errors


def test_json_nosql_operators_fires_on_result_set_change(serve_app):
    app = Flask(__name__)
    rows = [{"id": i, "name": f"document number {i}"} for i in range(40)]

    @app.route("/")
    def index():
        return Response('<form action="/search" method="post"><input name="q"></form>')

    @app.route("/search", methods=["POST"])
    def search():
        # No auth flip: the status stays 200 and only the result set grows, which is what
        # an operator injection into a filter looks like on a plain query endpoint.
        data = request.get_json(silent=True) or {}
        q = data.get("q")
        if isinstance(q, dict):
            return jsonify({"results": rows}), 200
        return jsonify({"results": []}), 200

    result = _scan(serve_app(app))
    findings = [f for f in result.findings if f.check == "web.json_nosql_operators"]
    assert findings, _names(result)
    assert not result.errors, result.errors
