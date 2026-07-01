from __future__ import annotations

import sqlite3

from flask import Flask, Response, make_response, redirect, request
from markupsafe import escape


def create_app() -> Flask:
    app = Flask(__name__)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    db.commit()

    csp = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )

    @app.after_request
    def harden(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = csp
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route("/")
    def index():
        links = (
            "<a href='/search?q=phone'>search</a>"
            "<a href='/user?id=1'>profile</a>"
            "<a href='/go?url=/'>home</a>"
            "<a href='/cors'>api</a>"
            "<a href='/greet?name=world'>greet</a>"
            "<a href='/transfer-form'>transfer</a>"
            "<a href='/link'>link</a>"
            "<a href='/setheader?lang=en'>setheader</a>"
        )
        resp = make_response(f"<html><title>Secure Shop</title><body>welcome {links}</body></html>")
        resp.set_cookie("session", "abc123", httponly=True, samesite="Lax")
        return resp

    @app.route("/search")
    def search():
        term = escape(request.args.get("q", ""))
        return f"<html><body>Results for {term}</body></html>"

    @app.route("/user")
    def user():
        raw = request.args.get("id", "1")
        try:
            uid = int(raw)
        except (TypeError, ValueError):
            return Response("invalid id", status=400)
        rows = db.execute("SELECT name FROM users WHERE id = ?", (uid,)).fetchall()
        return {"users": [r[0] for r in rows]}

    @app.route("/go")
    def go():
        dest = request.args.get("url", "/")
        if dest.startswith("/") and not dest.startswith("//") and "\\" not in dest and ":" not in dest.split("/", 1)[0]:
            return redirect(dest, code=302)
        return redirect("/", code=302)

    @app.route("/cors")
    def cors():
        resp = make_response({"ok": True})
        resp.headers["Access-Control-Allow-Origin"] = "https://shop.example"
        return resp

    @app.route("/greet")
    def greet():
        name = escape(request.args.get("name", ""))
        return f"<html><body>Hello {name}</body></html>"

    @app.route("/transfer-form")
    def transfer_form():
        html = (
            "<html><body>"
            "<form method='post' action='/transfer'>"
            "<input type='hidden' name='csrf_token' value='static-demo-token'>"
            "<input type='text' name='amount'>"
            "<input type='submit' value='Send'>"
            "</form>"
            "</body></html>"
        )
        return html

    @app.route("/transfer", methods=["POST"])
    def transfer():
        return "ok"

    @app.route("/link")
    def link():
        html = "<html><body><a href='/'>home</a></body></html>"
        return html

    @app.route("/setheader")
    def setheader():
        lang = request.args.get("lang", "en")
        if not lang.isalpha():
            lang = "en"
        resp = make_response("ok")
        resp.headers["Content-Language"] = lang
        return resp

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5002)
