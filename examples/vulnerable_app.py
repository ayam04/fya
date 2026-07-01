from __future__ import annotations

import sqlite3

from flask import Flask, Response, make_response, redirect, render_template_string, request


def create_app() -> Flask:
    app = Flask(__name__)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    db.commit()

    @app.after_request
    def strip_security(resp: Response) -> Response:
        resp.headers.pop("X-Frame-Options", None)
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
        resp = make_response(f"<html><title>Vulnerable Shop</title><body>welcome {links}</body></html>")
        resp.set_cookie("session", "abc123")
        return resp

    @app.route("/search")
    def search():
        term = request.args.get("q", "")
        return f"<html><body>Results for {term}</body></html>"

    @app.route("/user")
    def user():
        uid = request.args.get("id", "1")
        try:
            rows = db.execute(f"SELECT name FROM users WHERE id = {uid}").fetchall()
            return {"users": [r[0] for r in rows]}
        except sqlite3.Error as exc:
            return Response(f"SQL error: {exc}", status=500)

    @app.route("/go")
    def go():
        return redirect(request.args.get("url", "/"), code=302)

    @app.route("/cors")
    def cors():
        origin = request.headers.get("Origin", "*")
        resp = make_response({"ok": True})
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/.env")
    def dotenv():
        return Response("SECRET_KEY=super-secret\nDB_PASSWORD=hunter2\n", mimetype="text/plain")

    @app.route("/greet")
    def greet():
        name = request.args.get("name", "")
        return render_template_string(f"Hello {name}")

    @app.route("/transfer-form")
    def transfer_form():
        html = (
            "<html><body>"
            "<form method='post' action='/transfer'>"
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
        host = request.host
        html = f"<html><body><a href='http://{host}/'>home</a></body></html>"
        return html

    @app.route("/setheader")
    def setheader():
        lang = request.args.get("lang", "en")
        resp = make_response("ok")
        if "\r\n" in lang or "\n" in lang:
            sep = "\r\n" if "\r\n" in lang else "\n"
            parts = lang.split(sep, 1)
            base_val = parts[0]
            if len(parts) > 1 and ":" in parts[1]:
                extra_name, extra_val = parts[1].split(":", 1)
                try:
                    resp.headers[extra_name.strip()] = extra_val.strip()
                except Exception:
                    pass
            try:
                resp.headers["Content-Language"] = base_val or "en"
            except Exception:
                resp.headers["Content-Language"] = "en"
        else:
            resp.headers["Content-Language"] = lang
        return resp

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001)
