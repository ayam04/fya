from __future__ import annotations

import sqlite3

from flask import Flask, Response, make_response, redirect, request


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

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001)
