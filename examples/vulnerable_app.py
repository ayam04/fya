from __future__ import annotations

import re
import sqlite3

from flask import Flask, Response, abort, make_response, redirect, render_template_string, request


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
            "<a href='/cors-strict'>cors2</a>"
            "<a href='/reflect-host'>host</a>"
            "<a href='/greet?name=world'>greet</a>"
            "<a href='/transfer-form'>transfer</a>"
            "<a href='/link'>link</a>"
            "<a href='/setheader?lang=en'>setheader</a>"
            "<a href='/account?id=1'>account</a>"
            "<a href='/admin'>admin</a>"
            "<a href='/fetch?url=http://example.com/logo.png'>fetch</a>"
            "<a href='/items?category=food'>items</a>"
            "<a href='/xpath?q=1'>xpath</a>"
            "<a href='/ldap?u=admin'>ldap</a>"
            "<a href='/ssi?tpl=hi'>ssi</a>"
        )
        resp = make_response(
            f"<html><title>Vulnerable Shop</title><body>welcome {links}"
            "<script src='/static/app.js'></script></body></html>"
        )
        resp.set_cookie("session", "abc123")
        resp.set_cookie("__Host-demo", "1", path="/")
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

    @app.route("/account")
    def account():
        accounts = {1: "alice: checking balance 100.00 usd", 2: "bob: checking balance 250.00 usd"}
        try:
            aid = int(request.args.get("id", "1"))
        except ValueError:
            return Response("bad request", status=400)
        if aid not in accounts:
            return Response("account not found", status=404)
        return Response(accounts[aid])

    @app.route("/admin")
    def admin():
        body = "<h1>Admin Panel</h1>" + "<div>user management console entry</div>" * 20
        return Response(f"<html><body>{body}</body></html>")

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
            try:
                lang.encode("latin-1")
                resp.headers["Content-Language"] = lang
            except UnicodeEncodeError:
                resp.headers["Content-Language"] = "en"
        return resp

    @app.before_request
    def _honor_override():
        override = request.headers.get("X-Original-URL") or request.headers.get("X-Rewrite-URL")
        if override is not None and override.rstrip("/") not in ("",):
            abort(404)

    @app.route("/static/app.js")
    def app_js():
        js = (
            "var AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
            "var config = { region: 'us-east-1' };\n"
            "//# sourceMappingURL=app.js.map\n"
        )
        return Response(js, mimetype="application/javascript")

    @app.route("/static/app.js.map")
    def app_js_map():
        return Response(
            '{"version":3,"sources":["src/index.js"],"sourcesContent":["const secret = 1;"],"mappings":"AAAA"}',
            mimetype="application/json",
        )

    @app.route("/.git/HEAD")
    def git_head():
        return Response("ref: refs/heads/main\n", mimetype="text/plain")

    @app.route("/.git/config")
    def git_config():
        return Response("[core]\n\trepositoryformatversion = 0\n\tbare = false\n", mimetype="text/plain")

    @app.route("/.env.production")
    def env_prod():
        return Response("DB_PASSWORD=hunter2\nAPI_KEY=sk_test_abcdef1234567890\n", mimetype="text/plain")

    @app.route("/uploads/")
    def uploads():
        return Response(
            "<html><head><title>Index of /uploads</title></head><body>"
            "<h1>Index of /uploads</h1><pre><a href=\"../\">../</a>\n"
            "<a href=\"backup.sql\">backup.sql</a>\n</pre></body></html>"
        )

    @app.route("/fetch")
    def fetch():
        url = request.args.get("url", "")
        if "169.254.169.254" in url and "instance-identity" in url:
            return Response(
                '{"accountId":"123456789012","instanceId":"i-0abc123","region":"us-east-1","imageId":"ami-1"}',
                mimetype="application/json",
            )
        if url.startswith("file://"):
            if "passwd" in url:
                return Response("root:x:0:0:root:/root:/bin/bash\n", mimetype="text/plain")
            if "win.ini" in url:
                return Response("[fonts]\n", mimetype="text/plain")
        return Response("fetched: ok")

    @app.route("/items")
    def items():
        if any("[$" in key for key in request.args.keys()):
            return Response("<html><body>" + "<div>item</div>" * 60 + "</body></html>")
        category = request.args.get("category", "")
        return Response(f"<html><body><div>results for {category}</div></body></html>")

    @app.route("/xpath")
    def xpath():
        q = request.args.get("q", "")
        if "'" in q or '"' in q:
            return Response("javax.xml.xpath.XPathExpressionException: invalid xpath expression", status=500)
        return Response(f"<html><body>results for {q}</body></html>")

    @app.route("/ldap")
    def ldap():
        u = request.args.get("u", "")
        if "(" in u or ")" in u:
            return Response("javax.naming.NamingException: bad search filter near ')(cn=*)'", status=500)
        return Response(f"<html><body>user {u}</body></html>")

    @app.route("/ssi")
    def ssi():
        tpl = request.args.get("tpl", "")
        rendered = re.sub(r"<!--#echo[^>]*-->", "Wednesday, 02-Jul-2026 00:00:00 GMT", tpl)
        return Response(f"<html><body>{rendered}</body></html>")

    @app.route("/cors-strict")
    def cors_strict():
        origin = request.headers.get("Origin", "")
        resp = make_response(Response('{"ok":true}', mimetype="application/json"))
        host = request.host.split(":")[0]
        if origin and origin.endswith(host):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/reflect-host")
    def reflect_host():
        host = request.headers.get("X-Forwarded-Host") or request.host
        return Response(f'<html><body><a href="http://{host}/next">next</a></body></html>')

    @app.route("/graphql", methods=["GET", "POST"])
    def graphql():
        if request.method == "GET":
            if "__typename" in request.args.get("query", ""):
                return Response('{"data":{"__typename":"Query"}}', mimetype="application/json")
            return Response("{}", mimetype="application/json")
        data = request.get_json(silent=True)
        if isinstance(data, list):
            return Response(
                '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]',
                mimetype="application/json",
            )
        query = data.get("query", "") if isinstance(data, dict) else ""
        if "__typenam" in query and "__typename" not in query:
            return Response(
                '{"errors":[{"message":"Cannot query field \\"__typenam\\". Did you mean \\"__typename\\"?"}]}',
                mimetype="application/json",
            )
        if "__typename" in query:
            return Response('{"data":{"__typename":"Query"}}', mimetype="application/json")
        return Response('{"data":null}', mimetype="application/json")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001)
