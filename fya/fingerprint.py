from __future__ import annotations

import re

from .models import ScanContext

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_SIGNATURES = [
    ("header", "x-powered-by", "express", "Express"),
    ("header", "x-powered-by", "php", "PHP"),
    ("header", "x-powered-by", "asp.net", "ASP.NET"),
    ("header", "x-aspnet-version", "", "ASP.NET"),
    ("header", "server", "nginx", "nginx"),
    ("header", "server", "apache", "Apache"),
    ("header", "server", "gunicorn", "Gunicorn"),
    ("header", "server", "werkzeug", "Flask/Werkzeug"),
    ("header", "server", "cloudflare", "Cloudflare"),
    ("header", "server", "kestrel", "ASP.NET Kestrel"),
    ("cookie", "sessionid", "", "Django"),
    ("cookie", "csrftoken", "", "Django"),
    ("cookie", "laravel_session", "", "Laravel"),
    ("cookie", "connect.sid", "", "Express"),
    ("cookie", "jsessionid", "", "Java servlet"),
    ("cookie", "phpsessid", "", "PHP"),
    ("body", "", "wp-content", "WordPress"),
    ("body", "", "__next", "Next.js"),
    ("body", "", "ng-version", "Angular"),
    ("body", "", "data-reactroot", "React"),
]


def fingerprint_web(ctx: ScanContext) -> dict:
    base = ctx.target.base_url()
    info: dict = {"technologies": [], "is_api": False}
    if not base:
        return info
    response = ctx.http.get(base)
    if response is None:
        info["reachable"] = False
        return info

    info["reachable"] = True
    info["status"] = response.status_code
    info["final_url"] = response.url
    headers = {k.lower(): v for k, v in response.headers.items()}
    info["server"] = headers.get("server", "")
    info["powered_by"] = headers.get("x-powered-by", "")
    content_type = headers.get("content-type", "")
    info["content_type"] = content_type

    body = response.text[:200000] if response.text else ""
    match = _TITLE.search(body)
    info["title"] = match.group(1).strip()[:200] if match else ""

    cookies = {c.name.lower(): c for c in response.cookies}
    info["cookies"] = sorted(cookies.keys())

    techs = set()
    for kind, name, needle, label in _SIGNATURES:
        if kind == "header":
            value = headers.get(name, "").lower()
            if value and (not needle or needle in value):
                techs.add(label)
        elif kind == "cookie":
            if name in cookies:
                techs.add(label)
        elif kind == "body":
            if needle and needle.lower() in body.lower():
                techs.add(label)
    info["technologies"] = sorted(techs)

    is_json = "application/json" in content_type or "application/xml" in content_type
    looks_api = bool(re.search(r"/(api|v\d+|graphql)(/|$)", ctx.target.url or ""))
    info["is_api"] = is_json or looks_api
    info["waf"] = _waf_hint(headers)
    return info


def _waf_hint(headers: dict) -> str:
    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers:
        return "Cloudflare"
    if "akamai" in server or "akamaighost" in server:
        return "Akamai"
    if headers.get("x-sucuri-id"):
        return "Sucuri"
    return ""
