from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)

URL_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect", "redirect_uri",
    "return", "returnurl", "returnto", "continue", "next", "target", "to", "out", "goto", "rurl",
    "image", "image_url", "img", "imageurl", "fetch", "proxy", "callback", "webhook", "feed", "rss",
    "load", "domain", "host", "site", "page", "file", "reference", "open", "view", "path",
}


def is_catch_all(ctx) -> bool:
    """True when the server returns 200 for a random nonexistent path (SPA/catch-all rewrite)."""
    base = ctx.target.base_url()
    if not base:
        return False
    token = ctx.http.marker()
    probe = ctx.http.get(base.rstrip("/") + "/" + token + "-nope")
    return probe is not None and probe.status_code == 200


def looks_like_url(value: str) -> bool:
    v = (value or "").strip().lower()
    return v.startswith(("http://", "https://", "//")) or "://" in v


def is_url_param(name: str, value: str) -> bool:
    return (name or "").lower() in URL_PARAM_NAMES or looks_like_url(value)


def same_origin_scripts(ctx, cap: int = 40, max_bytes: int = 2_000_000):
    """Return [(url, body)] for inline and same-origin linked scripts on the seed pages."""
    base = ctx.target.base_url()
    if not base:
        return []
    host = ctx.target.host
    seeds = []
    for candidate in (base, ctx.target.url):
        if candidate and candidate not in seeds:
            seeds.append(candidate)

    scripts = []
    seen_src = set()
    for seed in seeds:
        resp = ctx.http.get(seed)
        if resp is None:
            continue
        body = resp.text or ""
        for inline in _INLINE_SCRIPT.findall(body):
            if inline.strip():
                scripts.append((seed, inline))
        for raw in _SCRIPT_SRC.findall(body):
            src = raw.strip("\"'")
            if not src:
                continue
            absolute = urljoin(seed, src).split("#", 1)[0]
            if not absolute.startswith(("http://", "https://")):
                continue
            if urlsplit(absolute).hostname != host:
                continue
            if absolute in seen_src:
                continue
            seen_src.add(absolute)
            if len(seen_src) > cap:
                break
            jr = ctx.http.get(absolute)
            if jr is None:
                continue
            text = jr.text or ""
            scripts.append((absolute, text[:max_bytes]))
        if len(scripts) >= cap:
            break
    return scripts[:cap]
