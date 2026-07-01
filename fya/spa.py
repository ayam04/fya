from __future__ import annotations

from urllib.parse import urljoin, urlsplit


def is_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


def _same_host(candidate: str, host: str) -> bool:
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    return bool(parts.hostname) and parts.hostname == host


def render_and_extract(url, wait_ms: int = 1500, cap: int = 40) -> list:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return []

    host = urlsplit(url).hostname
    if not host:
        return []

    found: list = []
    seen: set = set()

    def _add(candidate) -> None:
        if not candidate:
            return
        absolute = urljoin(url, candidate.strip())
        absolute = absolute.split("#", 1)[0]
        if not _same_host(absolute, host):
            return
        if absolute in seen:
            return
        seen.add(absolute)
        found.append(absolute)

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_context().new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=max(wait_ms * 4, 8000))
                try:
                    page.wait_for_load_state("networkidle", timeout=wait_ms)
                except Exception:
                    page.wait_for_timeout(wait_ms)
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.getAttribute('href'))"
                )
                actions = page.eval_on_selector_all(
                    "form[action]", "els => els.map(e => e.getAttribute('action'))"
                )
            finally:
                browser.close()
    except Exception:
        return []

    for href in hrefs or []:
        if len(found) >= cap:
            break
        _add(href)

    for action in actions or []:
        if len(found) >= cap:
            break
        if not action:
            continue
        absolute = urljoin(url, action.strip())
        if "?" not in absolute:
            continue
        _add(action)

    return found[:cap]


if __name__ == "__main__":
    print(is_available())
