from __future__ import annotations

import threading
import time
import uuid
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_UA = "fya/0.1 (+https://github.com/ayam04/fya)"
_SLOW_RESPONSE = 2.5
_BACKOFF_STATUS = {429, 502, 503, 504}


class AdaptiveHTTP:
    def __init__(
        self,
        timeout: float = 12.0,
        verify: bool = False,
        user_agent: str = DEFAULT_UA,
        proxy: Optional[str] = None,
        base_interval: float = 0.05,
        max_interval: float = 3.0,
        allow_redirects: bool = True,
    ):
        self.timeout = timeout
        self.verify = verify
        self.allow_redirects = allow_redirects
        self._interval = base_interval
        self._base_interval = base_interval
        self._max_interval = max_interval
        self._next_allowed = 0.0
        self._lock = threading.Lock()
        self.request_count = 0

        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        retry = Retry(total=2, backoff_factor=0.4, status_forcelist=[], raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        if not verify:
            try:
                requests.packages.urllib3.disable_warnings()
            except Exception:
                pass

    def _throttle(self) -> None:
        with self._lock:
            wait = self._next_allowed - time.monotonic()
            start = max(time.monotonic(), self._next_allowed)
            self._next_allowed = start + self._interval
            self.request_count += 1
        if wait > 0:
            time.sleep(wait)

    def _adapt(self, elapsed: float, status: Optional[int], failed: bool) -> None:
        with self._lock:
            if failed or (status in _BACKOFF_STATUS) or elapsed > _SLOW_RESPONSE:
                self._interval = min(self._max_interval, max(self._interval * 1.8, 0.1))
            else:
                self._interval = max(self._base_interval, self._interval * 0.9)

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", self.allow_redirects)
        self._throttle()
        start = time.monotonic()
        status = None
        failed = False
        try:
            response = self.session.request(method, url, **kwargs)
            status = response.status_code
            return response
        except requests.RequestException:
            failed = True
            return None
        finally:
            self._adapt(time.monotonic() - start, status, failed)

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    @staticmethod
    def marker() -> str:
        return "fya" + uuid.uuid4().hex[:12]

    def close(self) -> None:
        self.session.close()
