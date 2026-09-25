"""Shared HTTPS helpers for outbound intel adapters.

Python on Windows frequently ships without a usable CA file
(``ssl.get_default_verify_paths()`` returns ``cafile=None``), which makes
verification fall back to whatever the platform store happens to hold. Against
services.nvd.nist.gov that surfaces as ``CERTIFICATE_VERIFY_FAILED:
certificate has expired`` even though the server certificate is perfectly
valid — curl, carrying its own bundle, reaches the same host fine.

The fix is to carry a current CA bundle (certifi) when one is available.
Verification is never disabled: a security tool that turns off certificate
checking to make a request succeed has traded a real control for a convenience.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

USER_AGENT = "security-studio/2.0 (+https://github.com/gocar112/Security-Studio)"

_ctx_lock = threading.Lock()
_ctx: ssl.SSLContext | None = None
_ctx_source = "unknown"


def ssl_context() -> ssl.SSLContext:
    """A verified TLS context, preferring certifi's bundle when installed."""
    global _ctx, _ctx_source
    with _ctx_lock:
        if _ctx is not None:
            return _ctx
        try:
            import certifi  # type: ignore

            _ctx = ssl.create_default_context(cafile=certifi.where())
            _ctx_source = "certifi"
        except Exception:
            _ctx = ssl.create_default_context()
            _ctx_source = "system"
        return _ctx


def ssl_source() -> str:
    ssl_context()
    return _ctx_source


class RateLimiter:
    """Simple minimum-interval limiter, safe to share across threads."""

    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> float:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._last + self.min_interval - now)
            if delay > 0:
                time.sleep(delay)
            self._last = time.monotonic()
            return delay


class HttpError(Exception):
    def __init__(self, status: int, detail: str = ""):
        super().__init__("HTTP " + str(status) + (": " + detail if detail else ""))
        self.status = status
        self.detail = detail


def _require_https(url: str) -> None:
    """Reject local files, cleartext HTTP, and malformed outbound targets."""
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("outbound URL must be an absolute HTTPS URL")


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep a trusted HTTPS request from being redirected to another scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_HTTPS_OPENER = urllib.request.build_opener(
    _HttpsOnlyRedirectHandler(), urllib.request.HTTPSHandler(context=ssl_context())
)


def get_json(url: str, headers: dict | None = None, timeout: float = 30.0) -> dict:
    """GET a URL and parse JSON. Raises HttpError with the status on failure."""
    _require_https(url)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})},
    )
    try:
        # HTTPS and redirect schemes are enforced before the opener is used.
        with _HTTPS_OPENER.open(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except OSError:
            pass
        raise HttpError(exc.code, body) from exc
    except urllib.error.URLError as exc:
        raise HttpError(0, str(exc.reason)) from exc


def post_json(url: str, payload: dict, headers: dict | None = None,
              timeout: float = 30.0) -> dict:
    """POST a JSON body and parse the JSON response."""
    _require_https(url)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            **(headers or {}),
        },
        method="POST",
    )
    try:
        # HTTPS and redirect schemes are enforced before the opener is used.
        with _HTTPS_OPENER.open(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:300]
        except OSError:
            pass
        raise HttpError(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise HttpError(0, str(exc.reason)) from exc
