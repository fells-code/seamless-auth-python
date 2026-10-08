"""The admin dashboard, proxied from the auth API onto the application's origin."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING

import httpx2

from ._http import AuthResponse
from ._manifest import percent_decode

if TYPE_CHECKING:
    from ._adapter import Adapter

log = logging.getLogger("seamless_auth")

CONSOLE_BASE_PATH = "/console"
UPSTREAM_TIMEOUT = 10.0
MAX_REDIRECTS = 5
FORWARDED_HEADERS = ("content-type", "cache-control", "etag", "last-modified")


def _error(status: int, message: str) -> AuthResponse:
    return AuthResponse(
        status,
        [("content-type", "application/json; charset=utf-8")],
        json.dumps({"error": message}).encode(),
    )


class Console:
    """Reverse-proxies the Seamless admin dashboard. Nothing from the incoming
    request is forwarded but the method and the path: the console is public static
    hosting, and the browser's session cookies have no business at the upstream."""

    def __init__(self, adapter: Adapter) -> None:
        self._adapter = adapter
        base = httpx2.URL(adapter.config.auth_server_url)
        self._base = base
        self._prefix = (
            base.raw_path.decode("ascii").split("?", 1)[0].rstrip("/") + CONSOLE_BASE_PATH
        )

    def _inside(self, url: httpx2.URL) -> bool:
        """Holds a URL to the auth API's origin and the console subtree."""
        path = url.raw_path.decode("ascii").split("?", 1)[0]
        return (
            url.scheme == self._base.scheme
            and url.host == self._base.host
            and url.port == self._base.port
            and (path == self._prefix or path.startswith(self._prefix + "/"))
        )

    def _upstream(self, subpath: str, query: str) -> httpx2.URL | None:
        """Maps a path below the mount to the console on the auth API, refusing
        anything that could leave the console subtree: an encoded separator (an
        upstream that decodes it would read a traversal), and any dot segment,
        literal or encoded."""
        lower = subpath.lower()
        if "%2f" in lower or "%5c" in lower or "\\" in subpath:
            return None
        for segment in subpath.split("/"):
            decoded = percent_decode(segment)
            if decoded is None or decoded in (".", ".."):
                return None
        if subpath in ("", "/"):
            subpath = ""
        elif not subpath.startswith("/"):
            subpath = "/" + subpath
        if not subpath.isascii() or not subpath.isprintable():
            return None

        raw = f"{self._base.scheme}://{self._base.netloc.decode('ascii')}{self._prefix}{subpath}"
        if query:
            raw = f"{raw}?{query}"
        try:
            url = httpx2.URL(raw)
        except (httpx2.InvalidURL, ValueError):
            return None
        return url if self._inside(url) else None

    def handle(self, method: str, subpath: str, query: str = "") -> AuthResponse:
        """Serves one console request. ``subpath`` is the raw path below /console.
        Blocking: run it on a worker thread from async code."""
        method = method.upper()
        if method not in ("GET", "HEAD"):
            return _error(405, "Method not allowed")
        url = self._upstream(subpath, query)
        if url is None:
            return _error(400, "Invalid console path")

        client = self._adapter._client
        response: httpx2.Response | None = None
        try:
            for _ in range(MAX_REDIRECTS + 1):
                request = client.build_request(method, url, timeout=UPSTREAM_TIMEOUT)
                response = client.send(request, stream=True)
                if not response.is_redirect:
                    break
                follow = response.next_request
                response.close()
                response = None
                # A redirect is followed only while it stays inside the console on
                # the auth API's own origin.
                if follow is None or not self._inside(follow.url):
                    return _error(502, "Console upstream unreachable")
                url = follow.url
            else:
                return _error(502, "Console upstream unreachable")
        except (httpx2.HTTPError, httpx2.InvalidURL, UnicodeError, ValueError) as err:
            log.warning("[seamless-auth] Console upstream: %s", type(err).__name__)
            return _error(502, "Console upstream unreachable")

        if response is None:
            return _error(502, "Console upstream unreachable")
        headers = [
            (name, response.headers[name]) for name in FORWARDED_HEADERS if name in response.headers
        ]
        if method == "HEAD":
            response.close()
            return AuthResponse(response.status_code, headers, b"")
        return AuthResponse(response.status_code, headers, _stream(response), response.close)


def _stream(res: httpx2.Response) -> Iterator[bytes]:
    try:
        yield from res.iter_bytes()
    finally:
        res.close()
