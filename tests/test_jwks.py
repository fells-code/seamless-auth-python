from __future__ import annotations

import contextlib
import threading
import time

import httpx2
import pytest
from conftest import API_URL, JWKS, api_token

from seamless_auth._jwks import REFETCH_INTERVAL, JwksCache, TokenError

JWKS_URL = f"{API_URL}/.well-known/jwks.json"


class SlowJwks:
    """A JWKS endpoint whose fetches after the first hang until released."""

    def __init__(self) -> None:
        self.fetches = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def handle(self, _request: httpx2.Request) -> httpx2.Response:
        self.fetches += 1
        if self.fetches > 1:
            self.started.set()
            self.release.wait(10)
        return httpx2.Response(200, json=JWKS)


def test_a_cached_kid_does_not_wait_on_a_fetch_in_progress() -> None:
    endpoint = SlowJwks()
    cache = JwksCache(JWKS_URL, httpx2.Client(transport=httpx2.MockTransport(endpoint.handle)))
    token = api_token("u1", "access")
    cache.verify(token, API_URL, API_URL)
    # Past the refetch interval, so an unknown kid is allowed a refetch.
    cache._attempted_at = time.monotonic() - REFETCH_INTERVAL - 1

    unknown = threading.Thread(target=lambda: _swallow(cache, "random-kid"))
    unknown.start()
    try:
        assert endpoint.started.wait(5), "the refetch for the unknown kid never started"

        done = threading.Event()
        verified = threading.Thread(
            target=lambda: (cache.verify(token, API_URL, API_URL), done.set())
        )
        verified.start()
        assert done.wait(1), "a token with a cached, fresh kid waited on the slow fetch"
        verified.join(5)
    finally:
        endpoint.release.set()
        unknown.join(10)


def test_concurrent_misses_share_one_fetch() -> None:
    endpoint = SlowJwks()
    cache = JwksCache(JWKS_URL, httpx2.Client(transport=httpx2.MockTransport(endpoint.handle)))
    cache.verify(api_token("u1", "access"), API_URL, API_URL)
    cache._attempted_at = time.monotonic() - REFETCH_INTERVAL - 1

    threads = [threading.Thread(target=lambda: _swallow(cache, "random-kid")) for _ in range(5)]
    for t in threads:
        t.start()
    try:
        assert endpoint.started.wait(5)
        time.sleep(0.2)
    finally:
        endpoint.release.set()
        for t in threads:
            t.join(10)
    assert endpoint.fetches == 2, "the misses refetched once between them"


def _swallow(cache: JwksCache, kid: str) -> None:
    with contextlib.suppress(TokenError):
        cache.key(kid)


def test_a_failed_fetch_releases_its_waiters() -> None:
    fetches = 0

    def failing(_request: httpx2.Request) -> httpx2.Response:
        nonlocal fetches
        fetches += 1
        return httpx2.Response(503)

    cache = JwksCache(JWKS_URL, httpx2.Client(transport=httpx2.MockTransport(failing)))

    for _ in range(2):
        with pytest.raises(TokenError):
            cache.key("k1")
    assert fetches == 1, "a second miss inside the backoff does not fetch again"
    assert cache._fetching is None
