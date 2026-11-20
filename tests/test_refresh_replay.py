"""Concurrent refreshes across adapter instances. The auth API answers every caller
presenting a refresh token inside its replay window with the same successor, so each
instance succeeds and writes the same refresh cookie."""

from __future__ import annotations

import threading
from typing import Any

import httpx2
import pytest
from conftest import (
    TEST_SECRET,
    FakeApi,
    api_token,
    call,
    respond,
    signed_cookie,
)

from seamless_auth._jwt import verify_hs256

REFRESH = signed_cookie("seamless-refresh", {"sub": "u1", "refreshToken": "r1"})


class ReplayingApi:
    """Answers every caller holding r1 with the one successor r2 and a freshly
    minted access token, as the auth API's replay window does."""

    def __init__(self, callers: int) -> None:
        self.lock = threading.Lock()
        self.minted = 0
        self.arrived = threading.Barrier(callers)

    def refresh(self, _req: httpx2.Request) -> httpx2.Response:
        self.arrived.wait(timeout=10)
        with self.lock:
            self.minted += 1
            jti = f"access-{self.minted}"
        return httpx2.Response(
            200,
            json={
                "message": "Success",
                "sub": "u1",
                "token": api_token("u1", "access", sid="s-1", jti=jti),
                "refreshToken": "r2",
                "sessionId": "s-1",
                "ttl": 900,
                "refreshTtl": 3600,
                "roles": ["user"],
                "organizationId": "org-1",
            },
        )


def _claims(value: str) -> dict[str, Any]:
    claims = verify_hs256(value, TEST_SECRET)
    assert claims is not None
    return claims


@pytest.mark.parametrize(
    "route", [("POST", "/refresh"), ("GET", "/users/me")], ids=["post", "silent"]
)
def test_two_instances_refreshing_one_token_both_write_the_same_successor(
    route: tuple[str, str],
) -> None:
    contract = ReplayingApi(callers=2)
    apis = [FakeApi(), FakeApi()]
    for api in apis:
        api.on("POST", "/refresh", contract.refresh)
        api.on("GET", "/users/me", respond(200, {"user": {"id": "u1"}}))
    adapters = [api.adapter() for api in apis]
    replies: list[Any] = [None, None]

    def run(i: int) -> None:
        replies[i] = call(adapters[i], *route, cookie=REFRESH)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert contract.minted == 2
    for api in apis:
        assert len(api.calls_to("POST", "/refresh")) == 1
    for r in replies:
        assert r.status == 200, r.text
        assert "refreshToken" not in r.text
    refresh = [_claims(r.cookies["seamless-refresh"].value) for r in replies]
    assert [c["refreshToken"] for c in refresh] == ["r2", "r2"]
    access = [_claims(r.cookies["seamless-access"].value) for r in replies]
    assert [a["sessionId"] for a in access] == ["s-1", "s-1"]
    assert access[0]["token"] != access[1]["token"]


@pytest.mark.parametrize(
    "route", [("POST", "/refresh"), ("GET", "/users/me")], ids=["post", "silent"]
)
def test_refresh_token_reused_clears_the_cookies_and_is_not_retried(
    api: FakeApi, route: tuple[str, str]
) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))
    api.on("GET", "/users/me", respond(200, {"user": {"id": "u1"}}))

    r = call(api.adapter(), *route, cookie=REFRESH)

    assert r.status == 401, r.text
    assert r.cleared("seamless-access")
    assert r.cleared("seamless-refresh")
    assert len(api.calls_to("POST", "/refresh")) == 1
    assert api.calls_to("GET", "/users/me") == []
