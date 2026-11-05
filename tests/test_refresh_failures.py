"""Cookie-transport refresh failures: only a 401 from the auth API, or a refresh
cookie that cannot be read, ends the session. Anything transient keeps it."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from conftest import (
    API_URL,
    TEST_SECRET,
    TEST_SERVICE,
    FakeApi,
    Handler,
    api_token,
    call,
    raw_cookie,
    respond,
    session,
    signed_cookie,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

from seamless_auth.fastapi import auth_router

REFRESH = signed_cookie("seamless-refresh", {"sub": "u1", "refreshToken": "r1"})
SESSION_COOKIES = ("seamless-access", "seamless-ephemeral", "seamless-refresh")

# Silent refresh restores the access cookie for an auth route; POST /refresh is the
# explicit one.
SILENT = ("GET", "/users/me")
EXPLICIT = ("POST", "/refresh")


def _down(_req: httpx2.Request) -> httpx2.Response:
    raise httpx2.ConnectError("connection refused")


def _unverifiable() -> dict[str, Any]:
    body = session()
    body["token"] = api_token("u1", "ephemeral", sid="s-1")
    return body


UPSTREAM_UNAVAILABLE: dict[str, Handler] = {
    "transport error": _down,
    "2xx with no session": respond(200, {"message": "Success"}),
    "2xx with an unverifiable session": respond(200, _unverifiable()),
}


def _route(api: FakeApi) -> None:
    api.on("GET", "/users/me", respond(200, {"user": {"id": "u1"}}))


def _kept(r: Any) -> bool:
    return not any(name in r.cookies for name in SESSION_COOKIES)


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
@pytest.mark.parametrize("case", list(UPSTREAM_UNAVAILABLE), ids=list(UPSTREAM_UNAVAILABLE))
def test_a_transient_refresh_failure_is_502_and_keeps_the_cookies(
    api: FakeApi, route: tuple[str, str], case: str
) -> None:
    api.on("POST", "/refresh", UPSTREAM_UNAVAILABLE[case])
    _route(api)

    r = call(api.adapter(), *route, cookie=REFRESH)

    assert (r.status, r.body) == (502, {"error": "upstream_unavailable"}), r.text
    assert _kept(r), r.cookies


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (503, {"error": "maintenance"}, {"error": "maintenance"}),
        (
            429,
            {"error": "rate_limited", "retryAfter": 30},
            {"error": "rate_limited", "retryAfter": 30},
        ),
        (500, "boom", {"error": "upstream_error"}),
        (403, {"error": "forbidden"}, {"error": "forbidden"}),
    ],
)
def test_any_other_refresh_answer_passes_through_and_keeps_the_cookies(
    api: FakeApi, route: tuple[str, str], status: int, body: Any, expected: Any
) -> None:
    api.on("POST", "/refresh", respond(status, body))
    _route(api)

    r = call(api.adapter(), *route, cookie=REFRESH)

    assert (r.status, r.body) == (status, expected), r.text
    assert _kept(r), r.cookies


@pytest.mark.parametrize(
    ("route", "error", "cleared"),
    [
        (SILENT, "Refresh failed", SESSION_COOKIES),
        (EXPLICIT, "invalid_refresh_token", ("seamless-access", "seamless-refresh")),
    ],
    ids=["silent", "post"],
)
def test_a_401_refresh_ends_the_session(
    api: FakeApi, route: tuple[str, str], error: str, cleared: tuple[str, ...]
) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))
    _route(api)

    r = call(api.adapter(), *route, cookie=REFRESH)

    assert (r.status, r.body) == (401, {"error": error})
    for name in cleared:
        assert r.cleared(name), name


@pytest.mark.parametrize(
    "cookie",
    [
        f"{REFRESH}x",
        raw_cookie("seamless-refresh", "access", {"sub": "u1", "refreshToken": "r1"}),
        signed_cookie("seamless-refresh", {"sub": "u1"}),
    ],
    ids=["altered", "wrong kind", "no refresh token"],
)
@pytest.mark.parametrize(
    ("route", "error"), [(SILENT, "Refresh failed"), (EXPLICIT, "invalid_refresh_token")]
)
def test_an_unreadable_refresh_cookie_ends_the_session(
    api: FakeApi, route: tuple[str, str], error: str, cookie: str
) -> None:
    _route(api)

    r = call(api.adapter(), *route, cookie=cookie)

    assert (r.status, r.body) == (401, {"error": error})
    assert r.cleared("seamless-access") and r.cleared("seamless-refresh")
    assert not api.calls_to("POST", "/refresh")


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
def test_a_transient_failure_is_not_kept_for_the_reuse_window(
    api: FakeApi, route: tuple[str, str]
) -> None:
    api.on("POST", "/refresh", respond(503, {"error": "maintenance"}))
    _route(api)
    adapter = api.adapter()

    first = call(adapter, *route, cookie=REFRESH)
    api.on("POST", "/refresh", respond(200, session()))
    second = call(adapter, *route, cookie=REFRESH)

    assert first.status == 503
    assert second.status == 200, second.text
    assert "seamless-access" in second.cookies and "seamless-refresh" in second.cookies
    assert len(api.calls_to("POST", "/refresh")) == 2


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
def test_a_waiter_timing_out_on_another_rotation_keeps_the_cookies(
    api: FakeApi, route: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("seamless_auth._refresh.FLIGHT_TIMEOUT", 0.05)
    started = threading.Event()
    gate = threading.Event()

    def refresh(_req: httpx2.Request) -> httpx2.Response:
        started.set()
        gate.wait(2)
        return httpx2.Response(200, json=session())

    api.on("POST", "/refresh", refresh)
    _route(api)
    adapter = api.adapter()

    first: list[Any] = []
    leader = threading.Thread(target=lambda: first.append(call(adapter, *route, cookie=REFRESH)))
    leader.start()
    assert started.wait(2)
    waiter = call(adapter, *route, cookie=REFRESH)
    gate.set()
    leader.join()

    assert (waiter.status, waiter.body) == (502, {"error": "upstream_unavailable"}), waiter.text
    assert _kept(waiter), waiter.cookies
    assert first[0].status == 200
    assert len(api.calls_to("POST", "/refresh")) == 1


# The bindings: what a browser sees through each.

TRANSIENT: list[tuple[str, Handler, int]] = [
    ("transport error", _down, 502),
    ("503", respond(503, {"error": "maintenance"}), 503),
]


@pytest.fixture
def fastapi_client(api: FakeApi) -> TestClient:
    app = FastAPI()
    app.include_router(auth_router(api.adapter()))
    client = TestClient(app, base_url="https://testserver")
    client.cookies.set("seamless-refresh", REFRESH.split("=", 1)[1])
    return client


def _fastapi_send(client: TestClient, route: tuple[str, str]) -> httpx2.Response:
    method, path = route
    if method == "POST":
        return client.post(f"/auth{path}", headers={"content-type": "application/json"})
    return client.get(f"/auth{path}")


def _set_cookie_names(r: Any) -> set[str]:
    return {c.split("=", 1)[0] for c in r.headers.get_list("set-cookie")}


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
@pytest.mark.parametrize("transient", TRANSIENT, ids=[t[0] for t in TRANSIENT])
def test_fastapi_keeps_the_cookies_on_a_transient_refresh_failure(
    api: FakeApi,
    fastapi_client: TestClient,
    route: tuple[str, str],
    transient: tuple[str, Handler, int],
) -> None:
    case, handler, status = transient
    api.on("POST", "/refresh", handler)
    _route(api)

    r = _fastapi_send(fastapi_client, route)

    assert r.status_code == status, r.text
    assert not _set_cookie_names(r) & set(SESSION_COOKIES), case


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
def test_fastapi_clears_the_cookies_on_a_401_refresh(
    api: FakeApi, fastapi_client: TestClient, route: tuple[str, str]
) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))
    _route(api)

    r = _fastapi_send(fastapi_client, route)

    assert r.status_code == 401
    assert {"seamless-access", "seamless-refresh"} <= _set_cookie_names(r)


@pytest.fixture
def django_client(api: FakeApi) -> Iterator[Any]:
    import test_django  # noqa: F401  configures Django settings once
    from django.test import Client, override_settings

    from seamless_auth.django import _reset_adapter

    options: dict[str, Any] = {
        "auth_server_url": API_URL,
        "cookie_secret": TEST_SECRET,
        "service_secret": TEST_SERVICE,
        "jwks_kid": "test-main",
        "disable_manifest_fetch": True,
        "http_client": api.client(),
    }
    _reset_adapter()
    with override_settings(SEAMLESS_AUTH=options):
        client = Client(enforce_csrf_checks=True)
        client.cookies["seamless-refresh"] = REFRESH.split("=", 1)[1]
        yield client
    _reset_adapter()


def _django_send(client: Any, route: tuple[str, str]) -> Any:
    method, path = route
    if method == "POST":
        return client.post(f"/auth{path}", content_type="application/json")
    return client.get(f"/auth{path}")


def _django_cleared(r: Any, name: str) -> bool:
    return name in r.cookies and r.cookies[name].value == "" and r.cookies[name]["max-age"] == 0


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
@pytest.mark.parametrize("transient", TRANSIENT, ids=[t[0] for t in TRANSIENT])
def test_django_keeps_the_cookies_on_a_transient_refresh_failure(
    api: FakeApi,
    django_client: Any,
    route: tuple[str, str],
    transient: tuple[str, Handler, int],
) -> None:
    case, handler, status = transient
    api.on("POST", "/refresh", handler)
    _route(api)

    r = _django_send(django_client, route)

    assert r.status_code == status, r.content
    for name in SESSION_COOKIES:
        assert not _django_cleared(r, name), (case, name)


@pytest.mark.parametrize("route", [SILENT, EXPLICIT], ids=["silent", "post"])
def test_django_clears_the_cookies_on_a_401_refresh(
    api: FakeApi, django_client: Any, route: tuple[str, str]
) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))
    _route(api)

    r = _django_send(django_client, route)

    assert r.status_code == 401
    assert _django_cleared(r, "seamless-access") and _django_cleared(r, "seamless-refresh")
