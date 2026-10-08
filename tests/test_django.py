from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from conftest import (
    API_URL,
    TEST_SECRET,
    TEST_SERVICE,
    FakeApi,
    access,
    api_token,
    pre_auth,
    respond,
    session,
    signed_cookie,
)
from django.conf import settings

if not settings.configured:
    settings.configure(
        SECRET_KEY="django-tests-only",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="test_django_urls",
        MIDDLEWARE=["django.middleware.csrf.CsrfViewMiddleware"],
        INSTALLED_APPS=[],
    )
    import django

    django.setup()

from django.test import Client, override_settings

from seamless_auth.django import _reset_adapter


@pytest.fixture
def client(api: FakeApi) -> Iterator[Client]:
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
        yield Client(enforce_csrf_checks=True)
    _reset_adapter()


def test_a_sign_in_sets_every_cookie_and_skips_csrf(api: FakeApi, client: Client) -> None:
    api.on("POST", "/totp/verify-login", respond(200, session()))
    client.cookies["seamless-ephemeral"] = pre_auth().split("=", 1)[1]

    r = client.post("/auth/totp/verify-login", data='{"code":"1"}', content_type="application/json")

    assert r.status_code == 200, r.content
    assert set(r.cookies) == {"seamless-access", "seamless-refresh"}
    morsel = r.cookies["seamless-access"]
    assert morsel["httponly"] and morsel["secure"] and morsel["samesite"] == "None"
    assert morsel["path"] == "/" and morsel["max-age"] == 900
    assert "token" not in r.json()


def test_logout_clears_cookies(api: FakeApi, client: Client) -> None:
    api.on("DELETE", "/logout", respond(200, {}))
    client.cookies["seamless-access"] = access().split("=", 1)[1]

    r = client.delete("/auth/logout")

    assert r.status_code == 204
    for name in ("seamless-access", "seamless-ephemeral", "seamless-refresh"):
        assert r.cookies[name].value == ""
        assert r.cookies[name]["max-age"] == 0


def test_the_raw_path_reaches_the_matcher(api: FakeApi, client: Client) -> None:
    api.on("GET", "/admin/users/a%2Fb", respond(200, {"ok": True}))
    client.cookies["seamless-access"] = access().split("=", 1)[1]

    assert (
        client.get("/auth/admin/users/a%2Fb", REQUEST_URI="/auth/admin/users/a%2Fb").status_code
        == 200
    )
    assert client.get("/auth/admin/users/%2E%2E").status_code == 404


def test_downloads_stream(api: FakeApi, client: Client) -> None:
    api.on(
        "GET",
        "/admin/auth-events/export",
        lambda _r: httpx2.Response(
            200, content=b"line1\nline2\n", headers={"content-type": "application/x-ndjson"}
        ),
    )
    client.cookies["seamless-access"] = access().split("=", 1)[1]

    r = client.get("/auth/admin/auth-events/export")

    assert r.status_code == 200
    assert b"".join(r.streaming_content) == b"line1\nline2\n"  # type: ignore[attr-defined]
    assert r["Content-Type"] == "application/x-ndjson"


def test_a_text_plain_body_is_415(client: Client) -> None:
    r = client.post("/auth/oauth/mock/callback", data='{"code":"x"}', content_type="text/plain")
    assert r.status_code == 415


def test_the_guard(client: Client) -> None:
    assert client.get("/api/me").status_code == 401
    r = client.get("/api/me", HTTP_AUTHORIZATION=f"Bearer {api_token('u1', 'access')}")
    assert r.status_code == 200 and r.json() == {"id": "u1"}

    ephemeral = signed_cookie(
        "seamless-ephemeral", {"sub": "u1", "token": api_token("u1", "ephemeral")}
    )
    assert client.get("/api/me", HTTP_COOKIE=ephemeral).status_code == 401

    session_cookie = signed_cookie(
        "seamless-access", {"sub": "u1", "token": api_token("u1", "access")}
    )
    assert (
        client.post(
            "/api/transfer", HTTP_COOKIE=session_cookie, HTTP_SEC_FETCH_SITE="cross-site"
        ).status_code
        == 403
    )
    r = client.post("/api/transfer", HTTP_COOKIE=session_cookie, HTTP_SEC_FETCH_SITE="same-origin")
    assert r.status_code == 200


def test_the_guard_on_an_async_view(client: Client) -> None:
    r = client.get("/api/me-async", HTTP_AUTHORIZATION=f"Bearer {api_token('u1', 'access')}")
    assert r.status_code == 200 and r.json() == {"id": "u1"}
    assert client.get("/api/me-async").status_code == 401


def test_an_async_deliver_does_not_deadlock_under_asgi(api: FakeApi) -> None:
    import asyncio

    from asgiref.sync import sync_to_async
    from django.test import AsyncClient

    from seamless_auth import Delivery

    api.on(
        "POST",
        "/magic-link",
        respond(
            200, {"message": "sent", "delivery": {"kind": "magic_link_email", "to": "a@b.test"}}
        ),
    )
    got: list[str] = []

    async def deliver(delivery: Delivery) -> None:
        # Thread-sensitive work, as the async ORM does: it needs the executor that
        # is running the view.
        await sync_to_async(got.append)(delivery.to)

    options = {
        "auth_server_url": API_URL,
        "cookie_secret": TEST_SECRET,
        "service_secret": TEST_SERVICE,
        "jwks_kid": "test-main",
        "disable_manifest_fetch": True,
        "http_client": api.client(),
        "deliver": deliver,
    }

    async def run() -> int:
        client = AsyncClient()
        client.cookies["seamless-ephemeral"] = pre_auth().split("=", 1)[1]
        r = await client.post("/auth/magic-link", data="{}", content_type="application/json")
        return int(r.status_code)

    _reset_adapter()
    try:
        with override_settings(SEAMLESS_AUTH=options):
            status = asyncio.run(asyncio.wait_for(run(), timeout=10))
    finally:
        _reset_adapter()

    assert status == 200
    assert got == ["a@b.test"]
