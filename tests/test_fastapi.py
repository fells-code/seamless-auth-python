from __future__ import annotations

import httpx2
from conftest import API_URL, FakeApi, access, api_token, pre_auth, respond, session, signed_cookie
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from seamless_auth import Adapter, Delivery, User
from seamless_auth.fastapi import RequireUser, auth_router


def app_for(adapter: Adapter) -> TestClient:
    app = FastAPI()
    app.include_router(auth_router(adapter))
    current_user = RequireUser(adapter)

    @app.get("/api/me")
    def me(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
        return {"id": user.id}

    @app.post("/api/transfer")
    def transfer(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
        return {"id": user.id}

    return TestClient(app, base_url="https://testserver")


def test_a_sign_in_sets_every_cookie_on_the_response(api: FakeApi) -> None:
    api.on("POST", "/totp/verify-login", respond(200, session()))
    client = app_for(api.adapter())
    client.cookies.set("seamless-ephemeral", pre_auth().split("=", 1)[1])

    r = client.post("/auth/totp/verify-login", json={"code": "123456"})

    assert r.status_code == 200, r.text
    set_cookies = r.headers.get_list("set-cookie")
    assert {c.split("=", 1)[0] for c in set_cookies} == {"seamless-access", "seamless-refresh"}
    assert "token" not in r.json()


def test_the_raw_path_reaches_the_matcher(api: FakeApi) -> None:
    api.on("GET", "/admin/users/a%2Fb", respond(200, {"ok": True}))
    client = app_for(api.adapter())
    client.cookies.set("seamless-access", access().split("=", 1)[1])

    assert client.get("/auth/admin/users/a%2Fb").status_code == 200
    assert client.get("/auth/admin/users/%2E%2E").status_code == 404


def test_the_query_and_peer_are_forwarded(api: FakeApi) -> None:
    api.on("GET", "/admin/auth-events", respond(200, {"events": []}))
    client = app_for(api.adapter())
    client.cookies.set("seamless-access", access().split("=", 1)[1])

    client.get("/auth/admin/auth-events?limit=5&from=x", headers={"user-agent": "browser/1"})

    recorded = api.calls_to("GET", "/admin/auth-events")[0]
    assert recorded.query == "limit=5&from=x"
    # The test client's peer is "testclient", which is no address to forward.
    assert "x-seamless-client-ip" not in recorded.headers
    assert recorded.headers["x-seamless-client-user-agent"] == "browser/1"


def test_downloads_stream(api: FakeApi) -> None:
    api.on(
        "GET",
        "/admin/auth-events/export",
        lambda _r: httpx2.Response(
            200, content=b"line1\nline2\n", headers={"content-type": "application/x-ndjson"}
        ),
    )
    client = app_for(api.adapter())
    client.cookies.set("seamless-access", access().split("=", 1)[1])

    r = client.get("/auth/admin/auth-events/export")

    assert r.status_code == 200
    assert r.content == b"line1\nline2\n"
    assert r.headers["content-type"] == "application/x-ndjson"


def test_an_oversized_body_is_413(api: FakeApi) -> None:
    client = app_for(api.adapter())
    r = client.post(
        "/auth/login", content=b"x" * ((1 << 20) + 1), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert not api.calls_to("POST", "/login")


def test_a_text_plain_body_is_415(api: FakeApi) -> None:
    client = app_for(api.adapter())
    r = client.post(
        "/auth/oauth/mock/callback", content=b'{"code":"x"}', headers={"content-type": "text/plain"}
    )
    assert r.status_code == 415


def test_the_guard(api: FakeApi) -> None:
    client = app_for(api.adapter())

    assert client.get("/api/me").status_code == 401
    r = client.get("/api/me", headers={"authorization": f"Bearer {api_token('u1', 'access')}"})
    assert r.status_code == 200 and r.json() == {"id": "u1"}

    ephemeral = signed_cookie(
        "seamless-ephemeral", {"sub": "u1", "token": api_token("u1", "ephemeral")}
    )
    assert client.get("/api/me", headers={"cookie": ephemeral}).status_code == 401

    session_cookie = signed_cookie(
        "seamless-access", {"sub": "u1", "token": api_token("u1", "access")}
    )
    r = client.post(
        "/api/transfer", headers={"cookie": session_cookie, "sec-fetch-site": "cross-site"}
    )
    assert r.status_code == 403
    r = client.post(
        "/api/transfer", headers={"cookie": session_cookie, "sec-fetch-site": "same-origin"}
    )
    assert r.status_code == 200


def test_an_async_deliver_runs_on_the_app_loop(api: FakeApi) -> None:
    api.on(
        "POST",
        "/magic-link",
        respond(
            200, {"message": "sent", "delivery": {"kind": "magic_link_email", "to": "a@b.test"}}
        ),
    )
    got: list[Delivery] = []

    async def deliver(delivery: Delivery) -> None:
        got.append(delivery)

    client = app_for(api.adapter(deliver=deliver))
    client.cookies.set("seamless-ephemeral", pre_auth().split("=", 1)[1])

    r = client.post("/auth/magic-link")

    assert r.status_code == 200
    assert r.json() == {"message": "sent"}
    assert got[0].to == "a@b.test"
    assert API_URL
