from __future__ import annotations

import httpx2
import pytest
from conftest import (
    API_URL,
    FakeApi,
    access,
    api_token,
    hs256_access_token,
    pre_auth,
    respond,
    session,
    signed_cookie,
)
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from seamless_auth import Adapter, Delivery, User
from seamless_auth.fastapi import OptionalUser, RequireUser, auth_router


def app_for(adapter: Adapter) -> TestClient:
    app = FastAPI()
    app.include_router(auth_router(adapter))
    current_user = RequireUser(adapter)

    @app.get("/api/me")
    def me(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
        return {"id": user.id}

    @app.get("/api/enroll")
    def enroll(
        user: User = Depends(RequireUser(adapter, allow_recovery=True)),  # noqa: B008
    ) -> dict[str, object]:
        return {"id": user.id, "recovery": user.recovery}

    @app.post("/api/transfer")
    def transfer(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
        return {"id": user.id}

    @app.api_route("/api/admin", methods=["GET", "POST"])
    def admin(
        user: User = Depends(RequireUser(adapter, roles=["admin", "billing:write"])),  # noqa: B008
    ) -> dict[str, str]:
        return {"id": user.id}

    @app.api_route("/api/maybe", methods=["GET", "POST"])
    def maybe(
        user: User | None = Depends(OptionalUser(adapter)),  # noqa: B008
    ) -> dict[str, object]:
        return {"user": None if user is None else {"id": user.id, "org": user.organization_id}}

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

    # A valid cookie signature does not make the token inside it the API's.
    forged = signed_cookie("seamless-access", {"sub": "u1", "token": hs256_access_token()})
    assert client.get("/api/me", headers={"cookie": forged}).status_code == 401
    other = signed_cookie("seamless-access", {"sub": "u1", "token": api_token("u2", "access")})
    assert client.get("/api/me", headers={"cookie": other}).status_code == 401


def test_the_guard_refuses_a_recovery_session_unless_allowed(api: FakeApi) -> None:
    client = app_for(api.adapter())
    recovery = {"authorization": f"Bearer {api_token('u1', 'access', recovery=True)}"}

    r = client.get("/api/me", headers=recovery)
    assert r.status_code == 403
    assert r.json() == {"detail": "enrollment_required"}
    r = client.get("/api/enroll", headers=recovery)
    assert (r.status_code, r.json()) == (200, {"id": "u1", "recovery": True})
    assert client.get("/api/enroll").status_code == 401


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

    r = client.post("/auth/magic-link", headers={"content-type": "application/json"})

    assert r.status_code == 200
    assert r.json() == {"message": "sent"}
    assert got[0].to == "a@b.test"
    assert API_URL


def bearer_header(**claims: object) -> dict[str, str]:
    return {"authorization": f"Bearer {api_token('u1', 'access', **claims)}"}


def test_the_role_guard(api: FakeApi) -> None:
    client = app_for(api.adapter())

    r = client.get("/api/admin")
    assert (r.status_code, r.json()) == (401, {"detail": "unauthenticated"})
    r = client.get("/api/admin", headers=bearer_header(roles=["user"]))
    assert (r.status_code, r.json()) == (403, {"detail": "insufficient_role"})
    r = client.get(
        "/api/admin", headers=bearer_header(roles=["admin", "secret-role"], recovery=True)
    )
    assert (r.status_code, r.json()) == (403, {"detail": "enrollment_required"})
    for roles in (["admin"], ["billing:*"], ["billing"]):
        r = client.get("/api/admin", headers=bearer_header(roles=roles))
        assert (r.status_code, r.json()) == (200, {"id": "u1"}), roles

    cookie = signed_cookie(
        "seamless-access", {"sub": "u1", "token": api_token("u1", "access"), "roles": ["admin"]}
    )
    r = client.get("/api/admin", headers={"cookie": cookie})
    assert (r.status_code, r.json()) == (403, {"detail": "insufficient_role"})
    admin_cookie = signed_cookie(
        "seamless-access", {"sub": "u1", "token": api_token("u1", "access", roles=["admin"])}
    )
    r = client.post("/api/admin", headers={"cookie": admin_cookie, "sec-fetch-site": "cross-site"})
    assert (r.status_code, r.json()) == (403, {"detail": "cross_site_request_blocked"})


def test_the_role_guard_refuses_no_roles_at_setup(api: FakeApi) -> None:
    with pytest.raises(ValueError, match="at least one"):
        RequireUser(api.adapter(), roles=[])
    with pytest.raises(TypeError):
        RequireUser(api.adapter(), roles="admin")


def test_the_optional_user(api: FakeApi) -> None:
    client = app_for(api.adapter())

    assert client.get("/api/maybe").json() == {"user": None}
    r = client.get("/api/maybe", headers=bearer_header(org_id="org-1"))
    assert (r.status_code, r.json()) == (200, {"user": {"id": "u1", "org": "org-1"}})
    r = client.get("/api/maybe", headers=bearer_header(recovery=True))
    assert (r.status_code, r.json()) == (200, {"user": None})
    cookie = signed_cookie("seamless-access", {"sub": "u1", "token": api_token("u1", "access")})
    r = client.post("/api/maybe", headers={"cookie": cookie, "sec-fetch-site": "cross-site"})
    assert (r.status_code, r.json()) == (200, {"user": None})
    forged = signed_cookie("seamless-access", {"sub": "u1", "token": hs256_access_token()})
    assert client.get("/api/maybe", headers={"cookie": forged}).json() == {"user": None}
