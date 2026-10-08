from __future__ import annotations

import json
import logging
import threading
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
    call,
    pre_auth,
    raw_cookie,
    respond,
    service_claims,
    session,
    signed_cookie,
)

from seamless_auth import Adapter, Delivery, TrustedProxies
from seamless_auth._adapter import (
    DELIVERY_SUBJECT,
    MAX_BODY_BYTES,
    PROXY_SUBJECT,
    _is_json_content_type,
)
from seamless_auth._jwt import sign_hs256, verify_hs256

REFRESH = signed_cookie("seamless-refresh", {"sub": "u1", "refreshToken": "r1"})


def test_login_stores_the_pre_auth_token_and_picks_the_body(api: FakeApi) -> None:
    api.on(
        "POST",
        "/login",
        respond(
            200,
            {
                "message": "Success",
                "identifierType": "email",
                "loginMethods": ["email_otp"],
                "sub": "u1",
                "ttl": 300,
                "token": api_token("u1", "ephemeral"),
            },
        ),
    )

    r = call(api.adapter(), "POST", "/login", body='{"identifier":"a@b.test"}')

    assert r.status == 200
    assert "token" not in r.body and "sub" not in r.body, r.body
    assert r.body["identifierType"] == "email"
    cookie = r.cookies["seamless-ephemeral"]
    assert cookie.max_age == 300
    assert cookie.http_only and cookie.secure and cookie.same_site == "None" and cookie.path == "/"
    header = cookie.header()
    for part in ("Path=/", "Max-Age=300", "HttpOnly", "Secure", "SameSite=None"):
        assert part in header


def test_a_session_route_sets_cookies_and_strips_tokens(api: FakeApi) -> None:
    api.on("POST", "/totp/verify-login", respond(200, session()))

    r = call(
        api.adapter(), "POST", "/totp/verify-login", body='{"code":"123456"}', cookie=pre_auth()
    )

    assert r.status == 200, r.text
    recorded = api.calls_to("POST", "/totp/verify-login")[0]
    assert recorded.headers["authorization"] == "Bearer pre-auth"
    assert recorded.body == b'{"code":"123456"}'
    assert recorded.headers["content-type"] == "application/json"
    assert "token" not in r.body and "refreshToken" not in r.body
    assert r.cookies["seamless-access"].max_age == 900
    assert r.cookies["seamless-refresh"].max_age == 3600
    claims = verify_hs256(r.cookies["seamless-access"].value, TEST_SECRET)
    assert claims is not None
    assert (claims["sessionId"], claims["sub"], claims["kind"]) == ("s-1", "u1", "access")


def test_a_session_that_does_not_verify_is_refused(api: FakeApi) -> None:
    forged = {**session(), "sub": "someone-else"}
    api.on("POST", "/totp/verify-login", respond(200, forged))

    r = call(api.adapter(), "POST", "/totp/verify-login", body="{}", cookie=pre_auth())

    assert r.status == 502
    assert not r.cookies


def test_a_session_signed_by_another_key_is_refused(api: FakeApi) -> None:
    claims = {"sub": "u1", "typ": "access", "iss": API_URL, "aud": API_URL}
    forged = {**session(), "token": sign_hs256(claims, TEST_SECRET, 60, "k1")}
    api.on("POST", "/totp/verify-login", respond(200, forged))

    r = call(api.adapter(), "POST", "/totp/verify-login", body="{}", cookie=pre_auth())

    assert r.status == 502
    assert not r.cookies


def test_an_issued_session_must_carry_the_expected_token_type(api: FakeApi) -> None:
    wrong = {**session(), "token": api_token("u1", "ephemeral")}
    api.on("POST", "/totp/verify-login", respond(200, wrong))
    r = call(api.adapter(), "POST", "/totp/verify-login", body="{}", cookie=pre_auth())
    assert r.status == 502, "session from an ephemeral token"
    assert not r.cookies

    api.on(
        "POST",
        "/login",
        respond(
            200, {"message": "ok", "sub": "u1", "ttl": 300, "token": api_token("u1", "access")}
        ),
    )
    r = call(api.adapter(), "POST", "/login", body="{}")
    assert r.status == 502, "pre-auth from an access token"
    assert not r.cookies


def test_bearer_transport_returns_the_whole_body_and_no_cookies(api: FakeApi) -> None:
    body = session()
    api.on("POST", "/totp/verify-login", respond(200, body))

    r = call(
        api.adapter(),
        "POST",
        "/totp/verify-login",
        body="{}",
        headers={"x-seamless-auth-transport": "bearer", "authorization": "Bearer client-token"},
    )

    assert r.status == 200
    assert r.body["token"] == body["token"] and r.body["refreshToken"] == "refresh-u1"
    assert not r.cookies
    assert (
        api.calls_to("POST", "/totp/verify-login")[0].headers["authorization"]
        == "Bearer client-token"
    )


def test_a_missing_access_cookie_is_restored_from_the_refresh_cookie_once(api: FakeApi) -> None:
    refreshes = 0
    gate = threading.Event()

    def refresh(_req: httpx2.Request) -> httpx2.Response:
        nonlocal refreshes
        refreshes += 1
        gate.wait(2)
        return httpx2.Response(200, json=session())

    api.on("POST", "/refresh", refresh)
    api.on("GET", "/users/me", respond(200, {"user": {"id": "u1"}}))
    adapter = api.adapter()

    results: list[Any] = [None] * 3

    def run(i: int) -> None:
        results[i] = call(adapter, "GET", "/users/me", cookie=REFRESH)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    gate.set()
    for t in threads:
        t.join()

    for r in results:
        assert r.status == 200, r.text
        assert "seamless-access" in r.cookies and "seamless-refresh" in r.cookies
    assert refreshes == 1

    recorded = api.calls_to("POST", "/refresh")[0]
    assert recorded.headers["authorization"] == "Bearer r1"
    service = service_claims(recorded)
    assert service["sub"] == "u1" and service["refreshToken"] == "r1"
    assert service["aud"] == "seamless-auth" and service["iss"] == "seamless-portal-api"


def test_a_failed_refresh_is_not_shared(api: FakeApi) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))
    adapter = api.adapter()

    call(adapter, "GET", "/users/me", cookie=REFRESH)
    call(adapter, "GET", "/users/me", cookie=REFRESH)

    assert len(api.calls_to("POST", "/refresh")) == 2


def test_a_failed_refresh_clears_the_session(api: FakeApi) -> None:
    api.on("POST", "/refresh", respond(401, {"error": "refresh_token_reused"}))

    r = call(api.adapter(), "GET", "/users/me", cookie=REFRESH)

    assert r.status == 401
    assert isinstance(r.body["error"], str)
    assert r.cleared("seamless-access") and r.cleared("seamless-refresh")


def test_an_altered_access_cookie_is_refused_without_refreshing(api: FakeApi) -> None:
    r = call(api.adapter(), "GET", "/users/me", cookie=f"{access()}x; {REFRESH}")

    assert r.status == 401
    assert not api.calls_to("POST", "/refresh")


def test_post_refresh_rotates_both_cookies_and_returns_no_tokens(api: FakeApi) -> None:
    api.on("POST", "/refresh", respond(200, session()))

    r = call(api.adapter(), "POST", "/refresh", cookie=REFRESH)

    assert r.status == 200, r.text
    assert "token" not in r.body and "refreshToken" not in r.body
    assert "seamless-access" in r.cookies and "seamless-refresh" in r.cookies


def test_bearer_refresh_is_shared_for_one_refresh_token(api: FakeApi) -> None:
    api.on("POST", "/refresh", respond(200, session()))
    adapter = api.adapter()
    headers = {"x-seamless-auth-transport": "bearer", "authorization": "Bearer r1"}

    first = call(adapter, "POST", "/refresh", headers=headers)
    second = call(adapter, "POST", "/refresh", headers=headers)

    assert first.status == 200
    assert first.body["refreshToken"] == "refresh-u1"
    assert second.body == first.body
    assert len(api.calls_to("POST", "/refresh")) == 1
    assert not first.cookies


def test_bearer_refresh_without_a_token_is_401(api: FakeApi) -> None:
    r = call(api.adapter(), "POST", "/refresh", headers={"x-seamless-auth-transport": "bearer"})
    assert r.status == 401


def test_logout_answers_204_and_clears_even_when_the_api_refuses(api: FakeApi) -> None:
    api.on("DELETE", "/logout", respond(500, {"error": "boom"}))
    adapter = api.adapter()

    r = call(adapter, "DELETE", "/logout", cookie=access())
    assert r.status == 500
    for name in ("seamless-access", "seamless-ephemeral", "seamless-refresh"):
        assert r.cleared(name), name

    api.on("DELETE", "/logout", respond(200, {"message": "ok"}))
    r = call(adapter, "DELETE", "/logout", cookie=access())
    assert r.status == 204
    assert r.text == ""


@pytest.mark.parametrize("path", ["/logout", "/logout/", "//logout", "/LOGOUT"])
def test_logout_clears_even_when_the_session_is_unreadable(api: FakeApi, path: str) -> None:
    r = call(api.adapter(), "DELETE", path, cookie=f"{access()}x; {REFRESH}")

    assert r.status == 401
    for name in ("seamless-access", "seamless-ephemeral", "seamless-refresh"):
        assert r.cleared(name), name


def _capture() -> tuple[list[Delivery], Any]:
    got: list[Delivery] = []
    return got, got.append


def test_delivery_routes_hand_the_message_to_the_application(api: FakeApi) -> None:
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(
            200,
            {
                "message": "success",
                "token": "re-minted",
                "delivery": {"kind": "otp_email", "to": "a@b.test", "token": "123456"},
            },
        ),
    )
    got, deliver = _capture()

    r = call(
        api.adapter(deliver=deliver), "POST", "/otp/generate-login-email-otp", cookie=pre_auth()
    )

    assert r.status == 200
    assert r.body == {"message": "success"}, (
        "the re-minted token and the delivery must not reach the browser"
    )
    assert (got[0].kind, got[0].to, got[0].token) == ("otp_email", "a@b.test", "123456")
    recorded = api.calls_to("POST", "/otp/generate-login-email-otp")[0]
    assert recorded.headers["x-seamless-auth-delivery-mode"] == "external"
    assert service_claims(recorded)["sub"] == DELIVERY_SUBJECT


def test_bearer_transport_strips_the_delivery_payload_too(api: FakeApi) -> None:
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(
            200,
            {
                "message": "success",
                "token": "re-minted",
                "delivery": {"kind": "otp_email", "to": "a@b.test", "token": 123456},
            },
        ),
    )
    got, deliver = _capture()

    r = call(
        api.adapter(deliver=deliver),
        "POST",
        "/otp/generate-login-email-otp",
        headers={"x-seamless-auth-transport": "bearer", "authorization": "Bearer pre-auth"},
    )

    assert r.status == 200
    assert "delivery" not in r.body
    assert r.body["token"] == "re-minted", "a bearer client keeps the re-minted token"
    assert got[0].token == "123456"


def test_an_async_deliver_callback_is_awaited(api: FakeApi) -> None:
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

    r = call(api.adapter(deliver=deliver), "POST", "/magic-link", cookie=pre_auth())

    assert r.status == 200
    assert got[0].to == "a@b.test"


def test_a_failed_delivery_is_reported(api: FakeApi) -> None:
    api.on(
        "POST",
        "/magic-link",
        respond(
            200,
            {
                "message": "sent",
                "delivery": {
                    "kind": "magic_link_email",
                    "to": "a@b.test",
                    "magicLinkUrl": "https://x",
                },
            },
        ),
    )

    def deliver(_d: Delivery) -> None:
        raise RuntimeError("smtp down")

    r = call(api.adapter(deliver=deliver), "POST", "/magic-link", cookie=pre_auth())

    assert r.status == 502
    assert r.body["error"] == "delivery_failed"


def test_a_failing_async_delivery_is_not_sent_twice(api: FakeApi) -> None:
    api.on(
        "POST",
        "/magic-link",
        respond(
            200, {"message": "sent", "delivery": {"kind": "magic_link_email", "to": "a@b.test"}}
        ),
    )
    attempts = 0

    async def deliver(_d: Delivery) -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("smtp down")

    r = call(api.adapter(deliver=deliver), "POST", "/magic-link", cookie=pre_auth())

    assert r.status == 502
    assert attempts == 1


def test_without_deliver_the_api_sends_the_message(api: FakeApi) -> None:
    api.on("POST", "/magic-link", respond(200, {"message": "sent"}))

    call(api.adapter(), "POST", "/magic-link", cookie=pre_auth())

    recorded = api.calls_to("POST", "/magic-link")[0]
    assert "x-seamless-auth-delivery-mode" not in recorded.headers
    assert service_claims(recorded)["sub"] == PROXY_SUBJECT


def test_upstream_failures_pass_through(api: FakeApi) -> None:
    api.on("POST", "/login", respond(400, {"error": "invalid_request", "details": {"issues": []}}))
    adapter = api.adapter()

    r = call(adapter, "POST", "/login", body="{}")
    assert r.status == 400
    assert r.body["error"] == "invalid_request" and isinstance(r.body["details"], dict)

    api.on("POST", "/login", lambda _r: httpx2.Response(429, text="Too many requests"))
    r = call(adapter, "POST", "/login", body="{}")
    assert r.status == 429
    assert r.body["error"] == "upstream_error"


def test_downloads_stream_unparsed(api: FakeApi) -> None:
    api.on(
        "GET",
        "/admin/auth-events/export",
        lambda _r: httpx2.Response(
            200,
            content=b'{"a":1}\n{"b":2}\n',
            headers={
                "content-type": "application/x-ndjson",
                "content-disposition": 'attachment; filename="events.ndjson"',
            },
        ),
    )

    r = call(api.adapter(), "GET", "/admin/auth-events/export?from=x", cookie=access())

    assert r.status == 200
    assert r.text == '{"a":1}\n{"b":2}\n'
    assert "content-disposition" in r.headers
    assert api.calls_to("GET", "/admin/auth-events/export")[0].query == "from=x"


@pytest.mark.parametrize(
    "path",
    [
        "/no-such-route",
        "/admin/users/..",
        "/admin/users/%2E%2E",
        "/admin/users/%2e",
        "/admin/users/%zz",
        "/admin/users/%+1",
    ],
)
def test_unknown_routes_and_dot_segments_are_404(api: FakeApi, path: str) -> None:
    r = call(api.adapter(), "GET", path, cookie=access())
    assert r.status == 404
    assert not api.calls_to("GET", "/admin/users")


def test_parameters_are_re_escaped_upstream(api: FakeApi) -> None:
    api.on("GET", "/admin/users/a%2Fb%3Fc", respond(200, {"ok": True}))

    r = call(api.adapter(), "GET", "/admin/users/a%2Fb%3Fc", cookie=access())

    assert r.status == 200, r.text


def test_an_oversized_body_is_413(api: FakeApi) -> None:
    from seamless_auth import AuthRequest, Headers

    res = api.adapter().handle(
        AuthRequest(
            "POST",
            "/login",
            headers=Headers([("content-type", "application/json")]),
            body_too_large=True,
        )
    )

    assert res.status == 413
    assert not api.calls_to("POST", "/login")
    assert MAX_BODY_BYTES == 1 << 20


def test_a_body_that_is_not_json_is_refused_before_anything_is_spent(api: FakeApi) -> None:
    adapter = api.adapter(insecure_cookies=True)
    # What a cross-site form with enctype="text/plain" sends.
    forged = '{"code":"attacker","state":"attacker","x":"="}'

    for content_type, cookie in [
        ("text/plain", None),
        (None, None),
        ("application/x-www-form-urlencoded", None),
        ("text/plain", REFRESH),
    ]:
        path = "/users/credentials" if cookie else "/oauth/mock/callback"
        r = call(adapter, "POST", path, body=forged, content_type=content_type, cookie=cookie)
        assert r.status == 415, (content_type, r.text)
    assert not api.calls_to("POST", "/oauth/mock/callback")
    assert not api.calls_to("POST", "/refresh"), "a refused body must not spend the refresh token"

    api.on("POST", "/oauth/mock/callback", respond(400, {"error": "invalid_request"}))
    r = call(
        adapter,
        "POST",
        "/oauth/mock/callback",
        body="{}",
        content_type="application/json; charset=utf-8",
    )
    assert r.status == 400
    api.on("GET", "/users/me", respond(200, {"user": {}}))
    assert call(adapter, "GET", "/users/me", cookie=access()).status == 200


def test_cross_site_state_changes_are_blocked(api: FakeApi) -> None:
    adapter = api.adapter(allowed_origins=["https://app.example"])

    assert (
        call(adapter, "POST", "/login", body="{}", headers={"sec-fetch-site": "cross-site"}).status
        == 403
    )
    assert (
        call(
            adapter, "POST", "/login", body="{}", headers={"origin": "https://evil.example"}
        ).status
        == 403
    )
    assert call(adapter, "POST", "/login", body="{}", headers={"origin": "null"}).status == 403

    api.on("POST", "/login", respond(400, {"error": "invalid_request"}))
    r = call(adapter, "POST", "/login", body="{}", headers={"origin": "https://APP.example"})
    assert r.status == 400


def test_the_live_manifest_adds_routes(api: FakeApi) -> None:
    api.manifest = {
        "schemaVersion": 1,
        "routes": [{"method": "GET", "path": "/brand-new/{id}", "credential": "access"}],
    }
    api.on("GET", "/brand-new/a%20b", respond(200, {"fresh": True}))
    adapter = api.adapter(disable_manifest_fetch=False)

    for _ in range(2):
        r = call(adapter, "GET", "/brand-new/a%20b", cookie=access())
        assert r.status == 200, r.text
        assert r.body["fresh"] is True
    assert len(api.calls_to("GET", "/.well-known/seamless-adapter.json")) == 1


def test_a_manifest_with_unknown_effects_is_refused_for_the_bundled_one(
    api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    api.manifest = {
        "schemaVersion": 1,
        "routes": [{"method": "GET", "path": "/brand-new", "credential": "superuser"}],
    }
    adapter = api.adapter(disable_manifest_fetch=False)

    with caplog.at_level(logging.WARNING, logger="seamless_auth"):
        assert call(adapter, "GET", "/brand-new", cookie=access()).status == 404
    api.on("GET", "/users/me", respond(200, {"user": {}}))
    assert call(adapter, "GET", "/users/me", cookie=access()).status == 200, (
        "the bundled manifest still serves"
    )


def test_forwards_the_client_address_and_user_agent(api: FakeApi) -> None:
    api.on("POST", "/login", respond(400, {"error": "x"}))
    adapter = api.adapter(resolve_client_ip=TrustedProxies(["192.0.2.1"]))

    call(
        adapter,
        "POST",
        "/login",
        body="{}",
        peer="192.0.2.1",
        headers={"x-forwarded-for": "6.6.6.6, 203.0.113.50", "user-agent": "b" * 600},
    )

    recorded = api.calls_to("POST", "/login")[0]
    assert recorded.headers["x-seamless-client-ip"] == "203.0.113.50"
    assert len(recorded.headers["x-seamless-client-user-agent"]) == 512
    service = service_claims(recorded)
    assert service["sub"] == PROXY_SUBJECT and service["iss"] == "seamless-portal-api"


def test_without_a_resolver_the_peer_is_the_client(api: FakeApi) -> None:
    api.on("POST", "/login", respond(400, {"error": "x"}))

    call(
        api.adapter(),
        "POST",
        "/login",
        body="{}",
        peer="::ffff:198.51.100.7",
        headers={"x-forwarded-for": "6.6.6.6"},
    )

    assert api.calls_to("POST", "/login")[0].headers["x-seamless-client-ip"] == "198.51.100.7"


def test_redirects_from_the_api_are_not_followed() -> None:
    api = FakeApi()
    api.on(
        "POST",
        "/login",
        lambda _r: httpx2.Response(307, headers={"location": f"{API_URL}/elsewhere"}),
    )
    # The default client, not the test one: it is the default that must not follow.
    adapter = Adapter(
        auth_server_url=API_URL,
        cookie_secret=TEST_SECRET,
        service_secret=TEST_SERVICE,
        jwks_kid="test-main",
        disable_manifest_fetch=True,
    )
    adapter._client = httpx2.Client(transport=httpx2.MockTransport(api.handle))
    adapter._jwks._client = adapter._client

    r = call(adapter, "POST", "/login", body="{}")

    assert r.status == 307
    assert not api.calls_to("POST", "/elsewhere")


def test_cookies_only_count_in_their_own_slot(api: FakeApi) -> None:
    api.on("GET", "/users/me", respond(200, {"user": {"id": "u1"}}))
    adapter = api.adapter()

    r = call(
        adapter,
        "GET",
        "/users/me",
        cookie=raw_cookie("seamless-access", "ephemeral", {"sub": "u1", "token": "pre-auth"}),
    )
    assert r.status == 401
    assert not api.calls_to("GET", "/users/me")

    r = call(
        adapter,
        "GET",
        "/users/me",
        cookie=raw_cookie("seamless-refresh", "access", {"sub": "u1", "refreshToken": "r1"}),
    )
    assert r.status == 401
    assert not api.calls_to("POST", "/refresh")

    r = call(
        adapter,
        "POST",
        "/totp/verify-login",
        body="{}",
        cookie=raw_cookie("seamless-ephemeral", "access", {"sub": "u1", "token": "t"}),
    )
    assert r.status == 401
    assert not api.calls_to("POST", "/totp/verify-login")


def test_a_pre_auth_route_never_refreshes(api: FakeApi) -> None:
    r = call(api.adapter(), "POST", "/totp/verify-login", body="{}", cookie=REFRESH)
    assert r.status == 401
    assert not api.calls_to("POST", "/refresh")


@pytest.mark.parametrize("ttl", [0, -5, "soon", 1.5, None, True])
def test_an_unusable_ttl_is_refused(api: FakeApi, ttl: Any) -> None:
    api.on("POST", "/totp/verify-login", respond(200, {**session(), "ttl": ttl}))

    r = call(api.adapter(), "POST", "/totp/verify-login", body="{}", cookie=pre_auth())

    assert r.status == 502
    assert not r.cookies


def test_upstream_errors_are_logged_without_the_url(caplog: pytest.LogCaptureFixture) -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused", request=request)

    adapter = FakeApi().adapter(http_client=httpx2.Client(transport=httpx2.MockTransport(refuse)))
    with caplog.at_level(logging.WARNING, logger="seamless_auth"):
        r = call(adapter, "GET", "/magic-link/verify/secret-token?code=abc")

    assert r.status == 502
    assert "secret-token" not in caplog.text and "code=abc" not in caplog.text


@pytest.mark.parametrize(
    "options",
    [
        {"cookie_secret": "short"},
        {"service_secret": "short"},
        {"auth_server_url": ""},
        {"auth_server_url": "ftp://a"},
        {"cookie_domain": "a.example; Secure"},
        {"access_cookie_name": "bad name"},
        {"same_site": "Sometimes"},
    ],
)
def test_construction_refuses_weak_or_missing_configuration(options: dict[str, Any]) -> None:
    settings = {
        "auth_server_url": "https://a",
        "cookie_secret": TEST_SECRET,
        "service_secret": TEST_SERVICE,
        **options,
    }
    with pytest.raises(ValueError, match="seamless-auth"):
        Adapter(**settings)


@pytest.mark.parametrize(
    ("content_type", "want"),
    [
        (None, True),
        ("application/json", True),
        ("application/json; charset=utf-8", True),
        ("Application/JSON", True),
        ("application/problem+json", True),
        ("application/x-ndjson", False),
        ("application/jsonl", False),
        ("text/csv", False),
        ("text/plain", False),
        ("application/json/extra", False),
    ],
)
def test_json_content_types(content_type: str | None, want: bool) -> None:
    assert _is_json_content_type(content_type) is want


def test_repr_redacts_credentials() -> None:
    from seamless_auth import User
    from seamless_auth._delivery import parse_delivery

    delivery = parse_delivery(
        {
            "kind": "otp_email",
            "to": "a@b.test",
            "token": "123456",
            "magicLinkUrl": "https://x/verify/secret",
        }
    )
    assert "123456" not in repr(delivery) and "secret" not in repr(delivery)
    assert "live-access-token" not in repr(User(id="u1", token="live-access-token"))
    assert TEST_SECRET not in repr(FakeApi().adapter())
    assert json.dumps({"ok": True})


def test_a_compressed_download_reaches_the_client_decoded(api: FakeApi) -> None:
    import gzip

    api.on(
        "GET",
        "/admin/auth-events/export",
        lambda _r: httpx2.Response(
            200,
            stream=httpx2.ByteStream(gzip.compress(b"line1\nline2\n")),
            headers={"content-type": "application/x-ndjson", "content-encoding": "gzip"},
        ),
    )

    r = call(api.adapter(), "GET", "/admin/auth-events/export", cookie=access())

    assert r.text == "line1\nline2\n"
    assert "content-encoding" not in r.headers


def test_httpx_request_logs_carry_no_upstream_path_or_query(
    api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    api.on("GET", "/magic-link/verify/SECRETTOKEN", respond(200, {"message": "ok"}))
    adapter = api.adapter()
    with caplog.at_level(logging.INFO, logger="httpx2"):
        call(adapter, "GET", "/magic-link/verify/SECRETTOKEN?code=OAUTHCODE")
        logging.getLogger("httpx2").info(
            "HTTP Request: %s %s", "GET", httpx2.URL("https://other.test/x?y=1")
        )

    assert "SECRETTOKEN" not in caplog.text and "OAUTHCODE" not in caplog.text
    assert f"{API_URL}/[redacted]" in caplog.text
    assert "https://other.test/x?y=1" in caplog.text, "only this adapter's calls are redacted"


def test_header_bytes_that_cannot_be_forwarded_never_fail_a_request(api: FakeApi) -> None:
    api.on("DELETE", "/logout", respond(200, {}))
    adapter = api.adapter()

    r = call(adapter, "DELETE", "/logout", cookie=access(), headers={"user-agent": "café/1"})
    assert r.status == 204
    assert r.cleared("seamless-access")
    assert "x-seamless-client-user-agent" not in api.calls_to("DELETE", "/logout")[0].headers

    r = call(
        adapter,
        "GET",
        "/users/me",
        headers={"x-seamless-auth-transport": "bearer", "authorization": "Bearer té"},
    )
    assert r.status == 401

    r = call(adapter, "GET", "/admin/users?q=\x01" + "x" * 70000, cookie=access())
    assert r.status in (404, 502), r.status


def test_an_unexpected_error_answers_500_without_details(
    api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    adapter = api.adapter()

    def explode() -> None:
        raise RuntimeError("secret detail")

    adapter._manifest.get = explode  # type: ignore[method-assign,assignment]
    with caplog.at_level(logging.ERROR, logger="seamless_auth"):
        r = call(adapter, "GET", "/users/me", cookie=access())

    assert r.status == 500
    assert r.body == {"error": "internal_error"}
    assert "secret detail" not in caplog.text


def test_a_sync_callback_returning_a_coroutine_is_awaited(api: FakeApi) -> None:
    api.on(
        "POST",
        "/magic-link",
        respond(
            200, {"message": "sent", "delivery": {"kind": "magic_link_email", "to": "a@b.test"}}
        ),
    )
    got: list[Delivery] = []

    async def send(delivery: Delivery) -> None:
        got.append(delivery)

    # A sync callable that returns a coroutine, which an iscoroutinefunction check misses.
    returns_coroutine = lambda d: send(d)  # noqa: E731, PLW0108
    r = call(api.adapter(deliver=returns_coroutine), "POST", "/magic-link", cookie=pre_auth())

    assert r.status == 200
    assert got[0].to == "a@b.test"


def test_config_repr_hides_the_secrets(api: FakeApi) -> None:
    text = repr(api.adapter().config)
    assert TEST_SECRET not in text and TEST_SERVICE not in text


def test_a_client_without_a_timeout_gets_one(api: FakeApi) -> None:
    adapter = api.adapter(
        # The point of the test: a client with no timeout.
        http_client=httpx2.Client(transport=httpx2.MockTransport(api.handle), timeout=None)
    )
    assert adapter._timeout == {"timeout": 15.0}
    # The test client keeps httpx2's default timeout, so it is left alone.
    assert api.adapter()._timeout == {}
