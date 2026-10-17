from __future__ import annotations

import pytest
from conftest import FakeApi, call, pre_auth, raw_cookie, respond

VERIFY = "/magic-link/verify/abc"


def test_verify_forwards_the_client_bearer(api: FakeApi) -> None:
    api.on("GET", VERIFY, respond(200, {"message": "Success"}))

    r = call(
        api.adapter(),
        "GET",
        VERIFY,
        headers={"x-seamless-auth-transport": "bearer", "authorization": "Bearer pre-auth"},
    )

    assert r.status == 200, r.text
    assert api.calls_to("GET", VERIFY)[0].headers["authorization"] == "Bearer pre-auth"


def test_verify_forwards_a_valid_pre_auth_cookie_as_bearer(api: FakeApi) -> None:
    api.on("GET", VERIFY, respond(200, {"message": "Success"}))

    r = call(api.adapter(), "GET", VERIFY, cookie=pre_auth())

    assert r.status == 200, r.text
    assert api.calls_to("GET", VERIFY)[0].headers["authorization"] == "Bearer pre-auth"


@pytest.mark.parametrize(
    ("cookie", "headers"),
    [
        (None, None),
        ("seamless-ephemeral=not-a-signed-cookie", None),
        (raw_cookie("seamless-ephemeral", "access", {"sub": "u1", "token": "t"}), None),
        (None, {"x-seamless-auth-transport": "bearer"}),
    ],
    ids=["no cookie", "altered cookie", "wrong kind", "bearer without token"],
)
def test_verify_without_a_usable_pre_auth_sends_no_authorization(
    api: FakeApi, cookie: str | None, headers: dict[str, str] | None
) -> None:
    api.on("GET", VERIFY, respond(200, {"message": "Success"}))

    r = call(api.adapter(), "GET", VERIFY, cookie=cookie, headers=headers)

    assert r.status == 200, r.text
    calls = api.calls_to("GET", VERIFY)
    assert len(calls) == 1
    assert "authorization" not in calls[0].headers


def test_confirmation_required_passes_through(api: FakeApi) -> None:
    body = {
        "error": "confirmation_required",
        "message": "Confirm this sign-in",
        "requestedFrom": {"deviceClass": "desktop", "requestedAt": "2026-10-16T12:00:00.000Z"},
    }
    api.on("GET", VERIFY, respond(409, body))

    r = call(api.adapter(), "GET", VERIFY)

    assert r.status == 409
    assert r.body == body


def test_confirm_is_proxied_without_a_credential(api: FakeApi) -> None:
    api.on("POST", f"{VERIFY}/confirm", respond(200, {"message": "Success"}))

    r = call(api.adapter(), "POST", f"{VERIFY}/confirm")

    assert r.status == 200, r.text
    assert r.body == {"message": "Success"}
    calls = api.calls_to("POST", f"{VERIFY}/confirm")
    assert len(calls) == 1
    assert "authorization" not in calls[0].headers


def test_a_check_without_tokens_sets_no_cookies(api: FakeApi) -> None:
    api.on("GET", "/magic-link/check", respond(200, {"message": "Success"}))

    r = call(api.adapter(), "GET", "/magic-link/check", cookie=pre_auth())

    assert r.status == 200, r.text
    assert r.body == {"message": "Success"}
    assert not r.cookies
