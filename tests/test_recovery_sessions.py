"""Recovery sessions: the guard, and refreshing once a factor is enrolled."""

from __future__ import annotations

from typing import Any

import httpx2
import pytest
from conftest import FakeApi, api_token, call, respond, session, signed_cookie

from seamless_auth import EnrollmentRequired, Unauthenticated

# Recovery sessions in the guard.


def recovery_cookie() -> tuple[str, str]:
    token = api_token("u1", "access", sid="s-1", recovery=True)
    return ("cookie", signed_cookie("seamless-access", {"sub": "u1", "token": token}))


def test_the_guard_refuses_a_recovery_session_from_the_cookie(api: FakeApi) -> None:
    adapter = api.adapter()

    with pytest.raises(EnrollmentRequired):
        adapter.authenticate([recovery_cookie()])
    with pytest.raises(Unauthenticated):
        adapter.authenticate_request("GET", [recovery_cookie()])

    user = adapter.authenticate([recovery_cookie()], allow_recovery=True)
    assert (user.id, user.recovery) == ("u1", True)


def test_the_guard_refuses_a_recovery_session_from_a_bearer_token(api: FakeApi) -> None:
    adapter = api.adapter()
    headers = [("authorization", f"Bearer {api_token('u1', 'access', recovery=True)}")]

    with pytest.raises(EnrollmentRequired):
        adapter.authenticate(headers)
    assert adapter.authenticate_request("POST", headers, allow_recovery=True).recovery


@pytest.mark.parametrize("claim", [False, "true", 1, None])
def test_only_a_literal_true_makes_a_recovery_session(api: FakeApi, claim: Any) -> None:
    extra = {} if claim is None else {"recovery": claim}
    token = api_token("u1", "access", **extra)
    cookie = ("cookie", signed_cookie("seamless-access", {"sub": "u1", "token": token}))
    adapter = api.adapter()

    assert adapter.authenticate([cookie]).recovery is False
    assert adapter.authenticate([("authorization", f"Bearer {token}")]).recovery is False


# Refreshing after enrollment from a recovery session.

ENROLLMENT = [
    ("POST", "/webauthn/register/finish"),
    ("POST", "/totp/enroll/verify"),
]
REFRESH = signed_cookie("seamless-refresh", {"sub": "u1", "refreshToken": "r1"})


@pytest.mark.parametrize(("method", "path"), ENROLLMENT)
def test_enrolling_from_a_recovery_session_refreshes_the_cookies(
    api: FakeApi, method: str, path: str
) -> None:
    api.on(method, path, respond(200, {"message": "Success"}))
    api.on("POST", "/refresh", respond(200, session()))

    r = call(api.adapter(), method, path, body="{}", cookie=f"{recovery_cookie()[1]}; {REFRESH}")

    assert r.status == 200, r.text
    assert r.body == {"message": "Success"}
    assert "seamless-access" in r.cookies and "seamless-refresh" in r.cookies
    refreshed = api.calls_to("POST", "/refresh")
    assert len(refreshed) == 1
    assert refreshed[0].headers["authorization"] == "Bearer r1"


def test_enrolling_from_a_full_session_does_not_refresh(api: FakeApi) -> None:
    api.on("POST", "/webauthn/register/finish", respond(200, {"message": "Success"}))
    token = api_token("u1", "access", sid="s-1")
    cookie = signed_cookie("seamless-access", {"sub": "u1", "token": token})

    r = call(
        api.adapter(), "POST", "/webauthn/register/finish", body="{}", cookie=f"{cookie}; {REFRESH}"
    )

    assert r.status == 200
    assert not r.cookies
    assert not api.calls_to("POST", "/refresh")


def test_a_failed_enrollment_does_not_refresh(api: FakeApi) -> None:
    api.on("POST", "/totp/enroll/verify", respond(400, {"error": "invalid_code"}))

    r = call(
        api.adapter(),
        "POST",
        "/totp/enroll/verify",
        body="{}",
        cookie=f"{recovery_cookie()[1]}; {REFRESH}",
    )

    assert (r.status, r.body) == (400, {"error": "invalid_code"})
    assert not api.calls_to("POST", "/refresh")


def test_a_failed_refresh_after_enrollment_keeps_the_enrollment(api: FakeApi) -> None:
    api.on("POST", "/webauthn/register/finish", respond(200, {"message": "Success"}))
    api.on("POST", "/refresh", respond(401, {"error": "invalid_refresh_token"}))

    r = call(
        api.adapter(),
        "POST",
        "/webauthn/register/finish",
        body="{}",
        cookie=f"{recovery_cookie()[1]}; {REFRESH}",
    )

    assert r.status == 200
    assert not r.cookies


def test_enrolling_after_a_silent_refresh_rotates_from_the_new_refresh_token(
    api: FakeApi,
) -> None:
    recovery_session = {**session(), "token": api_token("u1", "access", sid="s-1", recovery=True)}
    answers = [recovery_session, {**session(), "refreshToken": "refresh-2"}]
    api.on("POST", "/refresh", lambda _r: httpx2.Response(200, json=answers.pop(0)))
    api.on("POST", "/webauthn/register/finish", respond(200, {"message": "Success"}))

    r = call(api.adapter(), "POST", "/webauthn/register/finish", body="{}", cookie=REFRESH)

    assert r.status == 200, r.text
    refreshed = api.calls_to("POST", "/refresh")
    assert [c.headers["authorization"] for c in refreshed] == ["Bearer r1", "Bearer refresh-u1"]
    assert "seamless-access" in r.cookies and "seamless-refresh" in r.cookies


def test_a_bearer_client_refreshes_after_enrollment_itself(api: FakeApi) -> None:
    api.on("POST", "/webauthn/register/finish", respond(200, {"message": "Success"}))
    token = api_token("u1", "access", recovery=True)

    r = call(
        api.adapter(),
        "POST",
        "/webauthn/register/finish",
        body="{}",
        headers={"x-seamless-auth-transport": "bearer", "authorization": f"Bearer {token}"},
    )

    assert r.status == 200
    assert not api.calls_to("POST", "/refresh")
