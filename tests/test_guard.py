from __future__ import annotations

import jwt
import pytest
from conftest import (
    _KEY,
    API_URL,
    FakeApi,
    api_token,
    hs256_access_token,
    raw_cookie,
    sign_rs256,
    signed_cookie,
)

from seamless_auth import CrossSiteRequest, Unauthenticated


def bearer(token: str) -> tuple[str, str]:
    return ("authorization", f"Bearer {token}")


def cookie(value: str) -> tuple[str, str]:
    return ("cookie", value)


ACCESS = api_token("u1", "access")

CASES = [
    ("no credential", [], False),
    (
        "session cookie",
        [
            cookie(
                signed_cookie("seamless-access", {"sub": "u1", "token": ACCESS, "roles": ["user"]})
            )
        ],
        True,
    ),
    # Every cookie is signed with the same secret. The pre-auth cookie /login issues
    # for any existing account must not pass for a session, in the access slot or
    # out of it.
    (
        "pre-auth cookie in the access slot",
        [
            cookie(
                raw_cookie(
                    "seamless-access",
                    "ephemeral",
                    {"sub": "u1", "token": api_token("u1", "ephemeral")},
                )
            )
        ],
        False,
    ),
    (
        "pre-auth cookie in its own slot",
        [
            cookie(
                signed_cookie(
                    "seamless-ephemeral", {"sub": "u1", "token": api_token("u1", "ephemeral")}
                )
            )
        ],
        False,
    ),
    (
        "refresh cookie in the access slot",
        [cookie(raw_cookie("seamless-access", "refresh", {"sub": "u1", "refreshToken": "r1"}))],
        False,
    ),
    (
        "access-kind cookie holding an ephemeral token",
        [
            cookie(
                signed_cookie(
                    "seamless-access", {"sub": "u1", "token": api_token("u1", "ephemeral")}
                )
            )
        ],
        False,
    ),
    (
        "access-kind cookie with no token",
        [cookie(signed_cookie("seamless-access", {"sub": "u1"}))],
        False,
    ),
    ("forged cookie", [cookie("seamless-access=a.b.c")], False),
    (
        "cookie wins over a valid bearer token",
        [cookie("seamless-access=a.b.c"), bearer(ACCESS)],
        False,
    ),
    ("access token", [bearer(ACCESS)], True),
    # An ephemeral sign-in token is signed by the same key and must not pass.
    ("ephemeral token", [bearer(api_token("u1", "ephemeral"))], False),
    (
        "token for another audience",
        [
            bearer(
                sign_rs256(
                    {"sub": "u1", "typ": "access", "iss": API_URL, "aud": "https://elsewhere"}
                )
            )
        ],
        False,
    ),
    (
        "token from another issuer",
        [
            bearer(
                sign_rs256(
                    {"sub": "u1", "typ": "access", "iss": "https://elsewhere", "aud": API_URL}
                )
            )
        ],
        False,
    ),
    (
        "audience as an array",
        [
            bearer(
                sign_rs256(
                    {"sub": "u1", "typ": "access", "iss": API_URL, "aud": ["other", API_URL]}
                )
            )
        ],
        True,
    ),
    (
        "expired token",
        [
            bearer(
                sign_rs256(
                    {"sub": "u1", "typ": "access", "iss": API_URL, "aud": API_URL, "exp": 1_000_000}
                )
            )
        ],
        False,
    ),
    ("HS256 token under the cookie secret", [bearer(hs256_access_token())], False),
    ("unsigned token", [bearer("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.")], False),
]


@pytest.mark.parametrize(("name", "headers", "ok"), CASES, ids=[c[0] for c in CASES])
def test_authenticate(api: FakeApi, name: str, headers: list[tuple[str, str]], ok: bool) -> None:
    adapter = api.adapter()
    if ok:
        user = adapter.authenticate(headers)
        assert user.id == "u1"
    else:
        with pytest.raises(Unauthenticated):
            adapter.authenticate(headers)


def test_a_cookie_session_is_refused_for_cross_site_state_changes(api: FakeApi) -> None:
    adapter = api.adapter()
    session_cookie = cookie(signed_cookie("seamless-access", {"sub": "u1", "token": ACCESS}))

    with pytest.raises(CrossSiteRequest):
        adapter.authenticate_request("POST", [session_cookie, ("sec-fetch-site", "cross-site")])
    assert (
        adapter.authenticate_request("POST", [session_cookie, ("sec-fetch-site", "same-origin")]).id
        == "u1"
    )
    assert (
        adapter.authenticate_request("GET", [session_cookie, ("sec-fetch-site", "cross-site")]).id
        == "u1"
    )
    # A bearer token is never attached by a browser, so it needs no such check.
    assert (
        adapter.authenticate_request("POST", [bearer(ACCESS), ("sec-fetch-site", "cross-site")]).id
        == "u1"
    )


def test_the_key_set_is_fetched_once(api: FakeApi) -> None:
    adapter = api.adapter()
    for _ in range(3):
        adapter.authenticate([bearer(ACCESS)])
    assert len(api.calls_to("GET", "/.well-known/jwks.json")) == 1


def test_an_unknown_kid_refetches_at_most_once_per_interval(api: FakeApi) -> None:
    adapter = api.adapter()
    adapter.authenticate([bearer(ACCESS)])
    for kid in ("x1", "x2", "x3"):
        token = jwt.encode(
            {"sub": "u1", "typ": "access", "iss": API_URL, "aud": API_URL, "exp": 2_000_000_000},
            _KEY,
            algorithm="RS256",
            headers={"kid": kid},
        )
        with pytest.raises(Unauthenticated):
            adapter.authenticate([bearer(token)])
    assert len(api.calls_to("GET", "/.well-known/jwks.json")) == 1


def test_one_bad_key_does_not_take_the_key_set_down(api: FakeApi) -> None:
    import httpx2
    from conftest import JWKS

    def jwks(_req: httpx2.Request) -> httpx2.Response:
        bad = [{"kty": "RSA", "kid": "bad"}, {"kty": "RSA", "kid": "worse", "n": "!!", "e": "AQAB"}]
        return httpx2.Response(200, json={"keys": bad + JWKS["keys"]})

    original = api.handle

    def handle(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/.well-known/jwks.json":
            return jwks(request)
        return original(request)

    adapter = api.adapter(http_client=httpx2.Client(transport=httpx2.MockTransport(handle)))
    assert adapter.authenticate([bearer(ACCESS)]).id == "u1"


def test_an_iat_from_a_clock_running_ahead_is_accepted(api: FakeApi) -> None:
    import time

    ahead = sign_rs256(
        {"sub": "u1", "typ": "access", "iss": API_URL, "aud": API_URL, "iat": int(time.time()) + 60}
    )
    assert api.adapter().authenticate([bearer(ahead)]).id == "u1"
