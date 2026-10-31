from __future__ import annotations

from typing import Any

import pytest
from verify_only_support import (
    AUDIENCE,
    ISSUER,
    JWKS_URI,
    NOW,
    TOKENS,
    VECTORS,
    Provider,
    user_fields,
)

from seamless_auth import (
    BearerError,
    BearerRequest,
    Headers,
    ResourceServer,
    VerifiedUser,
    require_role,
    require_scope,
    require_step_up,
    role_grants_access,
)
from seamless_auth._resource_server import bearer_token


@pytest.mark.parametrize("vector", VECTORS["verify"], ids=lambda v: v["name"])
def test_verify_vectors(vector: dict[str, Any]) -> None:
    server = Provider().server(jwks_uri=JWKS_URI)
    token = TOKENS[vector["name"]]
    if vector["valid"]:
        assert user_fields(server.verify(token)) == vector["user"]
    else:
        with pytest.raises(BearerError) as err:
            server.verify(token)
        assert err.value.status == 401
        assert err.value.body == {"error": "invalid_token"}
        assert err.value.www_authenticate == 'Bearer error="invalid_token"'


def test_every_token_has_a_verify_vector() -> None:
    assert {v["name"] for v in VECTORS["verify"]} == set(TOKENS)


def test_the_vectors_verify_through_discovery_too() -> None:
    provider = Provider()
    server = provider.server()
    assert server.verify(TOKENS["user_passkey"]).sub == "user-123"
    with pytest.raises(BearerError):
        server.verify(TOKENS["wrong_aud"])
    assert provider.paths.count("/.well-known/openid-configuration") == 1


def test_the_user_keeps_the_token_and_its_times() -> None:
    user = Provider().server(jwks_uri=JWKS_URI).verify(TOKENS["user_passkey"])
    assert user.token == TOKENS["user_passkey"]
    assert user.verified_at == NOW
    assert user.exp > NOW
    assert user.claims["client_id"] == "app-web"
    assert TOKENS["user_passkey"] not in repr(user)


def test_discovery_happens_once() -> None:
    provider = Provider()
    server = provider.server()
    for name in ("user_passkey", "user_otp", "client_credentials"):
        server.verify(TOKENS[name])
    assert provider.paths.count("/.well-known/openid-configuration") == 1
    assert provider.paths.count("/jwks") == 1


def test_an_issuer_with_a_trailing_slash_is_discovered_without_it_and_compared_with_it() -> None:
    provider = Provider(discovery={"issuer": f"{ISSUER}/", "jwks_uri": JWKS_URI})
    server = provider.server(issuer=f"{ISSUER}/")
    assert server.verify(TOKENS["iss_trailing_slash"]).sub == "user-456"
    with pytest.raises(BearerError):
        server.verify(TOKENS["user_otp"])
    assert provider.paths[0] == "/.well-known/openid-configuration"


@pytest.mark.parametrize(
    "discovery",
    [
        {"issuer": "https://evil.example.test", "jwks_uri": JWKS_URI},
        {"issuer": f"{ISSUER}/", "jwks_uri": JWKS_URI},
        {"jwks_uri": JWKS_URI},
        {"issuer": ISSUER},
        {"issuer": ISSUER, "jwks_uri": 7},
        {"issuer": ISSUER, "jwks_uri": "ftp://login.example.test/jwks"},
        {"issuer": ISSUER, "jwks_uri": "/jwks"},
        {"issuer": ISSUER, "jwks_uri": "http://login.example.test/jwks"},
        [],
        "not an object",
    ],
)
def test_a_bad_discovery_document_is_invalid_token(discovery: Any) -> None:
    provider = Provider(discovery=discovery)
    with pytest.raises(BearerError) as err:
        provider.server().verify(TOKENS["user_passkey"])
    assert err.value.error == "invalid_token"
    assert "/jwks" not in provider.paths


JWKS_URI_HTTP = "http://keys.test/jwks"


def test_an_http_jwks_uri_is_fine_under_an_http_issuer() -> None:
    import httpx2

    seen: list[str] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        if request.url.path == "/.well-known/openid-configuration":
            return httpx2.Response(
                200, json={"issuer": "http://login.test", "jwks_uri": JWKS_URI_HTTP}
            )
        return httpx2.Response(200, json=VECTORS["jwks"])

    client = httpx2.Client(transport=httpx2.MockTransport(handle))
    server = ResourceServer("http://login.test", AUDIENCE, http_client=client)
    with pytest.raises(BearerError):
        server.verify(TOKENS["user_passkey"])
    assert seen == ["http://login.test/.well-known/openid-configuration", JWKS_URI_HTTP]


def test_a_failed_discovery_is_401_and_retried_at_most_every_five_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1000.0]
    monkeypatch.setattr("seamless_auth._resource_server.time.monotonic", lambda: clock[0])
    provider = Provider(discovery_status=503)
    server = provider.server()
    for _ in range(3):
        with pytest.raises(BearerError) as err:
            server.verify(TOKENS["user_passkey"])
        assert err.value.status == 401
    assert provider.paths.count("/.well-known/openid-configuration") == 1

    clock[0] += 5
    provider.discovery_status = 200
    assert server.verify(TOKENS["user_passkey"]).sub == "user-123"
    assert provider.paths.count("/.well-known/openid-configuration") == 2


def test_an_unreachable_provider_is_401_not_500() -> None:
    def fail(_request: Any) -> Any:
        raise OSError("connection refused")

    import httpx2

    client = httpx2.Client(transport=httpx2.MockTransport(fail))
    server = ResourceServer(ISSUER, AUDIENCE, http_client=client)
    with pytest.raises(BearerError) as err:
        server.verify(TOKENS["user_passkey"])
    assert err.value.error == "invalid_token"


def test_a_jwks_failure_is_invalid_token() -> None:
    provider = Provider(jwks_status=500)
    with pytest.raises(BearerError) as err:
        provider.server().verify(TOKENS["user_passkey"])
    assert err.value.error == "invalid_token"


def test_a_large_discovery_document_is_refused() -> None:
    provider = Provider(
        discovery={"issuer": ISSUER, "jwks_uri": JWKS_URI, "pad": "x" * 300_000},
    )
    with pytest.raises(BearerError):
        provider.server().verify(TOKENS["user_passkey"])


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"issuer": "", "audience": AUDIENCE}, "issuer"),
        ({"issuer": "login.example.test", "audience": AUDIENCE}, "issuer"),
        ({"issuer": "ftp://login.example.test", "audience": AUDIENCE}, "issuer"),
        ({"issuer": "https://", "audience": AUDIENCE}, "issuer"),
        ({"issuer": ISSUER, "audience": ""}, "audience"),
        ({"issuer": ISSUER, "audience": None}, "audience"),
        ({"issuer": ISSUER, "audience": AUDIENCE, "jwks_uri": "/jwks"}, "jwks_uri"),
    ],
)
def test_construction_errors(options: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ResourceServer(**options)


def test_a_cnf_token_is_refused_without_a_hook() -> None:
    with pytest.raises(BearerError):
        Provider().server(jwks_uri=JWKS_URI).verify(TOKENS["cnf_bound"])


def test_the_confirmation_hook_accepts_a_cnf_token() -> None:
    seen: list[tuple[Any, BearerRequest | None]] = []

    def confirm(cnf: Any, request: BearerRequest | None) -> bool:
        seen.append((cnf, request))
        return True

    server = Provider().server(jwks_uri=JWKS_URI, confirm=confirm)
    request = BearerRequest("GET", Headers([("dpop", "proof")]), lambda: "https://api/x")
    user = server.authenticate(f"Bearer {TOKENS['cnf_bound']}", request)
    assert user.sub == "user-456"
    assert seen[0][0] == {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
    assert seen[0][1] is request
    assert request.url == "https://api/x"
    assert request.headers.get("DPoP") == "proof"


def test_a_token_without_cnf_never_reaches_the_hook() -> None:
    calls: list[Any] = []
    server = Provider().server(jwks_uri=JWKS_URI, confirm=lambda c, r: calls.append(c) or True)
    server.verify(TOKENS["user_otp"])
    assert calls == []


@pytest.mark.parametrize("answer", [False, None, 1, "yes"])
def test_the_hook_must_answer_true(answer: Any) -> None:
    server = Provider().server(jwks_uri=JWKS_URI, confirm=lambda c, r: answer)
    with pytest.raises(BearerError):
        server.verify(TOKENS["cnf_bound"])


def test_a_hook_that_raises_refuses_the_token() -> None:
    def confirm(cnf: Any, request: BearerRequest | None) -> bool:
        raise RuntimeError("no proof")

    with pytest.raises(BearerError):
        Provider().server(jwks_uri=JWKS_URI, confirm=confirm).verify(TOKENS["cnf_bound"])


def _segment(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_NESTED = _segment(b"[" * 100_000)
_NAN = _segment(b'{"alg":NaN}')
_NOT_UTF8 = _segment(bytes([0xFF]))


@pytest.mark.parametrize(
    "token",
    [
        "a.b.c",
        "..",
        f"{_NESTED}.e30.c2ln",
        f"{_NAN}.e30.c2ln",
        f"{_NOT_UTF8}.e30.c2ln",
        "e30.e30.c2ln=",
        "e30.e30.c2l+",
        "e30.e30.c2ln.",
    ],
)
def test_garbage_is_invalid_token_not_an_error(token: str) -> None:
    with pytest.raises(BearerError) as err:
        Provider().server(jwks_uri=JWKS_URI).verify(token)
    assert err.value.error == "invalid_token"


def test_a_short_signature_is_invalid_token() -> None:
    header, payload, _ = TOKENS["user_passkey"].split(".")
    with pytest.raises(BearerError):
        Provider().server(jwks_uri=JWKS_URI).verify(f"{header}.{payload}.AAAA")


def test_time_follows_the_clock() -> None:
    later = Provider().server(jwks_uri=JWKS_URI, clock=lambda: float(NOW + 7200))
    with pytest.raises(BearerError):
        later.verify(TOKENS["user_passkey"])


@pytest.mark.parametrize(
    ("header", "token"),
    [
        (None, None),
        ("", None),
        ("Bearer", None),
        ("Bearer a b", None),
        ("Basic a", None),
        ("Bearer a", "a"),
        ("bEaReR a", "a"),
        ("  Bearer \t a  ", "a"),
    ],
)
def test_bearer_token(header: str | None, token: str | None) -> None:
    assert bearer_token(header) == token


def _user(**claims: Any) -> VerifiedUser:
    base: dict[str, Any] = {"sub": "u", "client_id": "c", "verified_at": float(NOW)}
    return VerifiedUser(**{**base, **claims})


def test_require_scope_needs_every_scope() -> None:
    guard = require_scope("a", "b")
    guard.check(_user(scopes=("b", "a", "c")))
    with pytest.raises(BearerError) as err:
        guard.check(_user(scopes=("a",)))
    assert err.value.status == 403
    assert err.value.body == {"error": "insufficient_scope", "scope": "a b"}


def test_require_role_needs_any_role() -> None:
    require_role("admin", "billing:read").check(_user(roles=("billing:write",)))
    with pytest.raises(BearerError) as err:
        require_role("admin").check(_user(roles=("member",)))
    assert err.value.headers() == {}


def test_step_up_measures_max_age_with_no_leeway() -> None:
    guard = require_step_up(max_age=60)
    guard.check(_user(auth_time=NOW - 60))
    with pytest.raises(BearerError):
        guard.check(_user(auth_time=NOW - 61))


def test_step_up_reports_the_level_when_both_fail() -> None:
    with pytest.raises(BearerError) as err:
        require_step_up(acr_values=["phr"], max_age=10).check(_user(acr="x", auth_time=0))
    assert err.value.body["error_description"] == "A different authentication level is required"


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"max_age": -1},
        {"max_age": 1.5},
        {"max_age": True},
        {"acr_values": []},
        {"acr_values": "phr"},
        {"amr": []},
        {"amr": [""]},
    ],
)
def test_step_up_construction_errors(options: dict[str, Any]) -> None:
    with pytest.raises((ValueError, TypeError)):
        require_step_up(**options)


def test_scope_and_role_construction_errors() -> None:
    with pytest.raises(ValueError, match="at least one"):
        require_scope()
    with pytest.raises(ValueError, match="at least one"):
        require_role()
    with pytest.raises(ValueError, match="non-empty"):
        require_scope("")
    with pytest.raises(ValueError, match="non-empty"):
        require_role("admin", "")


@pytest.mark.parametrize(
    ("granted", "required", "expected"),
    [
        ("admin", "admin", True),
        ("billing:*", "billing", True),
        ("billing:*", "billing:invoices:read", True),
        ("billing:*", "users:read", False),
        ("billing", "billing:invoices", True),
        ("billing", "billingx:invoices", False),
        ("billing:invoices:write", "billing:invoices:read", True),
        ("billing:invoices:read", "billing:invoices:write", False),
        ("billing:write", "users:read", False),
        ("billing:invoices", "billing", False),
        ("", "admin", False),
        ("admin", "   ", False),
        (" admin ", "admin", True),
        ("admin", "user", False),
        ("a:b", "a:c", False),
    ],
)
def test_role_grants_access(granted: str, required: str, expected: bool) -> None:
    assert role_grants_access(granted, required) is expected
