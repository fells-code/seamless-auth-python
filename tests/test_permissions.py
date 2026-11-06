"""The permission guard, through the real FastAPI and Django stacks.

Every row of the guard contract runs on each framework and on both transports, so a
difference between them fails here rather than in the conformance suite.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx2
import jwt
import pytest
from conftest import (
    _KEY,
    API_URL,
    JWKS,
    TEST_SECRET,
    TEST_SERVICE,
    FakeApi,
    api_token,
    respond,
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
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse, Response
from test_permissions_django_urls import GUARDS
from verify_only_support import TOKENS, Provider

from seamless_auth import (
    Adapter,
    CrossSiteRequest,
    EnrollmentRequired,
    InsufficientPermission,
    InsufficientRole,
    PermissionRule,
    PermissionsUnavailable,
    ResourceServer,
    Unauthenticated,
    User,
    VerifiedUser,
    require_permission,
    require_role,
)
from seamless_auth.django import _reset_adapter, _reset_resource_server, require_auth
from seamless_auth.fastapi import (
    PermissionHTTPException,
    RequireBearer,
    RequireUser,
    add_bearer_error_handler,
)

ORG = "6f1c2c9e-2c5e-4b7a-9d39-0d3f6a1f0a11"
OTHER_ORG = "0b4f3f0e-8a55-4b0a-8d6a-52c8c27c1e77"
LIVE = "/users/me/permissions"
DENIED = (403, {"error": "insufficient_permission"})
UNAVAILABLE = (503, {"error": "permissions_unavailable"})
ALLOWED = (200, {"id": "u1"})


def _route_template(route: str) -> str:
    return route.replace("<str:organization_id>", "{organization_id}").replace(
        "<uuid:organization_id>", "{organization_id:uuid}"
    )


def fastapi_app(adapter: Adapter) -> FastAPI:
    app = FastAPI()
    for route, options in GUARDS.items():
        guard = RequireUser(adapter, **options)

        def handler(user: User = Depends(guard)) -> dict[str, str]:  # noqa: B008
            return {"id": user.id}

        app.add_api_route(f"/sync/{_route_template(route)}", handler, methods=["GET", "POST"])
    return app


@dataclass
class Stack:
    """One framework's routes, and the bodies that framework gives the existing
    refusals, which the permission guard leaves as they are."""

    get: Callable[..., Any]
    prefix: str
    unauthenticated: dict[str, str]
    enrollment_required: dict[str, str]

    def status(self, route: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
        r = self.get(f"/{self.prefix}/{route}", headers=headers or {})
        return r.status_code, r.json()


@pytest.fixture(params=["fastapi", "django", "django-async"])
def stack(request: pytest.FixtureRequest, api: FakeApi) -> Iterator[Stack]:
    if request.param == "fastapi":
        client = TestClient(fastapi_app(api.adapter()), base_url="https://testserver")
        yield Stack(
            client.get, "sync", {"detail": "unauthenticated"}, {"detail": "enrollment_required"}
        )
        return
    options = {
        "auth_server_url": API_URL,
        "cookie_secret": TEST_SECRET,
        "service_secret": TEST_SERVICE,
        "jwks_kid": "test-main",
        "disable_manifest_fetch": True,
        "http_client": api.client(),
    }
    _reset_adapter()
    with override_settings(SEAMLESS_AUTH=options, ROOT_URLCONF="test_permissions_django_urls"):
        yield Stack(
            Client(enforce_csrf_checks=True).get,
            "async" if request.param == "django-async" else "sync",
            {"error": "unauthenticated"},
            {"error": "enrollment_required"},
        )
    _reset_adapter()


def bearer(**claims: Any) -> dict[str, str]:
    return {"authorization": f"Bearer {api_token('u1', 'access', **claims)}"}


def cookie(**claims: Any) -> dict[str, str]:
    token = api_token("u1", "access", **claims)
    return {"cookie": signed_cookie("seamless-access", {"sub": "u1", "token": token})}


@pytest.fixture(params=[bearer, cookie], ids=["bearer", "cookie"])
def session(request: pytest.FixtureRequest) -> Callable[..., dict[str, str]]:
    transport: Callable[..., dict[str, str]] = request.param
    return transport


def live_body(**fields: Any) -> dict[str, Any]:
    return {
        "roles": [],
        "permissions": [],
        "organizationId": None,
        "organizationRoles": [],
        "organizationPermissions": [],
        **fields,
    }


# Not authenticated, and recovery sessions.


@pytest.mark.parametrize("route", ["any", "all", "org", f"org/{ORG}", "empty"])
def test_no_session_is_the_existing_401(stack: Stack, route: str) -> None:
    assert stack.status(route) == (401, stack.unauthenticated)


def test_a_bad_token_is_the_existing_401(stack: Stack) -> None:
    assert stack.status("any", {"authorization": "Bearer nope"}) == (401, stack.unauthenticated)


def test_a_recovery_session_is_the_existing_rejection(
    stack: Stack, api: FakeApi, session: Callable[..., dict[str, str]]
) -> None:
    for omitted in ({"permissions": ["reports:read"]}, {"permissions_omitted": True}):
        assert stack.status("any", session(recovery=True, **omitted)) == (
            403,
            stack.enrollment_required,
        )
    assert api.calls_to("GET", LIVE) == []


def test_allow_recovery_still_checks_permissions(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    assert stack.status("recovery", session(recovery=True)) == DENIED
    allowed = session(recovery=True, permissions=["reports:read"])
    assert stack.status("recovery", allowed) == ALLOWED


# Modes.


def test_any_needs_one(stack: Stack, session: Callable[..., dict[str, str]]) -> None:
    assert stack.status("any", session(permissions=["reports:read"])) == ALLOWED
    assert stack.status("any", session(permissions=["reports:export", "x"])) == ALLOWED
    assert stack.status("any", session(permissions=["x"])) == DENIED
    assert stack.status("any", session()) == DENIED


def test_all_needs_every_one(stack: Stack, session: Callable[..., dict[str, str]]) -> None:
    assert stack.status("all", session(permissions=["reports:read"])) == DENIED
    both = ["reports:read", "reports:write"]
    assert stack.status("all", session(permissions=both)) == ALLOWED


def test_all_may_draw_from_either_claim(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    split = session(permissions=["reports:read"], org_id=ORG, org_permissions=["reports:write"])
    assert stack.status("all", split) == ALLOWED


def test_a_refusal_names_no_permissions(stack: Stack) -> None:
    r = stack.get(f"/{stack.prefix}/any", headers=bearer(permissions=["x"]))
    assert r.status_code == 403
    assert r.json() == DENIED[1]
    assert "reports" not in r.content.decode()


# Matching.


@pytest.mark.parametrize(
    "held",
    [
        "REPORTS:READ",
        "Reports:read",
        " reports:read",
        "reports:read ",
        "reports:*",
        "*",
        "reports",
        "reports:read:all",
        "reports:write",
    ],
)
def test_matching_is_exact(stack: Stack, session: Callable[..., dict[str, str]], held: str) -> None:
    assert stack.status("any", session(permissions=[held])) == DENIED


def test_a_role_is_not_a_permission(stack: Stack) -> None:
    assert stack.status("any", bearer(roles=["reports:read", "reports:*"])) == DENIED
    org_roles = bearer(org_id=ORG, org_roles=["reports:read"])
    assert stack.status("any", org_roles) == DENIED


# Scope.


def test_by_default_an_organization_permission_counts(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    held = session(org_id=ORG, org_permissions=["reports:read"])
    assert stack.status("any", held) == ALLOWED


def test_organization_scope_counts_only_organization_permissions(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    instance = session(org_id=ORG, permissions=["projects:write"])
    assert stack.status("org", instance) == DENIED
    org = session(org_id=ORG, org_permissions=["projects:write"])
    assert stack.status("org", org) == ALLOWED


@pytest.mark.parametrize(
    "claims",
    [{}, {"org_id": ""}, {"org_id": None}, {"org_id": 7}, {"org_id": ["x"]}],
    ids=["absent", "empty", "null", "number", "list"],
)
def test_organization_scope_needs_an_organization(
    stack: Stack, session: Callable[..., dict[str, str]], claims: dict[str, Any]
) -> None:
    headers = session(org_permissions=["projects:write"], **claims)
    assert stack.status("org", headers) == DENIED
    assert stack.status(f"org/{ORG}", headers) == DENIED


def test_organization_all_needs_every_one_from_the_organization(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    split = session(org_id=ORG, permissions=["projects:read"], org_permissions=["projects:write"])
    assert stack.status("org-all", split) == DENIED
    both = session(org_id=ORG, org_permissions=["projects:read", "projects:write"])
    assert stack.status("org-all", both) == ALLOWED


def test_a_bound_route_needs_that_organization(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    held = session(org_id=ORG, org_permissions=["projects:write"])
    assert stack.status(f"org/{ORG}", held) == ALLOWED
    assert stack.status(f"org/{OTHER_ORG}", held) == DENIED
    assert stack.status(f"org/{ORG.upper()}", held) == DENIED


def test_a_bound_route_counts_only_organization_permissions(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    held = session(org_id=ORG, permissions=["projects:write"])
    assert stack.status(f"org/{ORG}", held) == DENIED


def test_a_route_without_the_parameter_denies(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    held = session(org_id=ORG, org_permissions=["projects:write"])
    assert stack.status("unbound", held) == DENIED


def test_a_parsed_route_parameter_compares_as_its_text(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    held = session(org_id=ORG, org_permissions=["projects:write"])
    assert stack.status(f"org-uuid/{UUID(ORG)}", held) == ALLOWED
    assert stack.status(f"org-uuid/{UUID(OTHER_ORG)}", held) == DENIED


# An empty list.


@pytest.mark.parametrize("route", ["empty", "empty-all", "empty-org"])
def test_an_empty_list_never_opens_a_route(
    stack: Stack, api: FakeApi, session: Callable[..., dict[str, str]], route: str
) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["x"], organizationId=ORG)))
    held = session(permissions=["x"], org_id=ORG, org_permissions=["x"])
    assert stack.status(route, held) == DENIED
    assert stack.status(route, session(permissions_omitted=True, org_id=ORG)) == DENIED
    assert api.calls_to("GET", LIVE) == []


# Malformed claims.


@pytest.mark.parametrize(
    "value",
    ["reports:read", {"reports:read": True}, 1, True, None],
    ids=["string", "object", "number", "bool", "null"],
)
def test_a_claim_that_is_not_a_list_reads_as_empty(
    stack: Stack, session: Callable[..., dict[str, str]], value: Any
) -> None:
    assert stack.status("any", session(permissions=value)) == DENIED
    assert stack.status("org", session(org_id=ORG, org_permissions=value)) == DENIED


def test_entries_that_are_not_strings_are_ignored(
    stack: Stack, session: Callable[..., dict[str, str]]
) -> None:
    noisy = [1, None, {"a": 1}, ["reports:read"], True]
    assert stack.status("any", session(permissions=noisy)) == DENIED
    assert stack.status("any", session(permissions=[*noisy, "reports:read"])) == ALLOWED


@pytest.mark.parametrize("value", ["true", 1, [True], False, None])
def test_only_a_literal_true_means_omitted(
    stack: Stack, api: FakeApi, session: Callable[..., dict[str, str]], value: Any
) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["reports:read"])))
    assert stack.status("any", session(permissions_omitted=value)) == DENIED
    allowed = session(permissions_omitted=value, permissions=["reports:read"])
    assert stack.status("any", allowed) == ALLOWED
    assert api.calls_to("GET", LIVE) == []


# The live read.


def test_a_token_with_its_permissions_is_never_read_live(stack: Stack, api: FakeApi) -> None:
    assert stack.status("any", bearer(permissions=["reports:read"])) == ALLOWED
    assert api.calls_to("GET", LIVE) == []


def test_the_live_read_decides_when_omitted(
    stack: Stack, api: FakeApi, session: Callable[..., dict[str, str]]
) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["reports:read"])))
    omitted = session(permissions_omitted=True)
    assert stack.status("any", omitted) == ALLOWED
    assert stack.status("all", omitted) == DENIED


def test_the_live_read_ignores_what_the_token_says(stack: Stack, api: FakeApi) -> None:
    api.on("GET", LIVE, respond(200, live_body()))
    held = bearer(permissions_omitted=True, permissions=["reports:read"])
    assert stack.status("any", held) == DENIED


def test_the_live_read_sends_only_the_callers_token(stack: Stack, api: FakeApi) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["reports:read"])))
    token = api_token("u1", "access", permissions_omitted=True)

    assert stack.status("any", {"authorization": f"Bearer {token}"}) == ALLOWED

    [call] = api.calls_to("GET", LIVE)
    assert call.headers["authorization"] == f"Bearer {token}"
    assert "x-seamless-service-token" not in call.headers


def test_the_live_read_uses_the_token_inside_the_cookie(stack: Stack, api: FakeApi) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["reports:read"])))
    token = api_token("u1", "access", permissions_omitted=True)
    held = {"cookie": signed_cookie("seamless-access", {"sub": "u1", "token": token})}

    assert stack.status("any", held) == ALLOWED

    [call] = api.calls_to("GET", LIVE)
    assert call.headers["authorization"] == f"Bearer {token}"


def test_the_live_read_is_not_cached(stack: Stack, api: FakeApi) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=["reports:read"])))
    omitted = bearer(permissions_omitted=True)
    assert stack.status("any", omitted) == ALLOWED

    api.on("GET", LIVE, respond(200, live_body()))
    assert stack.status("any", omitted) == DENIED
    assert len(api.calls_to("GET", LIVE)) == 2


def test_the_live_read_goes_to_the_configured_server_only(stack: Stack, api: FakeApi) -> None:
    urls: list[str] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        urls.append(str(request.url))
        return httpx2.Response(200, json=live_body(permissions=["reports:read"]))

    api.on("GET", LIVE, record)
    claims = {"aud": API_URL, "auth_server_url": "http://evil.test"}
    assert stack.status("any", bearer(permissions_omitted=True, **claims)) == ALLOWED
    assert urls == [f"{API_URL}{LIVE}"]


def test_organization_scope_reads_the_live_organization(stack: Stack, api: FakeApi) -> None:
    omitted = bearer(permissions_omitted=True, org_id=ORG)

    api.on(
        "GET",
        LIVE,
        respond(200, live_body(organizationId=ORG, organizationPermissions=["projects:write"])),
    )
    assert stack.status("org", omitted) == ALLOWED
    assert stack.status(f"org/{ORG}", omitted) == ALLOWED
    assert stack.status(f"org/{OTHER_ORG}", omitted) == DENIED

    # The organization the live read names decides, not the one in the token.
    api.on(
        "GET",
        LIVE,
        respond(
            200, live_body(organizationId=OTHER_ORG, organizationPermissions=["projects:write"])
        ),
    )
    assert stack.status(f"org/{ORG}", omitted) == DENIED
    assert stack.status(f"org/{OTHER_ORG}", omitted) == ALLOWED

    api.on("GET", LIVE, respond(200, live_body(organizationPermissions=["projects:write"])))
    assert stack.status("org", omitted) == DENIED

    api.on("GET", LIVE, respond(200, live_body(organizationId=ORG, permissions=["projects:write"])))
    assert stack.status("org", omitted) == DENIED


def test_a_live_401_is_the_existing_401(stack: Stack, api: FakeApi) -> None:
    api.on("GET", LIVE, respond(401, {"error": "unauthorized"}))
    assert stack.status("any", bearer(permissions_omitted=True)) == (401, stack.unauthenticated)


@pytest.mark.parametrize("status", [204, 301, 302, 400, 403, 404, 429, 500, 502, 503])
def test_any_other_live_status_fails_closed(stack: Stack, api: FakeApi, status: int) -> None:
    api.on("GET", LIVE, lambda _req: httpx2.Response(status))
    assert stack.status("any", bearer(permissions_omitted=True)) == UNAVAILABLE


@pytest.mark.parametrize(
    "error",
    [httpx2.ReadTimeout("slow"), httpx2.ConnectTimeout("slow"), httpx2.ConnectError("down")],
    ids=["read-timeout", "connect-timeout", "connect-error"],
)
def test_an_unreachable_live_read_fails_closed(
    stack: Stack, api: FakeApi, error: Exception
) -> None:
    def fail(_req: httpx2.Request) -> httpx2.Response:
        raise error

    api.on("GET", LIVE, fail)
    assert stack.status("any", bearer(permissions_omitted=True)) == UNAVAILABLE


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"null",
        b"[]",
        b'"reports:read"',
        b"{}",
        b'{"permissions":["reports:read"]}',
        b'{"organizationPermissions":[]}',
        b'{"permissions":"reports:read","organizationPermissions":[]}',
        b'{"permissions":["reports:read"],"organizationPermissions":{}}',
        b'{"permissions":["reports:read"],"organizationPermissions":[],"organizationId":7}',
        b"x" * ((1 << 20) + 1),
    ],
    ids=[
        "empty",
        "text",
        "null",
        "array",
        "string",
        "no-fields",
        "no-org-permissions",
        "no-permissions",
        "permissions-string",
        "org-permissions-object",
        "org-id-number",
        "too-large",
    ],
)
def test_a_malformed_live_body_fails_closed(stack: Stack, api: FakeApi, content: bytes) -> None:
    api.on("GET", LIVE, lambda _req: httpx2.Response(200, content=content))
    assert stack.status("any", bearer(permissions_omitted=True)) == UNAVAILABLE


def test_entries_of_a_live_list_that_are_not_strings_are_ignored(
    stack: Stack, api: FakeApi
) -> None:
    api.on("GET", LIVE, respond(200, live_body(permissions=[1, None])))
    assert stack.status("any", bearer(permissions_omitted=True)) == DENIED
    api.on("GET", LIVE, respond(200, live_body(permissions=[1, "reports:read"])))
    assert stack.status("any", bearer(permissions_omitted=True)) == ALLOWED


def test_a_failed_live_read_is_logged_without_the_token(
    stack: Stack, api: FakeApi, caplog: pytest.LogCaptureFixture
) -> None:
    api.on("GET", LIVE, lambda _req: httpx2.Response(500))
    token = api_token("u1", "access", permissions_omitted=True)

    assert stack.status("any", {"authorization": f"Bearer {token}"}) == UNAVAILABLE

    assert "live permissions read answered 500" in caplog.text
    assert token not in caplog.text


# The user type.


def rule(*permissions: str, **options: Any) -> PermissionRule:
    return PermissionRule(permissions, **options)


def test_the_user_carries_the_claims(api: FakeApi) -> None:
    claims = {
        "permissions": ["reports:read", 1],
        "org_id": ORG,
        "org_roles": ["admin", None],
        "org_permissions": ["projects:write"],
    }
    for headers in (bearer(**claims), cookie(**claims)):
        user = api.adapter().authenticate(list(headers.items()))
        assert user.permissions == ("reports:read",)
        assert user.organization_id == ORG
        assert user.organization_roles == ("admin",)
        assert user.organization_permissions == ("projects:write",)
        assert user.permissions_omitted is False


def test_the_user_says_when_the_token_omits_them(api: FakeApi) -> None:
    for headers in (
        bearer(permissions_omitted=True, org_id=ORG),
        cookie(permissions_omitted=True, org_id=ORG),
    ):
        user = api.adapter().authenticate(list(headers.items()))
        assert user.permissions_omitted is True
        assert user.permissions == ()
        assert user.organization_id == ORG


def test_cookie_payload_claims_are_not_read(api: FakeApi) -> None:
    held = {
        "cookie": signed_cookie(
            "seamless-access",
            {
                "sub": "u1",
                "token": api_token("u1", "access"),
                "permissions": ["reports:read"],
                "org_id": ORG,
                "org_permissions": ["projects:write"],
                "permissions_omitted": True,
            },
        )
    }
    user = api.adapter().authenticate(list(held.items()))
    assert user.permissions == ()
    assert user.organization_permissions == ()
    assert user.organization_id is None
    assert user.permissions_omitted is False


def test_organization_roles_do_not_count_for_the_role_guard(api: FakeApi) -> None:
    headers = bearer(org_id=ORG, org_roles=["admin"], permissions=["admin"])
    with pytest.raises(InsufficientRole):
        api.adapter().authenticate(list(headers.items()), roles=["admin"])


# The core, without a framework.


def test_the_core_raises_what_the_bindings_answer(api: FakeApi) -> None:
    adapter = api.adapter()
    required = rule("reports:read")

    with pytest.raises(InsufficientPermission):
        adapter.authenticate(list(bearer().items()), permissions=required)

    api.on("GET", LIVE, lambda _req: httpx2.Response(500))
    omitted = list(bearer(permissions_omitted=True).items())
    with pytest.raises(PermissionsUnavailable):
        adapter.authenticate(omitted, permissions=required)

    api.on("GET", LIVE, lambda _req: httpx2.Response(401))
    with pytest.raises(Unauthenticated):
        adapter.authenticate(omitted, permissions=required)

    with pytest.raises(EnrollmentRequired):
        adapter.authenticate(list(bearer(recovery=True).items()), permissions=required)


def test_the_core_binds_the_route_it_is_given(api: FakeApi) -> None:
    adapter = api.adapter()
    headers = list(bearer(org_id=ORG, org_permissions=["p"]).items())
    bound = rule("p", organization_param="org")

    assert adapter.authenticate(headers, permissions=bound, route_params={"org": ORG}).id == "u1"
    for params in (None, {}, {"org": OTHER_ORG}, {"org": None}, {"other": ORG}):
        with pytest.raises(InsufficientPermission):
            adapter.authenticate(headers, permissions=bound, route_params=params)


def test_the_cross_site_check_comes_before_permissions(api: FakeApi) -> None:
    api.on("GET", LIVE, respond(200, live_body()))
    headers = {**cookie(permissions_omitted=True), "sec-fetch-site": "cross-site"}
    with pytest.raises(CrossSiteRequest):
        api.adapter().authenticate_request(
            "POST", list(headers.items()), permissions=rule("reports:read")
        )
    assert api.calls_to("GET", LIVE) == []


def test_roles_and_permissions_together_both_apply(api: FakeApi) -> None:
    adapter = api.adapter()
    required = rule("reports:read")
    with pytest.raises(InsufficientRole):
        adapter.authenticate(
            list(bearer(permissions=["reports:read"]).items()),
            roles=["admin"],
            permissions=required,
        )
    with pytest.raises(InsufficientPermission):
        adapter.authenticate(
            list(bearer(roles=["admin"]).items()), roles=["admin"], permissions=required
        )


@pytest.mark.parametrize(
    ("options", "error"),
    [
        ({"permissions": "reports:read"}, TypeError),
        ({"permissions": [""]}, ValueError),
        ({"permissions": [1]}, ValueError),
        ({"permissions": ["a"], "permission_mode": "some"}, ValueError),
        ({"permissions": ["a"], "organization_param": ""}, ValueError),
        # Each of these would look scoped and check nothing.
        ({"permission_mode": "all"}, ValueError),
        ({"organization": True}, ValueError),
        ({"organization_param": "org"}, ValueError),
    ],
)
def test_a_guard_set_up_wrong_is_refused(
    api: FakeApi, options: dict[str, Any], error: type[Exception]
) -> None:
    with pytest.raises(error):
        RequireUser(api.adapter(), **options)
    with pytest.raises(error):
        require_auth(**options)


def test_an_iterable_of_permissions_is_kept(api: FakeApi) -> None:
    client = _one_route(api, RequireUser(api.adapter(), permissions=iter(["reports:read"])))
    assert client.get("/x", headers=bearer(permissions=["reports:read"])).status_code == 200
    assert client.get("/x", headers=bearer(permissions=["reports:read"])).status_code == 200


# FastAPI's response shape.


def _one_route(api: FakeApi, guard: RequireUser, app: FastAPI | None = None) -> TestClient:
    app = app or FastAPI()

    @app.get("/x")
    def x(user: User = Depends(guard)) -> dict[str, str]:  # noqa: B008
        return {"id": user.id}

    return TestClient(app)


def test_fastapi_needs_no_setup_for_the_permission_body(api: FakeApi) -> None:
    client = _one_route(api, RequireUser(api.adapter(), permissions=["reports:read"]))

    r = client.get("/x", headers=bearer())
    assert (r.status_code, r.json()) == DENIED

    api.on("GET", LIVE, lambda _req: httpx2.Response(500))
    r = client.get("/x", headers=bearer(permissions_omitted=True))
    assert (r.status_code, r.json()) == UNAVAILABLE


def test_fastapi_a_mounted_app_gets_the_permission_body(api: FakeApi) -> None:
    inner = FastAPI()
    _one_route(api, RequireUser(api.adapter(), permissions=["reports:read"]), inner)
    outer = FastAPI()
    outer.mount("/inner", inner)

    r = TestClient(outer).get("/inner/x", headers=bearer())
    assert (r.status_code, r.json()) == DENIED


def test_fastapi_an_application_handler_wins(api: FakeApi) -> None:
    app = FastAPI()

    def mine(request: Request, exc: Exception) -> Response:
        return JSONResponse({"mine": True}, status_code=418)

    app.add_exception_handler(PermissionHTTPException, mine)
    client = _one_route(api, RequireUser(api.adapter(), permissions=["reports:read"]), app)

    r = client.get("/x", headers=bearer())
    assert (r.status_code, r.json()) == (418, {"mine": True})


def test_fastapi_the_session_role_guard_still_answers_under_detail(api: FakeApi) -> None:
    """Records the role guard's existing difference from every other guard: its body is
    ``{"detail": ...}``. The permission guard does not share it. See the README, Roles."""
    client = _one_route(api, RequireUser(api.adapter(), roles=["admin"]))

    r = client.get("/x", headers=bearer())
    assert (r.status_code, r.json()) == (403, {"detail": "insufficient_role"})


# Verify-only.

ISSUER = "https://login.test"
AUDIENCE = "https://api.test"
JWKS_URI = f"{ISSUER}/jwks"


def provider_token(**claims: Any) -> str:
    now = 2_000_000_000
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u1",
        "client_id": "app",
        "iat": now,
        "exp": now + 300,
        **claims,
    }
    return jwt.encode(payload, _KEY, algorithm="RS256", headers={"kid": "k1", "typ": "at+jwt"})


def bearer_token_header(**claims: Any) -> dict[str, str]:
    return {"authorization": f"Bearer {provider_token(**claims)}"}


@dataclass
class KeyServer:
    paths: list[str]

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        if str(request.url) == JWKS_URI:
            return httpx2.Response(200, json=JWKS)
        return httpx2.Response(404)

    def options(self) -> dict[str, Any]:
        return {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_uri": JWKS_URI,
            "http_client": httpx2.Client(transport=httpx2.MockTransport(self.handle)),
            "clock": lambda: 2_000_000_000.0,
        }


def fastapi_bearer_app(server: ResourceServer) -> FastAPI:
    app = FastAPI()
    add_bearer_error_handler(app)
    for route, options in GUARDS.items():
        if "allow_recovery" in options:
            continue
        guard = require_permission(
            *options["permissions"],
            mode=options.get("permission_mode", "any"),
            organization=options.get("organization", False),
            organization_param=options.get("organization_param"),
        )
        dependency = RequireBearer(server, guard)

        def handler(user: VerifiedUser = Depends(dependency)) -> dict[str, str]:  # noqa: B008
            return {"id": user.sub}

        app.add_api_route(f"/bearer/{_route_template(route)}", handler, methods=["GET"])
    return app


@pytest.fixture
def keys() -> KeyServer:
    return KeyServer([])


@pytest.fixture(params=["fastapi", "django", "django-async"])
def bearer_stack(request: pytest.FixtureRequest, keys: KeyServer) -> Iterator[Stack]:
    if request.param == "fastapi":
        client = TestClient(fastapi_bearer_app(ResourceServer(**keys.options())))
        yield Stack(client.get, "bearer", {"error": "missing_token"}, {})
        return
    _reset_resource_server()
    with override_settings(
        SEAMLESS_RESOURCE_SERVER=keys.options(), ROOT_URLCONF="test_permissions_django_urls"
    ):
        prefix = "bearer-async" if request.param == "django-async" else "bearer"
        yield Stack(Client().get, prefix, {"error": "missing_token"}, {})
    _reset_resource_server()


def test_verify_only_no_token_is_the_existing_401(bearer_stack: Stack) -> None:
    assert bearer_stack.status("any") == (401, bearer_stack.unauthenticated)


def test_verify_only_denies_a_token_without_the_claims(bearer_stack: Stack) -> None:
    held = bearer_token_header(roles=["reports:read"], scope="reports:read")
    assert bearer_stack.status("any", held) == DENIED


def test_verify_only_modes_and_scopes(bearer_stack: Stack) -> None:
    assert bearer_stack.status("any", bearer_token_header(permissions=["reports:read"])) == ALLOWED
    assert bearer_stack.status("all", bearer_token_header(permissions=["reports:read"])) == DENIED
    split = bearer_token_header(
        permissions=["reports:read"], org_id=ORG, org_permissions=["reports:write"]
    )
    assert bearer_stack.status("all", split) == ALLOWED

    instance = bearer_token_header(org_id=ORG, permissions=["projects:write"])
    assert bearer_stack.status("org", instance) == DENIED
    no_org = bearer_token_header(org_permissions=["projects:write"])
    assert bearer_stack.status("org", no_org) == DENIED

    org = bearer_token_header(org_id=ORG, org_permissions=["projects:write"])
    assert bearer_stack.status("org", org) == ALLOWED
    assert bearer_stack.status(f"org/{ORG}", org) == ALLOWED
    assert bearer_stack.status(f"org/{OTHER_ORG}", org) == DENIED
    assert bearer_stack.status("unbound", org) == DENIED


@pytest.mark.parametrize("route", ["empty", "empty-all", "empty-org"])
def test_verify_only_an_empty_list_denies(bearer_stack: Stack, route: str) -> None:
    held = bearer_token_header(permissions=["x"], org_id=ORG, org_permissions=["x"])
    assert bearer_stack.status(route, held) == DENIED


def test_verify_only_malformed_claims_read_as_empty(bearer_stack: Stack) -> None:
    for value in ("reports:read", {"a": 1}, 1, [1, None]):
        assert bearer_stack.status("any", bearer_token_header(permissions=value)) == DENIED
    mixed = bearer_token_header(permissions=[1, "reports:read"])
    assert bearer_stack.status("any", mixed) == ALLOWED


def test_verify_only_omitted_denies_and_reads_nothing(bearer_stack: Stack, keys: KeyServer) -> None:
    held = bearer_token_header(permissions_omitted=True, permissions=["reports:read"])
    assert bearer_stack.status("any", held) == DENIED
    assert set(keys.paths) == {"/jwks"}


def test_verify_only_exposes_the_fields(keys: KeyServer) -> None:
    server = ResourceServer(**keys.options())
    user = server.authenticate(
        "Bearer "
        + provider_token(
            permissions=["a", 1],
            org_id=ORG,
            org_roles=["admin"],
            org_permissions=["b"],
            permissions_omitted=True,
        )
    )
    assert user.permissions == ("a",)
    assert user.organization_roles == ("admin",)
    assert user.organization_permissions == ("b",)
    assert user.permissions_omitted is True
    assert user.org_id == ORG

    bare = server.authenticate("Bearer " + provider_token())
    assert bare.permissions == bare.organization_roles == bare.organization_permissions == ()
    assert bare.permissions_omitted is False


def test_verify_only_a_real_provider_token_denies_today() -> None:
    server = Provider().server()
    guard = require_permission("orders:read")
    user = server.authenticate(f"Bearer {TOKENS['user_passkey']}")
    with pytest.raises(Exception, match="insufficient_permission") as refused:
        guard.check(user)
    assert refused.value.status == 403  # type: ignore[attr-defined]
    assert refused.value.body == {"error": "insufficient_permission"}  # type: ignore[attr-defined]


def test_verify_only_a_bound_guard_checked_without_a_route_denies(keys: KeyServer) -> None:
    server = ResourceServer(**keys.options())
    user = server.authenticate("Bearer " + provider_token(org_id=ORG, org_permissions=["p"]))
    with pytest.raises(Exception, match="insufficient_permission"):
        require_permission("p", organization_param="org").check(user)


def test_verify_only_setup_is_checked() -> None:
    with pytest.raises(ValueError, match="mode"):
        require_permission("a", mode="some")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-empty"):
        require_permission("")


def test_guards_without_route_needs_are_unchanged(keys: KeyServer) -> None:
    server = ResourceServer(**keys.options())
    user = server.authenticate("Bearer " + provider_token(roles=["admin"]))
    require_role("admin").check_route(user, {"anything": 1})
