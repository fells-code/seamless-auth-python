"""The shared request vectors through the real FastAPI and Django stacks."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from django.conf import settings
from verify_only_support import VECTORS, Provider, guard_of

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
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from seamless_auth import VerifiedUser, require_scope
from seamless_auth.django import _reset_resource_server
from seamless_auth.fastapi import RequireBearer, add_bearer_error_handler

REQUESTS: list[dict[str, Any]] = VECTORS["requests"]


def test_request_vector_names_are_unique() -> None:
    assert len({r["name"] for r in REQUESTS}) == len(REQUESTS)


def _headers(vector: dict[str, Any]) -> dict[str, str]:
    auth = vector["authorization"]
    return {} if auth is None else {"Authorization": auth}


def _check(vector: dict[str, Any], status: int, body: Any, www: str | None) -> None:
    expect = vector["expect"]
    assert status == expect["status"]
    assert www == expect["www_authenticate"]
    if expect["body"] is None:
        assert body == {"ok": True}
    else:
        assert body == expect["body"]


@pytest.fixture(scope="module")
def fastapi_client() -> TestClient:
    server = Provider().server()
    app = FastAPI()
    add_bearer_error_handler(app)
    for i, vector in enumerate(REQUESTS):
        dependency = RequireBearer(server, *guard_of(vector["guard"]))

        def handler(user: VerifiedUser = Depends(dependency)) -> dict[str, bool]:  # noqa: B008
            return {"ok": True}

        app.add_api_route(f"/vo/{i}", handler, methods=["GET"])
    return TestClient(app)


@pytest.mark.parametrize(
    ("index", "vector"), list(enumerate(REQUESTS)), ids=[r["name"] for r in REQUESTS]
)
def test_fastapi_request_vectors(
    fastapi_client: TestClient, index: int, vector: dict[str, Any]
) -> None:
    r = fastapi_client.get(f"/vo/{index}", headers=_headers(vector))
    _check(vector, r.status_code, r.json(), r.headers.get("www-authenticate"))


@pytest.fixture
def django_client() -> Iterator[Client]:
    _reset_resource_server()
    provider = Provider()
    options = {
        "issuer": VECTORS["issuer"],
        "audience": VECTORS["audience"],
        "http_client": provider.client(),
        "clock": lambda: float(VECTORS["now"]),
    }
    with override_settings(
        SEAMLESS_RESOURCE_SERVER=options, ROOT_URLCONF="test_verify_only_django_urls"
    ):
        yield Client(enforce_csrf_checks=True)
    _reset_resource_server()


@pytest.mark.parametrize(
    ("index", "vector"), list(enumerate(REQUESTS)), ids=[r["name"] for r in REQUESTS]
)
@pytest.mark.parametrize("flavour", ["sync", "async"])
def test_django_request_vectors(
    django_client: Client, flavour: str, index: int, vector: dict[str, Any]
) -> None:
    r = django_client.get(f"/{flavour}/{index}", headers=_headers(vector))
    _check(vector, r.status_code, r.json(), r.headers.get("WWW-Authenticate"))


def test_a_django_guard_without_require_bearer_answers_missing_token(
    django_client: Client,
) -> None:
    r = django_client.get("/unverified", headers={"Authorization": "Bearer x"})
    assert r.status_code == 401
    assert r.json() == {"error": "missing_token"}
    assert r.headers["WWW-Authenticate"] == "Bearer"


def test_django_runs_guards_in_declaration_order(django_client: Client) -> None:
    token = VECTORS["tokens"]["client_credentials"]
    r = django_client.get("/ordered", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json() == {"error": "insufficient_scope", "scope": "orders:read"}


def test_django_puts_the_user_on_the_request(django_client: Client) -> None:
    token = VECTORS["tokens"]["user_passkey"]
    r = django_client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.json() == {"sub": "user-123", "scopes": ["openid", "orders:read", "orders:write"]}


def test_fastapi_runs_guards_in_declaration_order() -> None:
    server = Provider().server()
    app = FastAPI()
    add_bearer_error_handler(app)

    guarded = RequireBearer(server, require_scope("orders:read"), require_scope("reports:read"))

    @app.get("/ordered")
    def ordered(user: VerifiedUser = Depends(guarded)) -> dict[str, str]:  # noqa: B008
        return {"sub": user.sub}

    token = VECTORS["tokens"]["client_credentials"]
    r = TestClient(app).get("/ordered", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert r.json()["scope"] == "orders:read"


def test_fastapi_without_the_handler_still_challenges() -> None:
    app = FastAPI()

    @app.get("/x")
    def x(user: VerifiedUser = Depends(RequireBearer(Provider().server()))) -> dict[str, str]:  # noqa: B008
        return {"sub": user.sub}

    r = TestClient(app).get("/x")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json() == {"detail": {"error": "missing_token"}}


def test_fastapi_two_authorization_headers_are_no_token() -> None:
    server = Provider().server()
    app = FastAPI()
    add_bearer_error_handler(app)

    @app.get("/x")
    def x(user: VerifiedUser = Depends(RequireBearer(server))) -> dict[str, str]:  # noqa: B008
        return {"sub": user.sub}

    token = VECTORS["tokens"]["user_passkey"]
    auth = f"Bearer {token}"
    r = TestClient(app).get("/x", headers=[("authorization", auth), ("authorization", auth)])
    assert r.status_code == 401
    assert r.json() == {"error": "missing_token"}
