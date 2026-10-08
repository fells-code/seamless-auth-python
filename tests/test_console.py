from __future__ import annotations

import httpx2
import pytest
from conftest import API_URL, FakeApi, access, read
from fastapi import FastAPI
from fastapi.testclient import TestClient

from seamless_auth.fastapi import console_router


def html(body: str) -> object:
    return lambda _r: httpx2.Response(200, text=body, headers={"content-type": "text/html"})


def test_the_console_is_proxied_from_the_auth_api(api: FakeApi) -> None:
    api.on(
        "GET",
        "/console/assets/app.js",
        lambda _r: httpx2.Response(
            200,
            text="console();",
            headers={
                "content-type": "text/javascript",
                "cache-control": "max-age=60",
                "set-cookie": "upstream=1",
            },
        ),
    )

    r = read(api.adapter().console("GET", "/assets/app.js", "v=2"))

    assert r.status == 200
    assert r.text == "console();"
    assert r.headers["content-type"] == "text/javascript"
    assert r.headers["cache-control"] == "max-age=60"
    assert "set-cookie" not in r.headers
    recorded = api.calls_to("GET", "/console/assets/app.js")[0]
    assert recorded.query == "v=2"
    assert "cookie" not in recorded.headers and "authorization" not in recorded.headers


def test_the_console_root_and_head(api: FakeApi) -> None:
    api.on("GET", "/console", html("<html>"))  # type: ignore[arg-type]
    api.on("HEAD", "/console", html(""))  # type: ignore[arg-type]
    adapter = api.adapter()

    for root in ("", "/"):
        r = read(adapter.console("GET", root))
        assert (r.status, r.text) == (200, "<html>")
    r = read(adapter.console("HEAD", "/"))
    assert (r.status, r.text) == (200, "")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_the_console_refuses_other_methods(api: FakeApi, method: str) -> None:
    assert read(api.adapter().console(method, "/x")).status == 405


@pytest.mark.parametrize(
    "path",
    [
        "/../admin/users",
        "/%2e%2e/admin/users",
        "/assets/%2E%2E/%2e%2e/jwks.json",
        "/..%2fadmin",
        "/..%2Fadmin",
        "/..%5cadmin",
        "/a/./b",
        "/%zz",
        "/%+1",
        "/a\\b",
    ],
)
def test_the_console_never_leaves_its_subtree(api: FakeApi, path: str) -> None:
    assert read(api.adapter().console("GET", path)).status == 400
    assert not api.calls


def test_the_console_follows_redirects_only_within_itself(api: FakeApi) -> None:
    api.on(
        "GET", "/console/old", lambda _r: httpx2.Response(302, headers={"location": "/console/new"})
    )
    api.on("GET", "/console/new", html("moved"))  # type: ignore[arg-type]
    api.on(
        "GET",
        "/console/escape",
        lambda _r: httpx2.Response(302, headers={"location": "/.well-known/jwks.json"}),
    )
    api.on(
        "GET",
        "/console/loop",
        lambda _r: httpx2.Response(302, headers={"location": "/console/loop"}),
    )
    adapter = api.adapter()

    r = read(adapter.console("GET", "/old"))
    assert (r.status, r.text) == (200, "moved")
    assert read(adapter.console("GET", "/escape")).status == 502
    assert not api.calls_to("GET", "/.well-known/jwks.json")
    assert read(adapter.console("GET", "/loop")).status == 502
    assert len(api.calls_to("GET", "/console/loop")) == 6


def test_the_console_under_an_auth_server_path(api: FakeApi) -> None:
    api.on("GET", "/base/console/x", html("ok"))  # type: ignore[arg-type]
    r = read(api.adapter(auth_server_url=f"{API_URL}/base").console("GET", "/x"))
    assert (r.status, r.text) == (200, "ok")


def test_the_console_reports_an_unreachable_upstream() -> None:
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    adapter = FakeApi().adapter(http_client=httpx2.Client(transport=httpx2.MockTransport(refuse)))
    r = read(adapter.console("GET", "/x"))
    assert r.status == 502
    assert "unreachable" in r.text


def test_the_fastapi_console_router(api: FakeApi) -> None:
    api.on("GET", "/console", html("<html>"))  # type: ignore[arg-type]
    api.on("GET", "/console/assets/app.js", html("js"))  # type: ignore[arg-type]
    app = FastAPI()
    app.include_router(console_router(api.adapter()))
    client = TestClient(app)
    client.cookies.set("seamless-access", access().split("=", 1)[1])

    for root in ("/console", "/console/"):
        r = client.get(root, follow_redirects=False)
        assert (r.status_code, r.text) == (200, "<html>"), root
    assert client.get("/console/assets/app.js").text == "js"
    assert client.get("/console/%2e%2e/jwks.json").status_code == 400
    assert client.post("/console/x").status_code == 405
    assert all("cookie" not in c.headers for c in api.calls)
