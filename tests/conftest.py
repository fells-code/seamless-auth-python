"""A fake auth API and helpers for driving the adapter as a client would."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from seamless_auth import Adapter, AuthRequest, AuthResponse, Headers, ResponseCookie
from seamless_auth._jwt import sign_hs256, verify_hs256

TEST_SECRET = "cookie-secret-cookie-secret-cookie-secret"
TEST_SERVICE = "service-secret-service-secret-service-secret"
API_URL = "http://auth.test"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "k1",
            "alg": "RS256",
            "use": "sig",
            "n": _b64(_KEY.public_key().public_numbers().n),
            "e": _b64(_KEY.public_key().public_numbers().e),
        }
    ]
}


def sign_rs256(claims: dict[str, Any]) -> str:
    """Signs a token as the auth API would."""
    now = int(time.time())
    return jwt.encode(
        {"iat": now, "exp": now + 300, **claims}, _KEY, algorithm="RS256", headers={"kid": "k1"}
    )


def api_token(sub: str, typ: str, **extra: Any) -> str:
    return sign_rs256({"sub": sub, "typ": typ, "iss": API_URL, "aud": API_URL, **extra})


def session(sub: str = "u1") -> dict[str, Any]:
    return {
        "message": "Success",
        "sub": sub,
        "token": api_token(sub, "access", sid="s-1"),
        "refreshToken": f"refresh-{sub}",
        "ttl": 900,
        "refreshTtl": 3600,
    }


@dataclass
class Recorded:
    method: str
    path: str
    query: str
    headers: httpx2.Headers
    body: bytes


Handler = Callable[[httpx2.Request], httpx2.Response]


def respond(status: int, body: Any) -> Handler:
    return lambda _req: httpx2.Response(status, json=body)


@dataclass
class FakeApi:
    """An auth API: JWKS, an optional manifest, and per-route handlers."""

    routes: dict[str, Handler] = field(default_factory=dict)
    calls: list[Recorded] = field(default_factory=list)
    manifest: Any = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def on(self, method: str, path: str, handler: Handler) -> None:
        self.routes[f"{method} {path}"] = handler

    def calls_to(self, method: str, path: str) -> list[Recorded]:
        with self.lock:
            return [c for c in self.calls if c.method == method and c.path == path]

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        raw_path = request.url.raw_path.decode().split("?", 1)[0]
        recorded = Recorded(
            request.method,
            raw_path,
            request.url.query.decode(),
            request.headers,
            request.read(),
        )
        with self.lock:
            self.calls.append(recorded)
        if raw_path == "/.well-known/jwks.json":
            return httpx2.Response(200, json=JWKS)
        if raw_path == "/.well-known/seamless-adapter.json" and self.manifest is not None:
            return httpx2.Response(200, json=self.manifest)
        handler = self.routes.get(f"{request.method} {raw_path}")
        if handler is None:
            return httpx2.Response(404, json={"error": "not_found"})
        return handler(request)

    def client(self) -> httpx2.Client:
        return httpx2.Client(transport=httpx2.MockTransport(self.handle), follow_redirects=False)

    def adapter(self, **options: Any) -> Adapter:
        settings: dict[str, Any] = {
            "auth_server_url": API_URL,
            "cookie_secret": TEST_SECRET,
            "service_secret": TEST_SERVICE,
            "jwks_kid": "test-main",
            "disable_manifest_fetch": True,
            "http_client": self.client(),
            **options,
        }
        return Adapter(**settings)


@pytest.fixture
def api() -> FakeApi:
    return FakeApi()


def signed_cookie(name: str, claims: dict[str, Any]) -> str:
    """A cookie as the adapter writes it, with the kind its name implies."""
    kind = {"seamless-access": "access", "seamless-refresh": "refresh"}.get(name, "ephemeral")
    return raw_cookie(name, kind, claims)


def raw_cookie(name: str, kind: str, claims: dict[str, Any]) -> str:
    """Signs claims with the cookie secret under any kind, including the wrong one
    for the slot."""
    return f"{name}={sign_hs256({**claims, 'kind': kind}, TEST_SECRET, 3600)}"


def pre_auth() -> str:
    return signed_cookie("seamless-ephemeral", {"sub": "u1", "token": "pre-auth"})


def access() -> str:
    return signed_cookie("seamless-access", {"sub": "u1", "token": "t"})


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    text: str
    body: Any
    cookies: dict[str, ResponseCookie]

    def cleared(self, name: str) -> bool:
        cookie = self.cookies.get(name)
        return cookie is not None and cookie.max_age == 0 and cookie.value == ""


def call(
    adapter: Adapter,
    method: str,
    path: str,
    *,
    body: str | None = None,
    content_type: str | None = "application/json",
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
    peer: str | None = None,
) -> Reply:
    """Sends a request to the adapter's auth routes. A body goes as JSON, as the
    client SDKs send it, unless ``content_type`` says otherwise."""
    path, _, query = path.partition("?")
    items = list((headers or {}).items())
    if cookie:
        items.append(("cookie", cookie))
    if body is not None and content_type:
        items.append(("content-type", content_type))
    res = adapter.handle(
        AuthRequest(
            method=method,
            path=path,
            query=query,
            headers=Headers(items),
            body=body.encode() if body is not None else None,
            peer=peer,
        )
    )
    return read(res)


def read(res: AuthResponse) -> Reply:
    raw = res.body if isinstance(res.body, bytes) else b"".join(res.body)
    text = raw.decode()
    try:
        body = json.loads(text) if text else None
    except ValueError:
        body = None
    return Reply(res.status, dict(res.headers), text, body, {c.name: c for c in res.cookies})


def service_claims(recorded: Recorded) -> dict[str, Any]:
    """The claims of a service token the adapter sent."""
    token = recorded.headers["x-seamless-service-token"].removeprefix("Bearer ")
    claims = verify_hs256(token, TEST_SERVICE)
    assert claims is not None
    return claims


def hs256_access_token() -> str:
    """An access-shaped token signed HS256 under the cookie secret: an
    algorithm-confusion attempt."""
    claims = {"sub": "u1", "typ": "access", "iss": API_URL, "aud": API_URL}
    return sign_hs256(claims, TEST_SECRET, 60, "k1")
