"""FastAPI (and Starlette) binding.

.. code-block:: python

    from fastapi import Depends, FastAPI
    from seamless_auth import Adapter, User
    from seamless_auth.fastapi import RequireUser, auth_router

    auth = Adapter(auth_server_url=..., cookie_secret=..., service_secret=..., jwks_kid=...)
    current_user = RequireUser(auth)

    app = FastAPI()
    app.include_router(auth_router(auth))  # the auth routes, at /auth

    @app.get("/api/me")
    def me(user: User = Depends(current_user)):
        return {"id": user.id}

Verify-only, for an API that only receives OpenID Provider access tokens::

    from seamless_auth import ResourceServer, VerifiedUser, require_scope
    from seamless_auth.fastapi import RequireBearer, add_bearer_error_handler

    rs = ResourceServer(issuer="https://login.example.com", audience="https://api.example.com")
    app = FastAPI()
    add_bearer_error_handler(app)

    @app.get("/orders")
    def orders(user: VerifiedUser = Depends(RequireBearer(rs, require_scope("orders:read")))):
        return {"sub": user.sub}
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, FastAPI, HTTPException, Request
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response, StreamingResponse

from ._adapter import (
    MAX_BODY_BYTES,
    Adapter,
    CrossSiteRequest,
    EnrollmentRequired,
    Unauthenticated,
    User,
)
from ._http import AuthRequest, AuthResponse, Headers
from ._resource_server import BearerError, BearerRequest, Guard, ResourceServer, VerifiedUser

__all__ = [
    "BearerHTTPException",
    "RequireBearer",
    "RequireUser",
    "add_bearer_error_handler",
    "auth_router",
    "bearer_exception_handler",
    "console_router",
]

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
# What a path segment may keep when a raw path has to be rebuilt from a decoded one.
_PATH_SAFE = "/:@!$&'()*+,;=-._~"


def auth_router(adapter: Adapter, *, prefix: str = "/auth") -> APIRouter:
    """The auth routes, at ``prefix``, which is where the client SDKs call. The
    adapter is blocking, so each request runs on Starlette's threadpool."""
    prefix = "/" + prefix.strip("/") if prefix.strip("/") else ""
    router = APIRouter(prefix=prefix, include_in_schema=False)

    async def handle(request: Request) -> Response:
        auth_request = await _auth_request(request, prefix)
        return _response(await run_in_threadpool(adapter.handle, auth_request))

    router.add_api_route("/{path:path}", handle, methods=_METHODS)
    return router


def console_router(adapter: Adapter) -> APIRouter:
    """The Seamless admin dashboard at /console, the path it is built against,
    proxied from the auth API so it shares the auth routes' origin."""
    router = APIRouter(prefix="/console", include_in_schema=False)

    async def handle(request: Request) -> Response:
        path = _relative_raw_path(request, "/console")
        query = request.scope.get("query_string", b"").decode("latin-1")
        return _response(await run_in_threadpool(adapter.console, request.method, path, query))

    router.add_api_route("", handle, methods=_METHODS)
    router.add_api_route("/{path:path}", handle, methods=_METHODS)
    return router


class RequireUser:
    """A dependency that answers 401 unless the request carries a valid session, and
    returns its :class:`~seamless_auth.User`. A session from the cookie also gets the
    auth routes' cross-site check (403 on a state change from another site).

    A recovery session (a user who still has to enroll a new passkey or
    authenticator app) answers 403 ``enrollment_required`` unless
    ``allow_recovery`` is set.

    A plain function, so FastAPI runs it on its threadpool: the first sight of a key
    may fetch the auth API's key set.
    """

    def __init__(self, adapter: Adapter, *, allow_recovery: bool = False) -> None:
        self._adapter = adapter
        self._allow_recovery = allow_recovery

    def __call__(self, request: Request) -> User:
        try:
            return self._adapter.authenticate_request(
                request.method, _headers(request), allow_recovery=self._allow_recovery
            )
        except EnrollmentRequired:
            raise HTTPException(status_code=403, detail="enrollment_required") from None
        except CrossSiteRequest:
            raise HTTPException(status_code=403, detail="cross_site_request_blocked") from None
        except Unauthenticated:
            raise HTTPException(status_code=401, detail="unauthenticated") from None


class BearerHTTPException(HTTPException):
    """A verify-only refusal. :func:`bearer_exception_handler` answers it with the
    exact JSON body; without the handler FastAPI still sends its status and
    ``WWW-Authenticate``, with the body under ``detail``."""

    def __init__(self, error: BearerError) -> None:
        super().__init__(error.status, detail=error.body, headers=error.headers() or None)
        self.body = error.body


def bearer_exception_handler(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, BearerHTTPException):
        raise exc
    return JSONResponse(exc.body, status_code=exc.status_code, headers=exc.headers)


def add_bearer_error_handler(app: FastAPI) -> None:
    """Answers :class:`RequireBearer` refusals with the shared verify-only bodies,
    such as ``{"error": "insufficient_scope", "scope": "orders:read"}``."""
    app.add_exception_handler(BearerHTTPException, bearer_exception_handler)


class RequireBearer:
    """A dependency that verifies the request's OpenID Provider access token, runs
    ``guards`` in order, and returns the :class:`~seamless_auth.VerifiedUser`.

    A plain function, so FastAPI runs it on its threadpool: the first request may
    fetch the provider's discovery document and key set.
    """

    def __init__(self, server: ResourceServer, *guards: Guard) -> None:
        self._server = server
        self._guards = guards

    def __call__(self, request: Request) -> VerifiedUser:
        values = request.headers.getlist("authorization")
        bearer = BearerRequest(request.method, _headers(request), lambda: str(request.url))
        try:
            # More than one Authorization header is not one token.
            user = self._server.authenticate(values[0] if len(values) == 1 else None, bearer)
            for guard in self._guards:
                guard.check(user)
        except BearerError as err:
            raise BearerHTTPException(err) from None
        return user


def _headers(request: Request) -> Headers:
    return Headers((k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw)


async def _auth_request(request: Request, prefix: str) -> AuthRequest:
    body = bytearray()
    too_large = False
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            too_large = True
            break

    client = request.client
    return AuthRequest(
        method=request.method,
        path=_relative_raw_path(request, prefix),
        query=request.scope.get("query_string", b"").decode("latin-1"),
        headers=_headers(request),
        body=bytes(body) if body and not too_large else None,
        peer=client.host if client else None,
        body_too_large=too_large,
    )


def _relative_raw_path(request: Request, prefix: str) -> str:
    """The path below the mount, still percent-encoded, so an escaped ``/`` or
    ``.`` in a parameter reaches the manifest matcher as the client sent it."""
    mount = request.scope.get("root_path", "") + prefix
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        text = raw.decode("latin-1").split("?", 1)[0]
        if text.startswith(mount):
            rest = text[len(mount) :]
            return rest if rest.startswith("/") else "/" + rest
    return "/" + quote(str(request.path_params.get("path", "")), safe=_PATH_SAFE)


def _response(res: AuthResponse) -> Response:
    response: Response
    if isinstance(res.body, bytes):
        response = Response(content=res.body, status_code=res.status)
    else:
        background = BackgroundTask(res.close) if res.close else None
        response = StreamingResponse(res.body, status_code=res.status, background=background)
    for name, value in res.headers:
        response.headers.append(name, value)
    for cookie in res.cookies:
        response.headers.append("set-cookie", cookie.header())
    return response
