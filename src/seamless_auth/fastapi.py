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
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response, StreamingResponse

from ._adapter import MAX_BODY_BYTES, Adapter, CrossSiteRequest, Unauthenticated, User
from ._http import AuthRequest, AuthResponse, Headers

__all__ = ["RequireUser", "auth_router"]

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


class RequireUser:
    """A dependency that answers 401 unless the request carries a valid session, and
    returns its :class:`~seamless_auth.User`. A session from the cookie also gets the
    auth routes' cross-site check (403 on a state change from another site).

    A plain function, so FastAPI runs it on its threadpool: the first sight of a key
    may fetch the auth API's key set.
    """

    def __init__(self, adapter: Adapter) -> None:
        self._adapter = adapter

    def __call__(self, request: Request) -> User:
        try:
            return self._adapter.authenticate_request(request.method, _headers(request))
        except CrossSiteRequest:
            raise HTTPException(status_code=403, detail="cross_site_request_blocked") from None
        except Unauthenticated:
            raise HTTPException(status_code=401, detail="unauthenticated") from None


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
