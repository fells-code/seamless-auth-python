"""Django binding.

Configure the adapter in settings, include its URLs, and guard views::

    # settings.py
    SEAMLESS_AUTH = {
        "auth_server_url": env("AUTH_SERVER_URL"),
        "cookie_secret": env("COOKIE_SECRET"),
        "service_secret": env("SERVICE_SECRET"),
        "jwks_kid": env("JWKS_KID"),
    }

    # urls.py
    urlpatterns = [path("auth/", include("seamless_auth.django"))]

    # views.py
    from seamless_auth.django import require_auth

    @require_auth
    def me(request):
        return JsonResponse({"id": request.seamless_user.id})

``SEAMLESS_AUTH`` takes the keyword arguments of :class:`seamless_auth.Adapter`.
``deliver`` and ``resolve_client_ip`` may be dotted paths to callables.
"""

from __future__ import annotations

import functools
import inspect
import threading
from collections.abc import Callable
from typing import Any, Literal, TypeVar, cast
from urllib.parse import quote, unquote

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.urls import re_path
from django.utils.module_loading import import_string
from django.views.decorators.csrf import csrf_exempt

from ._adapter import MAX_BODY_BYTES, Adapter, CrossSiteRequest, Unauthenticated, User
from ._http import AuthRequest, AuthResponse, Headers

__all__ = [
    "auth_view",
    "console_urlpatterns",
    "console_view",
    "get_adapter",
    "require_auth",
    "urlpatterns",
]

_PATH_SAFE = "/:@!$&'()*+,;=-._~"
_lock = threading.Lock()
_adapter: Adapter | None = None

F = TypeVar("F", bound=Callable[..., Any])


def get_adapter() -> Adapter:
    """The adapter configured by ``settings.SEAMLESS_AUTH``, built on first use."""
    global _adapter  # noqa: PLW0603
    with _lock:
        if _adapter is None:
            options = dict(getattr(settings, "SEAMLESS_AUTH", None) or {})
            if not options:
                raise ImproperlyConfigured("seamless-auth: set SEAMLESS_AUTH in settings")
            for name in ("deliver", "resolve_client_ip"):
                if isinstance(options.get(name), str):
                    options[name] = import_string(options[name])
            _adapter = Adapter(**options)
        return _adapter


def _reset_adapter() -> None:
    """Forgets the configured adapter, for tests that change settings."""
    global _adapter  # noqa: PLW0603
    with _lock:
        _adapter = None


@csrf_exempt
def auth_view(request: HttpRequest, path: str = "") -> HttpResponse:
    """The auth routes. Exempt from Django's CSRF middleware: the adapter refuses
    non-JSON bodies and checks the origin of state-changing requests itself, and the
    client SDKs send no CSRF token."""
    return _response(get_adapter().handle(_auth_request(request, path)))


urlpatterns = [re_path(r"^(?P<path>.*)$", auth_view, name="seamless-auth")]


@csrf_exempt
def console_view(request: HttpRequest, path: str = "") -> HttpResponse:
    """The Seamless admin dashboard, proxied from the auth API so it shares the
    auth routes' origin. Exempt from the CSRF middleware because it serves GET and
    HEAD only and answers anything else 405 itself."""
    return _response(
        get_adapter().console(
            request.method or "GET",
            _relative_raw_path(request, path),
            request.META.get("QUERY_STRING", ""),
        )
    )


#: Include at ``console/``: ``path("console/", include(console_urlpatterns))``.
console_urlpatterns = [re_path(r"^(?P<path>.*)$", console_view, name="seamless-console")]


def require_auth(view: F) -> F:
    """Answers 401 unless the request carries a valid session, and puts the
    :class:`~seamless_auth.User` on ``request.seamless_user``. A session from the
    cookie also gets the auth routes' cross-site check (403 on a state change from
    another site). Works on sync and async views."""

    def check(request: HttpRequest) -> HttpResponse | None:
        try:
            user = get_adapter().authenticate_request(request.method or "GET", _headers(request))
        except CrossSiteRequest:
            return JsonResponse({"error": "cross_site_request_blocked"}, status=403)
        except Unauthenticated:
            return JsonResponse({"error": "unauthenticated"}, status=401)
        request.seamless_user = user  # type: ignore[attr-defined]
        return None

    if inspect.iscoroutinefunction(view):

        @functools.wraps(view)
        async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            refused = await sync_to_async(check)(request)
            return refused or await view(request, *args, **kwargs)

        return cast(F, async_wrapper)

    @functools.wraps(view)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        return check(request) or view(request, *args, **kwargs)

    return cast(F, wrapper)


def user_of(request: HttpRequest) -> User:
    """The user :func:`require_auth` put on the request."""
    return cast(User, request.seamless_user)  # type: ignore[attr-defined]


def _headers(request: HttpRequest) -> Headers:
    return Headers(request.headers.items())


def _auth_request(request: HttpRequest, path: str) -> AuthRequest:
    body = request.read(MAX_BODY_BYTES + 1)
    too_large = len(body) > MAX_BODY_BYTES
    return AuthRequest(
        method=request.method or "GET",
        path=_relative_raw_path(request, path),
        query=request.META.get("QUERY_STRING", ""),
        headers=_headers(request),
        body=body if body and not too_large else None,
        peer=request.META.get("REMOTE_ADDR") or None,
        body_too_large=too_large,
    )


def _relative_raw_path(request: HttpRequest, path: str) -> str:
    """The path below the include, still percent-encoded, so an escaped ``/`` or
    ``.`` in a parameter reaches the manifest matcher as the client sent it. Django
    hands views a decoded path; the raw one comes from the server when it gives it."""
    decoded_full = request.path
    mount = decoded_full[: len(decoded_full) - len(path)] if path else decoded_full
    raw: Any = None
    scope = getattr(request, "scope", None)
    if isinstance(scope, dict) and isinstance(scope.get("raw_path"), bytes):
        raw = scope["raw_path"].decode("latin-1")
    else:
        raw = request.META.get("RAW_URI") or request.META.get("REQUEST_URI")
    if isinstance(raw, str):
        raw = raw.split("?", 1)[0]
        if unquote(raw) == decoded_full and raw.startswith(mount):
            rest = raw[len(mount) :]
            return str(rest) if rest.startswith("/") else "/" + str(rest)
    return "/" + quote(path, safe=_PATH_SAFE)


def _response(res: AuthResponse) -> HttpResponse:
    response: HttpResponse | StreamingHttpResponse
    if isinstance(res.body, bytes):
        response = HttpResponse(res.body, status=res.status)
        if "content-type" not in {name for name, _ in res.headers}:
            del response["Content-Type"]
    else:
        response = StreamingHttpResponse(res.body, status=res.status)
        del response["Content-Type"]
    for name, value in res.headers:
        response[name] = value
    for cookie in res.cookies:
        if cookie.max_age > 0:
            response.set_cookie(
                cookie.name,
                cookie.value,
                max_age=cookie.max_age,
                path=cookie.path,
                domain=cookie.domain,
                secure=cookie.secure,
                httponly=cookie.http_only,
                samesite=_same_site(cookie.same_site),
            )
        else:
            response.set_cookie(
                cookie.name,
                "",
                max_age=0,
                expires="Thu, 01 Jan 1970 00:00:00 GMT",
                path=cookie.path,
                domain=cookie.domain,
                secure=cookie.secure,
                httponly=cookie.http_only,
                samesite=_same_site(cookie.same_site),
            )
    return cast(HttpResponse, response)


def _same_site(value: str) -> Literal["Lax", "Strict", "None"]:
    return cast(Literal["Lax", "Strict", "None"], value)
