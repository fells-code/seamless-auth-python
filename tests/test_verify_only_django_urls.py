"""The URLconf the Django verify-only tests run against: one sync and one async
view per shared request vector."""

from typing import Any

from django.http import HttpRequest, JsonResponse
from django.urls import path
from verify_only_support import VECTORS

from seamless_auth.django import (
    bearer_user_of,
    require_bearer,
    require_role,
    require_scope,
    require_step_up,
)


def _decorate(view: Any, guard: dict[str, Any] | None) -> Any:
    if guard is not None:
        if guard["kind"] == "scope":
            view = require_scope(*guard["scopes"])(view)
        elif guard["kind"] == "role":
            view = require_role(*guard["roles"])(view)
        else:
            view = require_step_up(
                acr_values=guard.get("acr_values"),
                max_age=guard.get("max_age"),
                amr=guard.get("amr"),
            )(view)
    return require_bearer(view)


def ok(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


async def ok_async(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


@require_scope("orders:read")
def unverified(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


@require_bearer
@require_scope("orders:read")
@require_scope("reports:read")
def ordered(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


@require_bearer
def me(request: HttpRequest) -> JsonResponse:
    user = bearer_user_of(request)
    return JsonResponse({"sub": user.sub, "scopes": list(user.scopes)})


urlpatterns = [
    *(
        path(f"sync/{i}", _decorate(ok, r["guard"]), name=f"vo-sync-{i}")
        for i, r in enumerate(VECTORS["requests"])
    ),
    *(
        path(f"async/{i}", _decorate(ok_async, r["guard"]), name=f"vo-async-{i}")
        for i, r in enumerate(VECTORS["requests"])
    ),
    path("unverified", unverified),
    path("ordered", ordered),
    path("me", me),
]
