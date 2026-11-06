"""The URLconf the Django permission guard tests run against: each route as a sync
and as an async view, and the verify-only guard under ``bearer/``."""

from typing import Any

from django.http import HttpRequest, JsonResponse
from django.urls import path

from seamless_auth.django import (
    bearer_user_of,
    require_auth,
    require_bearer,
    require_permission,
    user_of,
)


def ok(request: HttpRequest, **_: Any) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


async def ok_async(request: HttpRequest, **_: Any) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


def bearer_ok(request: HttpRequest, **_: Any) -> JsonResponse:
    return JsonResponse({"id": bearer_user_of(request).sub})


async def bearer_ok_async(request: HttpRequest, **_: Any) -> JsonResponse:
    return JsonResponse({"id": bearer_user_of(request).sub})


GUARDS: dict[str, dict[str, Any]] = {
    "any": {"permissions": ["reports:read", "reports:export"]},
    "all": {"permissions": ["reports:read", "reports:write"], "permission_mode": "all"},
    "org": {"permissions": ["projects:write"], "organization": True},
    "org-all": {
        "permissions": ["projects:read", "projects:write"],
        "permission_mode": "all",
        "organization": True,
    },
    "org/<str:organization_id>": {
        "permissions": ["projects:write"],
        "organization_param": "organization_id",
    },
    "org-uuid/<uuid:organization_id>": {
        "permissions": ["projects:write"],
        "organization_param": "organization_id",
    },
    "unbound": {"permissions": ["projects:write"], "organization_param": "organization_id"},
    "empty": {"permissions": []},
    "empty-all": {"permissions": [], "permission_mode": "all"},
    "empty-org": {"permissions": [], "organization": True},
    "recovery": {"permissions": ["reports:read"], "allow_recovery": True},
}


def _bearer_guard(options: dict[str, Any]) -> Any:
    return require_permission(
        *options["permissions"],
        mode=options.get("permission_mode", "any"),
        organization=options.get("organization", False),
        organization_param=options.get("organization_param"),
    )


urlpatterns = [
    *(path(f"sync/{route}", require_auth(**options)(ok)) for route, options in GUARDS.items()),
    *(
        path(f"async/{route}", require_auth(**options)(ok_async))
        for route, options in GUARDS.items()
    ),
    *(
        path(f"bearer/{route}", require_bearer(_bearer_guard(options)(bearer_ok)))
        for route, options in GUARDS.items()
        if "allow_recovery" not in options
    ),
    *(
        path(f"bearer-async/{route}", require_bearer(_bearer_guard(options)(bearer_ok_async)))
        for route, options in GUARDS.items()
        if "allow_recovery" not in options
    ),
]
