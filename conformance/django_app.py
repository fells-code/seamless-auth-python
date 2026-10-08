"""The Django reference app the Seamless Auth adapter conformance suite drives
(``seamless verify --adapter-url``), in one file and served over ASGI. Its routes
and configuration follow verify/CONFORMANCE.md in fells-code/seamless-cli. It is a
test fixture, not an example deployment: /__captured exposes one-time codes.

    python conformance/django_app.py
"""

from __future__ import annotations

import os
import secrets
import sys

from django.conf import settings

sys.path.insert(0, os.path.dirname(__file__))
import _shared

settings.configure(
    DEBUG=False,
    SECRET_KEY=secrets.token_urlsafe(32),
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF=__name__,
    MIDDLEWARE=[
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
    ],
    INSTALLED_APPS=[],
    SEAMLESS_AUTH=_shared.adapter_options(),
)

import django  # noqa: E402

django.setup()

from django.core.asgi import get_asgi_application  # noqa: E402
from django.http import HttpRequest, JsonResponse  # noqa: E402
from django.urls import include, path  # noqa: E402

from seamless_auth.django import require_auth, user_of  # noqa: E402


def health(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


def captured(request: HttpRequest, recipient: str) -> JsonResponse:
    return JsonResponse(_shared.captured_for(recipient), safe=False)


@require_auth
def me(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


urlpatterns = [
    path("", health),
    path("__captured/<str:recipient>", captured),
    path("api/me", me),
    path("auth/", include("seamless_auth.django")),
]

application = get_asgi_application()

if __name__ == "__main__":
    import uvicorn

    print(f"seamless-auth Django reference app listening on :{_shared.port()}")
    uvicorn.run(application, host="0.0.0.0", port=_shared.port(), log_level="warning")
