"""The URLconf the Django binding tests run against."""

from django.http import HttpRequest, JsonResponse
from django.urls import include, path
from django.views.decorators.csrf import csrf_exempt

from seamless_auth.django import require_auth, user_of


@require_auth
def me(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


@require_auth
async def me_async(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


@csrf_exempt
@require_auth
def transfer(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"id": user_of(request).id})


urlpatterns = [
    path("api/me", me),
    path("api/me-async", me_async),
    path("api/transfer", transfer),
    path("auth/", include("seamless_auth.django")),
]
