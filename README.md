# seamless-auth-python

A [Seamless Auth](https://github.com/fells-code/seamless-auth-api) server adapter for Python, with
bindings for [FastAPI](https://fastapi.tiangolo.com) and [Django](https://www.djangoproject.com).

The adapter sits in your backend between your users and the Seamless Auth API:

- **Browsers** talk to it over `HttpOnly` cookies on your own domain. The API's tokens never
  reach page scripts.
- **Native clients** (mobile, CLIs) talk to it over bearer tokens, sending
  `x-seamless-auth-transport: bearer`.
- **The auth API** sees bearer tokens plus a service token that lets it trust the client
  address and user agent the adapter forwards.

Which routes the adapter serves, and what each does to the session, comes from the adapter
manifest the auth API publishes, so a new API route works without a new release of this package.

It is held to the same [conformance suite](https://github.com/fells-code/seamless-cli/blob/main/verify/CONFORMANCE.md)
as the Express, Fastify, Go and Rust adapters, with a FastAPI and a Django reference app, in CI on
every change.

## Install

```bash
pip install "seamless-auth[fastapi]"   # or "seamless-auth[django]"
```

Python 3.11 or later. Django 5.2 or later.

## FastAPI

```python
import os

from fastapi import Depends, FastAPI
from seamless_auth import Adapter, User
from seamless_auth.fastapi import RequireUser, auth_router

auth = Adapter(
    auth_server_url=os.environ["AUTH_SERVER_URL"],
    cookie_secret=os.environ["COOKIE_SECRET"],  # at least 32 bytes
    service_secret=os.environ["SERVICE_SECRET"],  # the API's API_SERVICE_TOKEN
    jwks_kid=os.environ["JWKS_KID"],
)
current_user = RequireUser(auth)

app = FastAPI()
# The auth routes, at /auth, which is where the client SDKs call.
app.include_router(auth_router(auth))


# Your own routes, behind the adapter's guard.
@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id}
```

`RequireUser` answers 401 unless the request carries a session, and returns the `User`.

## Django

```python
# settings.py
SEAMLESS_AUTH = {
    "auth_server_url": os.environ["AUTH_SERVER_URL"],
    "cookie_secret": os.environ["COOKIE_SECRET"],
    "service_secret": os.environ["SERVICE_SECRET"],
    "jwks_kid": os.environ["JWKS_KID"],
}

# urls.py
urlpatterns = [
    path("auth/", include("seamless_auth.django")),
    path("api/me", views.me),
]

# views.py
from django.http import JsonResponse
from seamless_auth.django import require_auth, user_of


@require_auth
def me(request):
    return JsonResponse({"id": user_of(request).id})
```

`SEAMLESS_AUTH` takes the keyword arguments of `Adapter` (below). `deliver` and
`resolve_client_ip` may be dotted paths to callables. `require_auth` works on sync and async
views. The auth routes are exempt from Django's CSRF middleware: the adapter does its own
cross-site checks (below), and the client SDKs send no CSRF token.

## The guard

The guard (`RequireUser`, `require_auth`) accepts the adapter's session cookie, or an auth API
access token in `Authorization: Bearer` for clients with no cookie jar. The cookie wins when both
are present. It does not refresh: the auth routes refresh a browser session silently, and a bearer
client calls `POST /auth/refresh` itself. `Adapter.authenticate(headers)` does the same check
anywhere else.

A request the guard admits on the session cookie also gets the auth routes' cross-site check:
while cookies are `SameSite=None`, a state-changing request from another site (`Sec-Fetch-Site:
cross-site`, or an `Origin` outside `allowed_origins`) answers 403. A bearer token is never
attached by a browser, so it is not checked.

### Request bodies

The auth routes forward a request body to the auth API as JSON, so a body must be sent as
`application/json` (or a `+json` type). Anything else answers 415 `unsupported_media_type`: a
cross-site form can post a `text/plain` body shaped like JSON with no CORS preflight, and read as
JSON it would be a sign-in the user never made. The client SDKs already send JSON.

## Options

| Argument | Default | Purpose |
| --- | --- | --- |
| `auth_server_url` | required | Where the adapter reaches the auth API |
| `auth_server_issuer` | the URL | Expected `iss` of the API's tokens, when it differs from the URL you reach it at |
| `audience` | the issuer | Expected `aud` of the API's tokens |
| `cookie_secret` | required | Signs the session cookies (32 bytes or more) |
| `service_secret` | required | The API's `API_SERVICE_TOKEN` (32 bytes or more) |
| `jwks_kid` | `dev-main` | `kid` header on service tokens |
| `cookie_domain` | none | Cookie `Domain` |
| `insecure_cookies` | `False` | Drops `Secure`, for local development over HTTP |
| `same_site` | `None`, or `Lax` with `insecure_cookies` | Cookie `SameSite` |
| `allowed_origins` | none | The only cross-origin callers allowed to change state while cookies are `SameSite=None` |
| `access_cookie_name`, `refresh_cookie_name` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `registration_cookie_name`, `pre_auth_cookie_name` | `seamless-ephemeral` | Sign-in flow cookie names |
| `deliver` | none | Sends OTP codes and magic links through your own transports |
| `resolve_client_ip` | the connecting peer | The end user's address. See below |
| `disable_manifest_fetch` | `False` | Use only the manifest bundled with this version |
| `http_client` | 15 second timeout, no redirects | Outbound `httpx2.Client` |

### Client IP

The adapter forwards the end user's address and user agent so the auth API rate limits and
audits against the user, not your server. Behind a proxy, name it:

```python
from seamless_auth import TrustedProxies

auth = Adapter(..., resolve_client_ip=TrustedProxies(["10.0.0.0/8"]))
```

`TrustedProxies` walks `X-Forwarded-For` from the right, skipping trusted proxies. There is
deliberately no hop-count option: a hop count cannot tell a proxy from a client that sent its
own header.

### Delivery

Without `deliver`, the auth API sends OTP codes and magic links itself. With it, the adapter
asks the API for the message and hands it to you:

```python
from seamless_auth import Delivery


def deliver(d: Delivery) -> None:
    mailer.send(d.to, d.kind, d.token, d.magic_link_url)


auth = Adapter(..., deliver=deliver)
```

An `async def` callback works too; under FastAPI it runs on the application's event loop. A
delivery error answers the request with 502 `delivery_failed`.

### The admin console

The adapter can serve the Seamless admin dashboard from your API, proxied from the auth API, so it
shares the origin and cookie scope of the `/auth` routes:

```python
# FastAPI
from seamless_auth.fastapi import console_router

app.include_router(console_router(auth))  # /console

# Django (urls.py)
from seamless_auth.django import console_urlpatterns

urlpatterns += [path("console/", include(console_urlpatterns))]
```

It serves `GET` and `HEAD` only and forwards nothing but the method and path, so the browser's
cookies never reach the upstream. It refuses any path that could leave the console (dot segments,
encoded separators), and follows a redirect only while it stays inside the console on the auth API.
When you serve it, add your API's origin to the auth server's `ORIGINS` so passkey ceremonies
started in the console verify.

## How it runs

The adapter is synchronous and thread-safe: one `Adapter` serves the whole process. Under FastAPI
the bindings run it on Starlette's threadpool, so it never blocks the event loop. Under Django it
runs in the request thread, on WSGI or ASGI. Refresh sharing (one rotation per refresh token,
handed to every parallel request for 5 seconds) works across threads.

## The manifest

On its first request the adapter fetches `/.well-known/seamless-adapter.json` from the auth API
(5 second timeout) and keeps it for the life of the process. If the API serves none, it uses the
copy bundled in this package and tries again a minute later. A manifest with anything this
version does not understand is refused whole, rather than following a route with the wrong token.
Refresh the bundled copy with `scripts/sync-manifest.sh`.

## Conformance

`conformance/` holds the FastAPI and Django reference apps the conformance suite drives. To run
one locally you need Docker, a checkout of `seamless-auth-api` and the `seamless` CLI:

```bash
PORT=8080 AUTH_SERVER_URL=http://localhost:5312 AUTH_SERVER_ISSUER=http://auth-api:5312 \
  API_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  uv run python conformance/fastapi_app.py &   # or conformance/django_app.py

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0
