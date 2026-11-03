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

For an API that only checks access tokens from the Seamless OpenID Provider, the package also has a
[verify-only mode](#verify-only-resource-servers) that needs just the issuer and an audience.

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
    service_secret=os.environ["SEAMLESS_SERVICE_TOKEN"],  # the API's API_SERVICE_TOKEN value
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

The auth server reads the service token from `API_SERVICE_TOKEN` and your app reads it from
`SEAMLESS_SERVICE_TOKEN`; both hold the same value.

`RequireUser` answers 401 unless the request carries a session, and returns the `User`. It
answers 403 for a recovery session (see [Recovery sessions](#recovery-sessions)) unless you pass
`RequireUser(auth, allow_recovery=True)`. `RequireUser(auth, roles=["admin"])` also requires a role
(see [Roles](#roles)).

`OptionalUser(auth)` is for routes that serve signed-in and anonymous visitors alike. It returns
the `User` exactly when `RequireUser(auth)` would admit the request, and `None` otherwise (no
session, a recovery session, or a cross-site state change on the cookie). It never answers an
error.

```python
from seamless_auth.fastapi import OptionalUser

maybe_user = OptionalUser(auth)


@app.get("/")
def home(user: User | None = Depends(maybe_user)):
    return {"signed_in": user is not None}
```

## Django

```python
# settings.py
SEAMLESS_AUTH = {
    "auth_server_url": os.environ["AUTH_SERVER_URL"],
    "cookie_secret": os.environ["COOKIE_SECRET"],
    "service_secret": os.environ["SEAMLESS_SERVICE_TOKEN"],
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

`@require_auth(allow_recovery=True)` admits a recovery session too (see
[Recovery sessions](#recovery-sessions)), and `@require_auth(roles=["admin"])` also requires a role
(see [Roles](#roles)). `user_of(request)` reads the `User` the guard put on the request; call it
only under `require_auth`, as it raises `AttributeError` on an unguarded request.

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

The session cookie is signed with `cookie_secret`, and the guard also verifies the auth API access
token inside it against the API's key set, as it does a bearer token: RS256, the expected issuer
and audience, in date, `typ: access`, and the same `sub` as the cookie. `User.roles` and
`User.recovery` come from that verified token, not from the cookie, so a forged cookie cannot carry
claims of its own even if the cookie secret leaks. The first request with a new key fetches the key
set, and when it cannot be fetched the guard answers 401.

A request the guard admits on the session cookie also gets the auth routes' cross-site check, for
methods other than `GET`, `HEAD` and `OPTIONS`, whatever the `same_site` setting (a sibling
subdomain is same-site, so `SameSite=Lax` or `Strict` still sends it the cookies):

- `Sec-Fetch-Site: cross-site` answers 403.
- `Sec-Fetch-Site: same-origin` (or `none`) passes.
- `Sec-Fetch-Site: same-site` also covers a sibling subdomain, and a request with no
  `Sec-Fetch-Site` could come from anywhere, so for both the `Origin` decides. `Origin: null`
  answers 403. When `allowed_origins` is set, the request must carry an `Origin` on that list, or
  it answers 403. Without `allowed_origins` it passes, and on the auth routes the body rule below
  is what stops a form.
- A request with neither `Sec-Fetch-Site` nor `Origin` is not a browser form, so it passes, with
  or without `allowed_origins`. On the auth routes the body rule below still applies to it.
- `allowed_origins=[]` is strict: no `Origin` is on it, so a same-site request, or one with an
  `Origin` and no `Sec-Fetch-Site`, answers 403.

A bearer token is never attached by a browser, so the guard does not check a request it admits on
one. The auth routes check every state change, bearer transport (`x-seamless-auth-transport:
bearer`) included, as the other adapters do. A native client sends neither `Sec-Fetch-Site` nor
`Origin`, so it passes.

`User.organization_id` is the active organization, from the `org_id` claim of the verified access
token, or `None` when the session has none. Like `User.roles`, it never comes from the cookie.

### Roles

`roles` on the guard (`RequireUser(auth, roles=[...])`, `@require_auth(roles=[...])`) admits a
session when any one of the user's roles grants any one listed role, by `role_grants_access` (the
port of `roleGrantsAccess` in `@seamless-auth/types`): `org:*` grants `org` and `org:billing`, an
unscoped `org` grants `org:billing`, and `projects:write` grants `projects:read`. The roles come
from the verified access token. A session granted none answers 403
`{ "error": "insufficient_role" }` (FastAPI: `{ "detail": "insufficient_role" }`), after the
session, recovery and cross-site checks, and the body never names the roles. An empty `roles`
list raises `ValueError` when the guard is built.

```python
@app.get("/api/admin")
def admin(user: User = Depends(RequireUser(auth, roles=["admin"]))):
    return {"id": user.id}
```

```python
@require_auth(roles=["admin", "billing:write"])
def billing(request):
    return JsonResponse({"org": user_of(request).organization_id})
```

`Adapter.authenticate_request(method, headers, roles=[...])` and `Adapter.authenticate(headers,
roles=[...])` raise `InsufficientRole`; `has_any_role(user, roles)` is the check on its own.

### Recovery sessions

A user who signs in with a recovery code, or completes self-service account recovery, gets a
recovery session: its access token carries `recovery: true`, and the auth API refuses it on
everything but enrolling a new passkey or authenticator app until they do. The guard refuses it
too, with 403 `{ "error": "enrollment_required" }` (FastAPI's `RequireUser` answers `{ "detail":
"enrollment_required" }`, as it does its other errors), so an application never treats a
half-recovered account as signed in. Allow it on the routes that guide the user through
enrollment with `allow_recovery=True`, and read `User.recovery` there.
`Adapter.authenticate` raises `EnrollmentRequired`, a subclass of `Unauthenticated`.

When a recovery session in cookie transport completes `POST /webauthn/register/finish` or
`POST /totp/enroll/verify`, the adapter refreshes the session in the same response, so the
access cookie drops the claim at once. If that refresh fails, the enrollment still answers as the
auth API did and the cookie keeps the claim until the next refresh. A bearer client holds its own
refresh token, so it calls `POST /auth/refresh` itself after enrolling.

### Request bodies

The auth routes forward a request body to the auth API as JSON, so a body must be sent as
`application/json` (or a `+json` type). Anything else answers 415 `unsupported_media_type`: a
cross-site form can post a `text/plain` body shaped like JSON with no CORS preflight, and read as
JSON it would be a sign-in the user never made.

A state change on an auth route (any method but `GET`, `HEAD` and `OPTIONS`) needs that content
type even with no body, or else an `x-seamless-auth-transport` header (`cookie` or `bearer`).
Either one forces a CORS preflight, which a form on a sibling subdomain cannot send, so a body-less
form post answers 415 too. `POST /auth/refresh`, `DELETE /auth/logout` and
`DELETE /auth/logout/all` are exempt, though they still get the cross-site check.

## Options

| Argument | Default | Purpose |
| --- | --- | --- |
| `auth_server_url` | required | Where the adapter reaches the auth API |
| `auth_server_issuer` | the URL | Expected `iss` of the API's tokens, when it differs from the URL you reach it at |
| `audience` | the issuer | Expected `aud` of the API's tokens |
| `cookie_secret` | required | Signs the session cookies (32 bytes or more, and not a placeholder) |
| `service_secret` | required | The service token, read from `SEAMLESS_SERVICE_TOKEN` in the examples; the same value as the API's `API_SERVICE_TOKEN` (32 bytes or more, and not a placeholder) |
| `jwks_kid` | `dev-main` | `kid` header on service tokens |
| `cookie_domain` | none | Cookie `Domain` |
| `insecure_cookies` | `False` | Drops `Secure`, and allows placeholder secrets, for local development over HTTP |
| `same_site` | `None`, or `Lax` with `insecure_cookies` | Cookie `SameSite` |
| `allowed_origins` | none | The only origins allowed to change state from a same-site page or without fetch metadata; `[]` allows none |
| `access_cookie_name`, `refresh_cookie_name` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `registration_cookie_name`, `pre_auth_cookie_name` | `seamless-ephemeral` | Sign-in flow cookie names |
| `deliver` | none | Sends OTP codes and magic links through your own transports |
| `deliver_account_notices` | `False` | `deliver` also sends account notices to the owner (below) |
| `resolve_client_ip` | the connecting peer | The end user's address. See below |
| `disable_manifest_fetch` | `False` | Use only the manifest bundled with this version |
| `http_client` | 15 second timeout, no redirects | Outbound `httpx2.Client` |

The adapter refuses to start with a known placeholder for either secret, such as the starters'
`dev-only-cookie-signing-key-replace-me`, `GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV`, or anything
containing `replace-me`, unless `insecure_cookies` is set.

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
delivery error answers the request with 502 `delivery_failed`. A delivery kind this version does
not know is logged and skipped.

An OTP code from `POST /recovery/start` carries `purpose="account_recovery"`
(`Delivery.is_account_recovery`): word that message as an account recovery code, with a warning
to ignore it if the user did not ask, not as a sign-in code.

An `enrollment_invite_email` carries `sign_in_url`, the `signInUrl` of
`SendEnrollmentInviteEmailInput` in `@seamless-auth/types`: the sign-in page, which signs nobody
in on its own.

#### Account notices

When account recovery opens (`POST /recovery/verify`), the auth API tells the account's owner at
every verified address, with a link that cancels it. It sends those notices itself unless you
take them on as well:

```python
auth = Adapter(..., deliver=deliver, deliver_account_notices=True)
```

Then `deliver` also receives `account_notice_email` (`to`, `subject`, `text`, `notice`,
`cancel_url`) and `account_notice_sms` (`to`, `text`, `notice`, `cancel_url`), one call per
address. The auth API counts a notice it hands back as the owner being told, so turn this on only
when `deliver` sends both kinds. `cancel_url` (and `text`, which contains it) is a credential that
cancels the recovery: send it only to `to`, and never log it. Every notice is attempted. One that
gets through is enough, and the request answers as the auth API did. If none does, the owner has
not been told, so the adapter cancels the recovery request (`POST /recovery/cancel` with the token
from the cancel link) and answers 503 `recovery_notice_failed`, as the auth API itself would.
Without the option, routes that carry notices are called without external delivery, so the auth
API sends them through its own transports.

#### Unsubscribe headers

The adapter hands you what the auth API asked for; your mailer builds and sends the email. So
custom headers, such as the one-click unsubscribe pair from
[RFC 8058](https://www.rfc-editor.org/rfc/rfc8058), are set in your own sender, not passed through
the adapter. Sign-in codes, magic links and enrollment invites are transactional and do not need
them; mail your application sends on its own, such as release notes, does:

```python
from email.message import EmailMessage

msg = EmailMessage()
msg["To"] = user.email
msg["Subject"] = "What's new"
msg["List-Unsubscribe"] = f"<https://app.example.com/unsubscribe?t={token}>"
msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
msg.set_content(body)
smtp.send_message(msg)
```

The unsubscribe URL must be HTTPS and accept a POST with no further confirmation. Refuse header
values that contain a CR or LF, and never let a caller set From, To, Cc, Bcc, Subject or
Content-Type through custom headers, as `@seamless-auth/messaging` does.

### Magic links

The auth API signs a user in from a magic link only on the device that asked for it. On
`GET /magic-link/verify/{token}` the adapter forwards that device's pre-auth token when it has
one: the client's own bearer token in bearer transport, or the pre-auth cookie in cookie
transport if it verifies. Without one it sends none, and never answers 401, because the API
falls back to the client address and user agent the adapter forwards.

Opened anywhere else, the link answers 409 `confirmation_required`, with `requestedFrom`
(`deviceClass`, `requestedAt`) describing the request, and is not consumed. Once the user
approves it, `POST /magic-link/verify/{token}/confirm` consumes it. The requesting attempt's
first `GET /magic-link/check` after that issues the session; later checks answer
`{ "message": "Success" }` with no tokens, and the adapter then leaves the cookies as they are.

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
It keeps the auth API's `X-Frame-Options`, `Content-Security-Policy` and `X-Content-Type-Options`,
so the console cannot be framed on your origin. When you serve it, add your API's origin to the auth server's `ORIGINS` so passkey ceremonies
started in the console verify.

## Verify-only resource servers

An API that only receives access tokens from the Seamless OpenID Provider (RFC 9068 JWTs, sent as
`Authorization: Bearer`) needs none of the adapter: no cookies, no service secret, no auth routes.
`ResourceServer` takes the provider's issuer and this API's resource identifier, and nothing else:

```python
from seamless_auth import ResourceServer

rs = ResourceServer(
    issuer="https://login.example.com",  # the API's oidc_issuer
    audience="https://api.example.com",  # this API's resource identifier
)
```

### FastAPI

```python
from fastapi import Depends, FastAPI
from seamless_auth import VerifiedUser, require_role, require_scope, require_step_up
from seamless_auth.fastapi import RequireBearer, add_bearer_error_handler

app = FastAPI()
add_bearer_error_handler(app)

read_orders = RequireBearer(rs, require_scope("orders:read"))
refund = RequireBearer(
    rs, require_scope("orders:write"), require_step_up(acr_values=["phr"], max_age=300)
)


@app.get("/orders")
def orders(user: VerifiedUser = Depends(read_orders)):
    return {"sub": user.sub, "org": user.org_id}


@app.post("/orders/{id}/refund")
def refund_order(id: str, user: VerifiedUser = Depends(refund)): ...
```

`RequireBearer(rs, *guards)` verifies the token, runs the guards in order, and returns the
`VerifiedUser`. `add_bearer_error_handler(app)` answers refusals with the JSON bodies below; without
it FastAPI still sends the status and `WWW-Authenticate`, with the body under `detail`.

### Django

```python
# settings.py
SEAMLESS_RESOURCE_SERVER = {
    "issuer": os.environ["OIDC_ISSUER"],
    "audience": os.environ["API_AUDIENCE"],
}

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from seamless_auth.django import bearer_user_of, require_bearer, require_scope, require_step_up


@require_bearer
@require_scope("orders:read")
def orders(request):
    return JsonResponse({"sub": bearer_user_of(request).sub})


@csrf_exempt  # bearer only: no cookie for a cross-site request to ride on
@require_bearer
@require_scope("orders:write")
@require_step_up(acr_values=["phr"], max_age=300)
def refund(request, id): ...
```

`SEAMLESS_RESOURCE_SERVER` takes the keyword arguments of `ResourceServer`; `confirm` may be a
dotted path. `@require_bearer` (or `@require_bearer(server=rs)`) verifies the token and puts the
`VerifiedUser` on the request; the guard decorators go beneath it and run top to bottom. A guard
with no `@require_bearer` above it answers as if there were no token. All of them work on sync and
async views.

### What is verified

A token passes only if all of these hold, and anything else answers 401 `invalid_token`:

- A compact JWS with header `alg: RS256`, `typ` of `at+jwt` or `application/at+jwt` (any case),
  a `kid`, and no `crit`.
- Signed by the key with that `kid` in the provider's key set, an RSA key whose `use` (if
  present) is `sig` and whose `alg` (if present) is `RS256`.
- `iss` equal to `issuer` exactly, and `aud` equal to `audience` or a list containing it.
- In date: `exp` required, `nbf` optional, with 5 seconds of clock skew.
- A non-empty `sub` and `client_id`, and no first-party `typ` claim.
- No `cnf` (a sender-constrained token), unless a `confirm` hook accepts it (below).
- `scope`, `acr`, `sid` strings, `amr` and `roles` lists of strings, `auth_time` a number and
  `org_id` a string or null, where present.

Keys come from `jwks_uri` when you pass one. Otherwise the first request fetches
`<issuer>/.well-known/openid-configuration` (5 second timeout, 256 KiB at most), which must name
the same `issuer` and an http(s) `jwks_uri` (https under an https issuer). Discovery succeeds once
per process; a failure answers 401 and is retried at most every 5 seconds. The key set is cached
as the adapter caches the auth API's: a new `kid` refetches it at most every 30 seconds, and it is
fetched again after 10 minutes.

`VerifiedUser` carries `sub`, `client_id`, `scopes` (the `scope` claim split on spaces), `roles`,
`sid`, `org_id`, `acr`, `amr`, `auth_time`, `exp`, `iat`, the raw `token` and every `claims`. A
client credentials token (`sub == client_id`, no user claims) is valid, and fails role and step-up
guards.

### Guards

| Guard | Passes when | Otherwise |
| --- | --- | --- |
| `require_scope(*scopes)` | every scope is in `scopes`, exactly | 403 `{"error":"insufficient_scope","scope":"a b"}`, `WWW-Authenticate: Bearer error="insufficient_scope", scope="a b"` |
| `require_role(*roles)` | any role is granted (`x:*` grants `x` and under, `billing` grants `billing:...`, `p:write` grants `p:read`) | 403 `{"error":"insufficient_role"}` |
| `require_step_up(acr_values=, amr=, max_age=)` | `acr` is one of `acr_values` (`phr` also accepts `phrh`), every `amr` is present, and at most `max_age` seconds since `auth_time` | 401 `insufficient_user_authentication` (RFC 9470) |

A missing token, a scheme other than `Bearer` or more than one token answers 401
`{"error":"missing_token"}` with `WWW-Authenticate: Bearer`. A step-up refusal names what the client
must ask the provider for, so it can send the user to sign in again:

```
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="More recent authentication is required", acr_values="phr", max_age="300"
```

with the same fields in the JSON body (`max_age` as a number). `role_grants_access(granted,
required)` is the role matching on its own.

### Sender-constrained tokens

A token with a `cnf` claim is bound to a key the client must prove it holds (DPoP), so it is
refused unless you pass `confirm`. The hook gets the `cnf` value and a `BearerRequest` (method,
headers, absolute URL), and accepts the token by returning `True`. Anything else, including an
exception, refuses it:

```python
def confirm(cnf, request):
    return check_dpop_proof(cnf["jkt"], request.headers.get("DPoP"), request.method, request.url)


rs = ResourceServer(issuer=..., audience=..., confirm=confirm)
```

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
  SEAMLESS_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  uv run python conformance/fastapi_app.py &   # or conformance/django_app.py

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0

Project governance, including the
[Seamless Auth License Pledge](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md#the-seamless-auth-license-pledge),
is in the fells-code [GOVERNANCE.md](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md).
