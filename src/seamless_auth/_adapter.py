"""The adapter: configuration, the request pipeline, and the guard."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import threading
import time
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx2

from ._client_ip import TrustedProxies, client_user_agent, parse_ip
from ._cookies import (
    KIND_ACCESS,
    KIND_REFRESH,
    CookieWrite,
    clear_cookie,
    cookie_kind,
    ephemeral_cookie,
    raw_cookie,
    read_cookie,
    session_cookies,
    set_cookie,
)
from ._delivery import Delivery, parse_delivery
from ._http import AuthRequest, AuthResponse, Headers
from ._jwks import BodyTooLarge, JwksCache, TokenError, read_limited
from ._jwt import Claims, sign_hs256, str_claim, unverified_claims
from ._manifest import ManifestRoute, ManifestSource, RouteMatch
from ._refresh import Refresher, RefreshOutcome

if TYPE_CHECKING:
    from ._console import Console

log = logging.getLogger("seamless_auth")

MIN_SECRET_LENGTH = 32
UPSTREAM_TIMEOUT = 15.0
MAX_BODY_BYTES = 1 << 20
TRANSPORT_HEADER = "x-seamless-auth-transport"
DELIVERY_MODE_HEADER = "x-seamless-auth-delivery-mode"

# The auth API validates service tokens against a fixed issuer and audience,
# whatever the adopter's own audience is.
SERVICE_ISSUER = "seamless-portal-api"
SERVICE_AUDIENCE = "seamless-auth"
SERVICE_TTL = 60
PROXY_SUBJECT = "seamless-auth-python-adapter"
DELIVERY_SUBJECT = "seamless-auth-external-delivery"
# Reused for a little less than its lifetime, so a request never signs a fresh
# token and never presents one that expires in flight.
PROXY_REUSE = 45.0

_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_DOMAIN = re.compile(r"^[A-Za-z0-9.\-]+$")
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

ClientIpResolver = Callable[[Headers, str | None], str | None]
Deliver = Callable[[Delivery], Any]


@dataclass(frozen=True)
class User:
    """The session a request was authenticated with."""

    id: str
    roles: tuple[str, ...] = ()
    email: str | None = None
    phone: str | None = None
    #: The auth API access token, for calling the API on the user's behalf.
    token: str = field(default="", repr=False)


class Unauthenticated(Exception):
    """A request carried no valid session."""


class CrossSiteRequest(Exception):
    """A state-changing request from another site, carrying a session cookie."""


@dataclass
class Config:
    auth_server_url: str
    auth_server_issuer: str
    audience: str
    cookie_secret: str = field(repr=False)
    service_secret: str = field(repr=False)
    jwks_kid: str
    cookie_domain: str | None
    secure_cookies: bool
    same_site: str
    allowed_origins: tuple[str, ...]
    access_cookie_name: str
    registration_cookie_name: str
    refresh_cookie_name: str
    pre_auth_cookie_name: str

    def cookie_name(self, held: str) -> str:
        """The cookie a held credential lives in."""
        return {
            "access": self.access_cookie_name,
            "registration": self.registration_cookie_name,
            "refresh": self.refresh_cookie_name,
        }.get(held, self.pre_auth_cookie_name)


@dataclass
class _Reply:
    status: int
    body: Any = None
    raw: httpx2.Response | None = None
    set: list[CookieWrite] = field(default_factory=list)
    clear: list[str] = field(default_factory=list)


def _error(status: int, code: str) -> _Reply:
    return _Reply(status, {"error": code})


@dataclass
class _Forwarded:
    ip: str | None
    user_agent: str | None


class Adapter:
    """Serves the Seamless Auth routes and guards the application's own.

    Thread-safe: one adapter serves every request in the process.
    """

    def __init__(
        self,
        *,
        auth_server_url: str,
        cookie_secret: str,
        service_secret: str,
        jwks_kid: str | None = None,
        auth_server_issuer: str | None = None,
        audience: str | None = None,
        cookie_domain: str | None = None,
        insecure_cookies: bool = False,
        same_site: str | None = None,
        allowed_origins: Iterable[str] = (),
        access_cookie_name: str = "seamless-access",
        refresh_cookie_name: str = "seamless-refresh",
        # Shares the registration cookie on purpose: registration and sign-in never
        # hold an ephemeral cookie at the same time.
        registration_cookie_name: str = "seamless-ephemeral",
        pre_auth_cookie_name: str = "seamless-ephemeral",
        deliver: Deliver | None = None,
        resolve_client_ip: ClientIpResolver | TrustedProxies | None = None,
        disable_manifest_fetch: bool = False,
        http_client: httpx2.Client | None = None,
    ) -> None:
        url = (auth_server_url or "").strip().rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("seamless-auth: auth_server_url must be an http or https URL")
        if len((cookie_secret or "").encode()) < MIN_SECRET_LENGTH:
            raise ValueError(
                f"seamless-auth: cookie_secret must be at least {MIN_SECRET_LENGTH} bytes"
            )
        if len((service_secret or "").encode()) < MIN_SECRET_LENGTH:
            raise ValueError(
                f"seamless-auth: service_secret must be at least {MIN_SECRET_LENGTH} bytes"
            )
        for name in (
            access_cookie_name,
            refresh_cookie_name,
            registration_cookie_name,
            pre_auth_cookie_name,
        ):
            if not _COOKIE_NAME.match(name or ""):
                raise ValueError(f"seamless-auth: invalid cookie name {name!r}")
        if cookie_domain is not None and not _COOKIE_DOMAIN.match(cookie_domain):
            raise ValueError(f"seamless-auth: invalid cookie domain {cookie_domain!r}")
        if same_site is None:
            same_site = "Lax" if insecure_cookies else "None"
        if same_site not in ("Strict", "Lax", "None"):
            raise ValueError("seamless-auth: same_site must be Strict, Lax or None")
        if not jwks_kid:
            log.warning(
                '[seamless-auth] jwks_kid is not set and defaults to "dev-main", a '
                "placeholder. Set it to name the service-token key explicitly."
            )
            jwks_kid = "dev-main"

        issuer = auth_server_issuer or url
        self._config = Config(
            auth_server_url=url,
            auth_server_issuer=issuer,
            audience=audience or issuer,
            cookie_secret=cookie_secret,
            service_secret=service_secret,
            jwks_kid=jwks_kid,
            cookie_domain=cookie_domain,
            secure_cookies=not insecure_cookies,
            same_site=same_site,
            allowed_origins=tuple(allowed_origins),
            access_cookie_name=access_cookie_name,
            registration_cookie_name=registration_cookie_name,
            refresh_cookie_name=refresh_cookie_name,
            pre_auth_cookie_name=pre_auth_cookie_name,
        )
        # A client that follows redirects would carry the service token to wherever
        # the auth API pointed it.
        self._client = http_client or httpx2.Client(
            timeout=UPSTREAM_TIMEOUT, follow_redirects=False
        )
        # A supplied client with no timeout at all still gets one: a call that never
        # returns would hold a refresh flight, and every tab waiting on it.
        t = self._client.timeout
        unbounded = all(v is None for v in (t.connect, t.read, t.write, t.pool))
        self._timeout: dict[str, Any] = {"timeout": UPSTREAM_TIMEOUT} if unbounded else {}
        _redact_upstream_urls(url)
        self._deliver = _sync_deliver(deliver) if deliver is not None else None
        self._resolve_client_ip = resolve_client_ip
        self._jwks = JwksCache(url, self._client)
        self._manifest = ManifestSource(url, self._client, not disable_manifest_fetch)
        self._refreshes = Refresher()
        self._proxy_token: tuple[str, float] | None = None
        self._console: Console | None = None

    def __repr__(self) -> str:
        return f"Adapter(auth_server_url={self._config.auth_server_url!r})"

    @property
    def config(self) -> Config:
        return self._config

    def console(self, method: str, path: str, query: str = "") -> AuthResponse:
        """Serves the Seamless admin dashboard, proxied from the auth API, so it
        loads from the same origin as the cookie-based auth routes. ``path`` is the
        raw path below /console. GET and HEAD only; nothing is forwarded but the
        method and path, and no path can leave the console. Blocking: run it on a
        worker thread from async code."""
        from ._console import Console  # noqa: PLC0415  (imports this module)

        if self._console is None:
            self._console = Console(self)
        return self._console.handle(method, path, query)

    # The request pipeline.

    def handle(self, request: AuthRequest) -> AuthResponse:
        """Serves one request to the auth routes. Blocking: run it on a worker
        thread from async code."""
        try:
            return self._handle(request)
        except Exception as err:
            # The type only, and no traceback for an error reporter to capture: the
            # frames hold the user's tokens and a service token.
            log.error(
                "[seamless-auth] %s %s failed: %s", request.method, request.path, type(err).__name__
            )
            return _json_response(500, {"error": "internal_error"})

    def _handle(self, request: AuthRequest) -> AuthResponse:
        blocked = self._check_origin(request.method, request.headers)
        if blocked is not None:
            return self._write(blocked, bearer=False)

        bearer = (request.headers.get(TRANSPORT_HEADER) or "").lower() == "bearer"
        forwarded = self._forwarded(request)
        method = request.method.upper()
        # Matched on segments, as manifest routes are, so /logout/ and //logout are
        # still logout and never fall through to a route that clears less.
        special = "/".join(s for s in request.path.split("/") if s).lower()

        if method == "POST" and special == "refresh":
            reply = self._refresh_route(request.headers, forwarded, bearer)
        elif method == "DELETE" and special in ("logout", "logout/all"):
            reply = self._logout_route(request.headers, forwarded, bearer, f"/{special}")
        else:
            found = self._manifest.get().find(method, request.path)
            if found is None:
                reply = _error(404, "not_found")
            else:
                reply = self._manifest_route(request, forwarded, found, bearer)
        return self._write(reply, bearer)

    def _forwarded(self, request: AuthRequest) -> _Forwarded:
        if self._resolve_client_ip is not None:
            ip = self._resolve_client_ip(request.headers, request.peer)
        else:
            ip = request.peer
        parsed = parse_ip(ip)
        return _Forwarded(str(parsed) if parsed else None, client_user_agent(request.headers))

    def _write(self, reply: _Reply, bearer: bool) -> AuthResponse:
        """Applies a reply. Clears go before sets, because a reply that does both is
        replacing a session rather than ending one. Bearer transport writes no
        cookies at all."""
        headers: list[tuple[str, str]] = []
        cookies = []
        if not bearer:
            cookies = [clear_cookie(self._config, name) for name in dict.fromkeys(reply.clear)]
            for cookie in reply.set:
                try:
                    cookies.append(set_cookie(self._config, cookie))
                except Exception as err:
                    log.error("[seamless-auth] Could not issue cookie %s: %s", cookie.name, err)
                    return _json_response(500, {"error": "internal_error"})

        if reply.raw is not None:
            raw = reply.raw
            for name in ("content-type", "content-disposition", "cache-control"):
                value = raw.headers.get(name)
                if value:
                    headers.append((name, value))
            return AuthResponse(reply.status, headers, _stream(raw), raw.close, cookies)
        if reply.body is None:
            return AuthResponse(reply.status, headers, b"", cookies=cookies)
        response = _json_response(reply.status, reply.body)
        response.cookies = cookies
        return response

    # Upstream calls.

    def _call(
        self,
        forwarded: _Forwarded,
        method: str,
        path: str,
        *,
        query: str = "",
        body: bytes | None = None,
        authorization: str | None = None,
        service: str | None = None,
        external_delivery: bool = False,
        stream: bool = False,
    ) -> httpx2.Response:
        url = f"{self._config.auth_server_url}{path}"
        if query:
            url = f"{url}?{query}"
        headers = {"accept": "application/json"}
        content = None
        if body is not None and method != "GET":
            headers["content-type"] = "application/json"
            content = body
        if authorization:
            headers["authorization"] = authorization
        if service:
            headers["x-seamless-service-token"] = service
        if forwarded.ip:
            headers["x-seamless-client-ip"] = forwarded.ip
        if forwarded.user_agent:
            headers["x-seamless-client-user-agent"] = forwarded.user_agent
        if external_delivery:
            headers[DELIVERY_MODE_HEADER] = "external"
        try:
            request = self._client.build_request(
                method, url, headers=headers, content=content, **self._timeout
            )
            return self._client.send(request, stream=stream)
        except (httpx2.HTTPError, httpx2.InvalidURL, UnicodeError, ValueError) as err:
            # The type only: the text of these holds the URL, and a path or query
            # can hold a magic-link token or an OAuth code.
            raise _UpstreamError(type(err).__name__) from None

    def _sign_service(self, subject: str, extra: Claims | None = None) -> str:
        claims = {**(extra or {}), "iss": SERVICE_ISSUER, "aud": SERVICE_AUDIENCE, "sub": subject}
        token = sign_hs256(claims, self._config.service_secret, SERVICE_TTL, self._config.jwks_kid)
        return f"Bearer {token}"

    def _proxy_authorization(self) -> str:
        """Lets the auth API trust the client address and user agent this adapter
        forwards."""
        cached = self._proxy_token
        if cached is not None and time.monotonic() < cached[1]:
            return cached[0]
        token = self._sign_service(PROXY_SUBJECT)
        self._proxy_token = (token, time.monotonic() + PROXY_REUSE)
        return token

    # Credentials and sessions.

    def _credential_for(
        self, headers: Headers, forwarded: _Forwarded, kind: str, bearer: bool
    ) -> tuple[str | None, list[CookieWrite]] | _Reply:
        """Resolves the held token a route names. In cookie transport it reads the
        route's cookie, refreshing a missing access token from the refresh cookie;
        in bearer transport the client holds its own token."""
        if kind == "none":
            return None, []
        if bearer:
            token = _bearer_token(headers)
            if token is None:
                return _error(401, f"{kind} session required")
            return f"Bearer {token}", []

        name = self._config.cookie_name(kind)
        has_cookie = raw_cookie(headers, name) is not None
        payload = read_cookie(self._config, headers, name, cookie_kind(kind))
        token = str_claim(payload, "token")
        if payload is not None and token:
            return f"Bearer {token}", []

        # A refresh only ever yields an access token, so only the access cookie can
        # be restored from it. Spending it for a pre-auth or registration route
        # would store an access token under that route's cookie. A cookie that fails
        # verification is refused rather than refreshed past.
        if kind == "access" and (not has_cookie or payload is not None):
            refreshed = self._silent_refresh(headers, forwarded)
            if isinstance(refreshed, tuple):
                session, cookies = refreshed
                return f"Bearer {str_claim(session, 'token')}", cookies
            if refreshed != _NO_REFRESH_COOKIE:
                log.debug("[seamless-auth] Silent refresh failed: %s", refreshed)
                reply = _error(401, "Refresh failed")
                reply.clear = [
                    self._config.access_cookie_name,
                    self._config.registration_cookie_name,
                    self._config.refresh_cookie_name,
                ]
                return reply

        if has_cookie:
            return _error(401, f"Invalid or expired {name} cookie")
        return _error(401, f'Missing required cookie "{name}"')

    def _verify_session(self, session: Claims, typ: str) -> str:
        """Checks the token in a session response: signed by the auth API, of the
        expected type, and belonging to the subject the body names. Returns the
        session id. A response that fails any of these is one this adapter cannot
        vouch for, so nothing is issued from it."""
        claims = self._jwks.verify(
            str_claim(session, "token"), self._config.auth_server_issuer, self._config.audience
        )
        if str_claim(claims, "typ") != typ:
            raise TokenError("unexpected token type")
        subject = str_claim(claims, "sub")
        if not subject or subject != str_claim(session, "sub"):
            raise TokenError("token subject does not match the response")
        return str_claim(claims, "sid")

    def _manifest_route(
        self, request: AuthRequest, forwarded: _Forwarded, found: RouteMatch, bearer: bool
    ) -> _Reply:
        route = found.route
        if route.credential == "refresh":
            return _error(404, "not_found")
        if request.body_too_large:
            return _error(413, "payload_too_large")
        body = request.body if request.body and request.body.strip() else None
        # The body goes upstream as JSON, so it has to be JSON. A cross-site form can
        # send a text/plain body shaped like JSON with no CORS preflight; read as
        # JSON, that would be a sign-in the victim never made.
        if body is not None and not _is_explicit_json(request.headers.get("content-type")):
            return _error(415, "unsupported_media_type")

        credential = self._credential_for(request.headers, forwarded, route.credential, bearer)
        if isinstance(credential, _Reply):
            return credential
        authorization, cookies = credential

        external = route.delivery and self._deliver is not None
        try:
            res = self._call(
                forwarded,
                route.method,
                route.upstream_path(found.params),
                query=request.query,
                body=body,
                authorization=authorization,
                service=(
                    self._sign_service(DELIVERY_SUBJECT)
                    if external
                    else self._proxy_authorization()
                ),
                external_delivery=external,
                stream=True,
            )
        except _UpstreamError as err:
            log.warning("[seamless-auth] %s %s: %s", route.method, route.path, err)
            return _Reply(502, {"error": "upstream_unavailable"}, set=cookies)

        success = 200 <= res.status_code < 300
        if success and not _is_json_content_type(res.headers.get("content-type")):
            return _Reply(res.status_code, raw=res, set=cookies)

        data, is_json = _read_json(res)
        if not success:
            failed = _failure(res.status_code, data, is_json)
            failed.set = cookies
            return failed

        if route.delivery and isinstance(data, dict):
            # The message is the application's to send. It never goes back to the
            # caller, in either transport.
            raw_delivery = data.pop("delivery", None)
            if raw_delivery is not None and external and self._deliver is not None:
                try:
                    self._deliver(parse_delivery(raw_delivery))
                except Exception as err:
                    log.warning(
                        "[seamless-auth] Delivery for %s %s failed: %s",
                        route.method,
                        route.path,
                        err,
                    )
                    return _Reply(502, {"error": "delivery_failed"}, set=cookies)

        reply = _Reply(res.status_code, set=cookies)
        reply.clear = [self._config.cookie_name(held) for held in route.clears]

        if route.issues and isinstance(data, dict) and _carries_session(data):
            try:
                session_id = self._verify_session(data, _issued_token_type(route.issues))
                if not bearer:
                    reply.set.extend(self._issued_cookies(route, data, session_id))
            except (TokenError, ValueError) as err:
                log.warning(
                    "[seamless-auth] Refusing an unverifiable session from %s %s: %s",
                    route.method,
                    route.path,
                    err,
                )
                return _error(502, "invalid_upstream_session")

        reply.body = data if bearer or data is None else _cookie_transport_body(route.pick, data)
        return reply

    def _issued_cookies(
        self, route: ManifestRoute, session: Claims, session_id: str
    ) -> list[CookieWrite]:
        issues = route.issues or ""
        if issues in ("preAuth", "registration"):
            return [ephemeral_cookie(self._config, issues, session)]
        return session_cookies(self._config, session, session_id, issues == "session")

    # Refresh and logout.

    def _rotate(self, forwarded: _Forwarded, refresh_token: str, service: str) -> RefreshOutcome:
        try:
            res = self._call(
                forwarded,
                "POST",
                "/refresh",
                authorization=f"Bearer {refresh_token}",
                service=service,
                stream=True,
            )
        except _UpstreamError as err:
            return RefreshOutcome(error=str(err))
        data, is_json = _read_json(res)
        if res.status_code != 200:
            return RefreshOutcome(status=res.status_code, body=data, is_json=is_json)
        if not isinstance(data, dict) or not _carries_session(data):
            return RefreshOutcome(error="refresh returned no session")
        return RefreshOutcome(session=data, status=200)

    def _silent_refresh(
        self, headers: Headers, forwarded: _Forwarded
    ) -> tuple[Claims, list[CookieWrite]] | str:
        """Rotates the session held in the refresh cookie."""
        name = self._config.refresh_cookie_name
        raw = raw_cookie(headers, name)
        if not raw:
            return _NO_REFRESH_COOKIE
        payload = read_cookie(self._config, headers, name, KIND_REFRESH)
        refresh_token = str_claim(payload, "refreshToken")
        if not refresh_token:
            return "invalid refresh cookie"
        service = self._sign_service(str_claim(payload, "sub"), {"refreshToken": refresh_token})

        outcome = self._refreshes.share(
            f"cookie:{raw}", lambda: self._rotate(forwarded, refresh_token, service)
        )
        if outcome.session is None:
            return outcome.error or f"refresh answered {outcome.status}"
        try:
            session_id = self._verify_session(outcome.session, "access")
            cookies = session_cookies(self._config, outcome.session, session_id, True)
        except (TokenError, ValueError) as err:
            return str(err)
        return outcome.session, cookies

    def _refresh_route(self, headers: Headers, forwarded: _Forwarded, bearer: bool) -> _Reply:
        if bearer:
            token = _bearer_token(headers)
            if token is None:
                return _error(401, "refresh token required")
            service = self._proxy_authorization()
            outcome = self._refreshes.share(
                f"bearer:{token}", lambda: self._rotate(forwarded, token, service)
            )
            if outcome.session is None:
                if outcome.error is not None:
                    return _error(502, "upstream_unavailable")
                return _failure(outcome.status, outcome.body, outcome.is_json)
            try:
                self._verify_session(outcome.session, "access")
            except TokenError:
                return _error(502, "invalid_upstream_session")
            return _Reply(200, outcome.session)

        refreshed = self._silent_refresh(headers, forwarded)
        if refreshed == _NO_REFRESH_COOKIE:
            return _error(401, "refresh token required")
        if not isinstance(refreshed, tuple):
            log.debug("[seamless-auth] Refresh failed: %s", refreshed)
            reply = _error(401, "invalid_refresh_token")
            reply.clear = [self._config.access_cookie_name, self._config.refresh_cookie_name]
            return reply
        session, cookies = refreshed
        return _Reply(200, _cookie_transport_body(None, session), set=cookies)

    def _logout_route(
        self, headers: Headers, forwarded: _Forwarded, bearer: bool, path: str
    ) -> _Reply:
        """Answers 204 and clears every held cookie, even when the auth API refuses,
        so a browser is never left holding a session it asked to end."""
        clears = [
            self._config.access_cookie_name,
            self._config.registration_cookie_name,
            self._config.refresh_cookie_name,
        ]
        credential = self._credential_for(headers, forwarded, "access", bearer)
        if isinstance(credential, _Reply):
            credential.clear = clears
            return credential
        try:
            res = self._call(
                forwarded,
                "DELETE",
                path,
                authorization=credential[0],
                service=self._proxy_authorization(),
                stream=True,
            )
        except _UpstreamError:
            return _Reply(502, {"error": "upstream_unavailable"}, clear=clears)
        res.close()
        status = 204 if 200 <= res.status_code < 300 else res.status_code
        return _Reply(status, clear=clears)

    # The guard.

    def authenticate(self, headers: Headers | Iterable[tuple[str, str]]) -> User:
        """Verifies a request's session: the adapter's access cookie, or an auth API
        access token in ``Authorization: Bearer`` for clients with no cookie jar.
        The cookie wins when present. It does not refresh: silent refresh belongs
        to the auth routes, and a bearer client refreshes through
        ``POST /auth/refresh`` itself. Raises :class:`Unauthenticated`."""
        return self._authenticate(_as_headers(headers))[0]

    def authenticate_request(
        self, method: str, headers: Headers | Iterable[tuple[str, str]]
    ) -> User:
        """:meth:`authenticate` for a guarded route. A session from the cookie also
        gets the auth routes' cross-site check, or a form on another site could act
        as the user: raises :class:`CrossSiteRequest` for one."""
        headers = _as_headers(headers)
        user, by_cookie = self._authenticate(headers)
        if by_cookie and self._check_origin(method, headers) is not None:
            raise CrossSiteRequest
        return user

    def _authenticate(self, headers: Headers) -> tuple[User, bool]:
        name = self._config.access_cookie_name
        if raw_cookie(headers, name):
            claims = read_cookie(self._config, headers, name, KIND_ACCESS)
            token = str_claim(claims, "token")
            if claims is None or not str_claim(claims, "sub") or not _is_access_token(token):
                raise Unauthenticated
            return _user_from(claims, token), True

        bearer = _bearer_token(headers)
        if bearer is None:
            raise Unauthenticated
        try:
            claims = self._jwks.verify(
                bearer, self._config.auth_server_issuer, self._config.audience
            )
        except TokenError as err:
            raise Unauthenticated from err
        # An ephemeral sign-in token is signed by the same key, so the type is what
        # keeps it from passing for a session.
        if str_claim(claims, "typ") != "access" or not str_claim(claims, "sub"):
            raise Unauthenticated
        return _user_from(claims, bearer), False

    def _check_origin(self, method: str, headers: Headers) -> _Reply | None:
        """Blocks cross-site state changes while cookies are SameSite=None, which is
        when the browser would otherwise attach them to such a request."""
        if self._config.same_site != "None":
            return None
        if method.upper() in ("GET", "HEAD", "OPTIONS"):
            return None
        blocked = _error(403, "cross_site_request_blocked")

        site = headers.get("sec-fetch-site")
        if site is not None:
            return blocked if site.lower() == "cross-site" else None
        origin = headers.get("origin")
        if origin is None:
            return None
        if origin == "null":
            return blocked
        if not self._config.allowed_origins:
            return None
        normalized = _normalize_origin(origin)
        if normalized and any(
            _normalize_origin(allowed) == normalized for allowed in self._config.allowed_origins
        ):
            return None
        return blocked


_NO_REFRESH_COOKIE = "no refresh cookie"


def _as_headers(headers: Headers | Iterable[tuple[str, str]]) -> Headers:
    return headers if isinstance(headers, Headers) else Headers(headers)


def _sync_deliver(deliver: Deliver) -> Callable[[Delivery], None]:
    """The adapter runs on a worker thread, and the callback may be async (an
    ``async def``, or anything that returns an awaitable)."""

    def run(delivery: Delivery) -> None:
        result = deliver(delivery)
        if inspect.isawaitable(result):
            _await_from_thread(result)

    return run


def _await_from_thread(awaitable: Awaitable[Any]) -> None:
    """Awaits on the event loop that owns this thread when there is one: anyio's
    under FastAPI, or Django's through asgiref, whose thread-sensitive executor a
    fresh loop would deadlock against. A fresh loop is the last resort."""
    started = False

    async def wait() -> None:
        nonlocal started
        started = True
        await awaitable

    try:
        from anyio import from_thread  # noqa: PLC0415  (optional: present under Starlette)

        from_thread.run(wait)
        return
    except ImportError:
        pass
    except RuntimeError:
        # Only when the loop could not be reached: a RuntimeError the callback raised
        # itself must not send the message a second time.
        if started:
            raise
    try:
        from asgiref.sync import async_to_sync  # noqa: PLC0415  (optional: present under Django)
    except ImportError:
        asyncio.run(wait())
        return
    async_to_sync(wait)()


class _UpstreamError(Exception):
    """A call to the auth API that could not be made or completed."""


class _RedactUpstreamUrls(logging.Filter):
    """httpx2 logs every request's full URL at INFO. For calls to the auth API that
    URL can hold a magic-link token or an OAuth code, so its path and query go."""

    def __init__(self, base: str) -> None:
        super().__init__()
        self._base = base

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(self._redact(arg) for arg in record.args)
        return True

    def _redact(self, arg: object) -> object:
        text = str(arg) if isinstance(arg, httpx2.URL | str) else None
        if text is not None and text.startswith(self._base):
            return f"{self._base}/[redacted]"
        return arg


_redacted_bases: set[str] = set()
_redaction_lock = threading.Lock()


def _redact_upstream_urls(base: str) -> None:
    with _redaction_lock:
        if base not in _redacted_bases:
            _redacted_bases.add(base)
            logging.getLogger("httpx2").addFilter(_RedactUpstreamUrls(base))


def _bearer_token(headers: Headers) -> str | None:
    header = headers.get("authorization") or ""
    if len(header) > 7 and header[:7].lower() == "bearer ":
        token = header[7:].strip()
        # A token is ASCII. Anything else could not be forwarded in a header anyway.
        if token and token.isascii() and token.isprintable():
            return token
    return None


def _is_access_token(token: str) -> bool:
    """Reads the type of the auth API token inside a session cookie. It was verified
    against the API's key set before the adapter signed it into the cookie, so its
    claims are read without verifying it again."""
    return bool(token) and str_claim(unverified_claims(token), "typ") == "access"


def _user_from(claims: Claims, token: str) -> User:
    roles = claims.get("roles")
    return User(
        id=str_claim(claims, "sub"),
        roles=tuple(r for r in roles if isinstance(r, str)) if isinstance(roles, list) else (),
        email=str_claim(claims, "email") or None,
        phone=str_claim(claims, "phone") or None,
        token=token,
    )


def _issued_token_type(issues: str) -> str:
    """The type of token a route that issues a session must return."""
    return "ephemeral" if issues in ("preAuth", "registration") else "access"


def _carries_session(body: dict[str, Any]) -> bool:
    return bool(str_claim(body, "token")) and bool(str_claim(body, "sub"))


def _cookie_transport_body(pick: tuple[str, ...] | None, body: Any) -> Any:
    """What a browser sees: a pick, or everything but tokens. The cookies carry
    every token, including the ephemeral one the auth API re-mints on an OTP send."""
    if not isinstance(body, dict):
        return body
    out = {k: body[k] for k in pick if k in body} if pick is not None else dict(body)
    out.pop("token", None)
    out.pop("refreshToken", None)
    return out


def _failure(status: int, body: Any, is_json: bool) -> _Reply:
    """Passes an upstream error through. Callers read fields off the auth API's own
    error body, so an object goes out as-is; anything else becomes a code they can
    still branch on."""
    if is_json and isinstance(body, dict):
        return _Reply(status, body)
    return _error(status, "upstream_error")


def _read_json(res: httpx2.Response) -> tuple[Any, bool]:
    """Reads a JSON response body. An empty body is None; a body that is not JSON
    reports False."""
    try:
        data = read_limited(res, MAX_BODY_BYTES)
    except (BodyTooLarge, httpx2.HTTPError):
        return None, False
    finally:
        res.close()
    if not data.strip():
        return None, True
    try:
        return json.loads(data), True
    except ValueError:
        return None, False


def _stream(res: httpx2.Response) -> Iterator[bytes]:
    # Decoded: only the content type and disposition go to the client, so bytes
    # still under the API's Content-Encoding would arrive unreadable.
    try:
        yield from res.iter_bytes()
    finally:
        res.close()


def _json_response(status: int, body: Any) -> AuthResponse:
    return AuthResponse(
        status,
        [("content-type", "application/json; charset=utf-8")],
        json.dumps(body, separators=(",", ":")).encode(),
    )


def _media_type(content_type: str) -> str | None:
    media_type = content_type.split(";", 1)[0].strip().lower()
    kind, sep, subtype = media_type.partition("/")
    if not sep or not _TOKEN.match(kind) or not _TOKEN.match(subtype):
        return None
    return media_type


def _is_json_content_type(content_type: str | None) -> bool:
    """application/json or a +json type. A download such as application/x-ndjson
    is not: parsing it would keep only its first line."""
    if content_type is None or not content_type.strip():
        return True
    media_type = _media_type(content_type)
    return media_type is not None and (
        media_type == "application/json" or media_type.endswith("+json")
    )


def _is_explicit_json(content_type: str | None) -> bool:
    """A request content type that names JSON. Unlike a response, a request with a
    body and no content type is not taken for JSON."""
    return bool(content_type and content_type.strip()) and _is_json_content_type(content_type)


def _normalize_origin(origin: str) -> str | None:
    """scheme://host[:port], lowercased, or None for anything that is not one."""
    scheme, sep, rest = origin.strip().partition("://")
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if not sep or not scheme or not host or "@" in host:
        return None
    return f"{scheme}://{host}".lower()
