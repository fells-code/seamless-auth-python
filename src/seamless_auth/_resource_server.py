"""Verify-only resource server mode: OpenID Provider access tokens (RFC 9068) as
``Authorization: Bearer``, with audience, scope, role and step-up guards."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeGuard
from urllib.parse import urlsplit

import httpx2
from jwt.algorithms import RSAAlgorithm

from ._http import Headers
from ._jwks import FETCH_TIMEOUT, JwksCache, TokenError, read_limited
from ._jwt import CLOCK_SKEW_SECONDS

log = logging.getLogger("seamless_auth")

DISCOVERY_PATH = "/.well-known/openid-configuration"
MAX_DISCOVERY_BYTES = 256 * 1024
# A failed discovery holds off the next attempt this long, so a provider that is
# down is not asked again on every request.
DISCOVERY_RETRY = 5.0

_ACCESS_TOKEN_TYPES = ("at+jwt", "application/at+jwt")
_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_WHITESPACE = re.compile(r"[ \t\r\n\f\v]+")
_RS256 = RSAAlgorithm(RSAAlgorithm.SHA256)


class BearerError(Exception):
    """A request a verify-only guard refused, with the answer to give it."""

    def __init__(self, status: int, body: dict[str, Any], www_authenticate: str | None) -> None:
        super().__init__(body["error"])
        self.status = status
        self.body = body
        self.www_authenticate = www_authenticate

    @property
    def error(self) -> str:
        return str(self.body["error"])

    def headers(self) -> dict[str, str]:
        return {"WWW-Authenticate": self.www_authenticate} if self.www_authenticate else {}


def missing_token() -> BearerError:
    return BearerError(401, {"error": "missing_token"}, "Bearer")


def invalid_token() -> BearerError:
    return BearerError(401, {"error": "invalid_token"}, 'Bearer error="invalid_token"')


@dataclass(frozen=True)
class VerifiedUser:
    """The caller an OpenID Provider access token names. A client credentials token
    has ``sub == client_id`` and no user claims."""

    sub: str
    client_id: str
    scopes: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    sid: str | None = None
    org_id: str | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()
    auth_time: float | None = None
    exp: float = 0
    iat: float | None = None
    #: When the token was verified, by the verifier's clock. Step-up ``max_age``
    #: is measured from here.
    verified_at: float = 0
    claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    token: str = field(default="", repr=False)


class BearerRequest:
    """What a confirmation hook may need of the request: its method, headers, and
    absolute URL (built on first read)."""

    def __init__(self, method: str, headers: Headers, url: str | Callable[[], str]) -> None:
        self.method = method
        self.headers = headers
        self._url = url

    @property
    def url(self) -> str:
        if callable(self._url):
            self._url = self._url()
        return self._url


#: Called with a token's ``cnf`` claim and the request it came on (``None`` when the
#: token is verified on its own). Returning ``True`` accepts the binding.
Confirm = Callable[[Any, BearerRequest | None], bool]


class ResourceServer:
    """Verifies OpenID Provider access tokens for one API.

    ``issuer`` is the provider's issuer and ``audience`` this API's resource
    identifier. Keys come from ``jwks_uri``, or from the issuer's discovery
    document when it is not given. A token carrying ``cnf`` is refused unless
    ``confirm`` accepts it.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_uri: str | None = None,
        http_client: httpx2.Client | None = None,
        confirm: Confirm | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(issuer, str) or not _http_url(issuer):
            raise ValueError("seamless-auth: issuer must be an absolute http(s) URL")
        if not isinstance(audience, str) or not audience:
            raise ValueError("seamless-auth: audience is required")
        if jwks_uri is not None and not _http_url(jwks_uri):
            raise ValueError("seamless-auth: jwks_uri must be an absolute http(s) URL")
        self.issuer = issuer
        self.audience = audience
        self._client = http_client or httpx2.Client(timeout=FETCH_TIMEOUT, follow_redirects=False)
        self._confirm = confirm
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._jwks = JwksCache(jwks_uri, self._client) if jwks_uri else None
        self._discovery_attempted_at: float | None = None

    def __repr__(self) -> str:
        return f"ResourceServer(issuer={self.issuer!r}, audience={self.audience!r})"

    def authenticate(
        self, authorization: str | None, request: BearerRequest | None = None
    ) -> VerifiedUser:
        """The user an ``Authorization`` header carries. Raises :class:`BearerError`,
        ``missing_token`` or ``invalid_token``."""
        token = bearer_token(authorization)
        if token is None:
            raise missing_token()
        return self.verify(token, request)

    def verify(self, token: str, request: BearerRequest | None = None) -> VerifiedUser:
        """Verifies a token. Raises :class:`BearerError` ``invalid_token``."""
        try:
            return self._verify(token, request)
        except TokenError as err:
            log.debug("[seamless-auth] Bearer token refused: %s", err)
            raise invalid_token() from None

    def _keys(self) -> JwksCache:
        with self._lock:
            if self._jwks is not None:
                return self._jwks
            now = time.monotonic()
            if (
                self._discovery_attempted_at is not None
                and now - self._discovery_attempted_at < DISCOVERY_RETRY
            ):
                raise TokenError("discovery failed recently")
            self._discovery_attempted_at = now
            try:
                self._jwks = JwksCache(self._discover(), self._client)
            except Exception as err:
                log.warning("[seamless-auth] OpenID discovery for %s failed: %s", self.issuer, err)
                raise TokenError(f"discovery: {err}") from err
            return self._jwks

    def _discover(self) -> str:
        url = self.issuer.rstrip("/") + DISCOVERY_PATH
        with self._client.stream("GET", url, timeout=FETCH_TIMEOUT) as res:
            if res.status_code != 200:
                raise TokenError(f"HTTP {res.status_code}")
            body = read_limited(res, MAX_DISCOVERY_BYTES)
        doc = _json_object(body)
        if doc.get("issuer") != self.issuer:
            raise TokenError("discovery document names another issuer")
        jwks_uri = doc.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not _http_url(jwks_uri):
            raise TokenError("discovery document has no http(s) jwks_uri")
        if urlsplit(self.issuer).scheme == "https" and urlsplit(jwks_uri).scheme != "https":
            raise TokenError("jwks_uri is not https under an https issuer")
        return jwks_uri

    def _verify(self, token: str, request: BearerRequest | None) -> VerifiedUser:
        segments = token.split(".")
        if len(segments) != 3 or not all(_SEGMENT.match(s) for s in segments):
            raise TokenError("not a compact JWS")
        header = _json_object(_b64decode(segments[0]))
        if header.get("alg") != "RS256":
            raise TokenError("unexpected algorithm")
        typ = header.get("typ")
        if not isinstance(typ, str) or not typ.isascii() or typ.lower() not in _ACCESS_TOKEN_TYPES:
            raise TokenError("not an access token")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("no key id")
        if "crit" in header:
            raise TokenError("critical header parameters are not supported")

        jwk = self._keys().key(kid)
        if jwk.params.get("kty") != "RSA":
            raise TokenError("not an RSA key")
        if "use" in jwk.params and jwk.params["use"] != "sig":
            raise TokenError("key is not for signatures")
        if "alg" in jwk.params and jwk.params["alg"] != "RS256":
            raise TokenError("key is for another algorithm")
        signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
        try:
            signed = _RS256.verify(signing_input, jwk.key, _b64decode(segments[2]))
        except ValueError as err:
            raise TokenError("bad signature") from err
        if not signed:
            raise TokenError("bad signature")

        claims = _json_object(_b64decode(segments[1]))
        if claims.get("iss") != self.issuer:
            raise TokenError("unexpected issuer")
        aud = claims.get("aud")
        if not (aud == self.audience or (isinstance(aud, list) and self.audience in aud)):
            raise TokenError("unexpected audience")

        now = self._clock()
        exp = claims.get("exp")
        if not _is_number(exp) or not now < exp + CLOCK_SKEW_SECONDS:
            raise TokenError("expired")
        if "nbf" in claims:
            nbf = claims["nbf"]
            if not _is_number(nbf) or not now + CLOCK_SKEW_SECONDS >= nbf:
                raise TokenError("not yet valid")

        sub = claims.get("sub")
        client_id = claims.get("client_id")
        if not isinstance(sub, str) or not sub:
            raise TokenError("no subject")
        if not isinstance(client_id, str) or not client_id:
            raise TokenError("no client_id")
        # A first-party session token carries typ; one must never pass as an access
        # token for an API (ADR D11).
        if "typ" in claims:
            raise TokenError("first-party token")

        scope = _optional(claims, "scope", _is_str)
        acr = _optional(claims, "acr", _is_str)
        sid = _optional(claims, "sid", _is_str)
        amr = _optional(claims, "amr", _is_str_list)
        roles = _optional(claims, "roles", _is_str_list)
        auth_time = _optional(claims, "auth_time", _is_number)
        iat = claims.get("iat") if _is_number(claims.get("iat")) else None
        org_id = claims.get("org_id")
        if org_id is not None and not isinstance(org_id, str):
            raise TokenError("org_id is not a string")

        cnf = claims.get("cnf")
        if cnf is not None and not self._confirmed(cnf, request):
            raise TokenError("confirmation (cnf) not accepted")

        return VerifiedUser(
            sub=sub,
            client_id=client_id,
            scopes=tuple(s for s in (scope or "").split(" ") if s),
            roles=tuple(roles or ()),
            sid=sid,
            org_id=org_id,
            acr=acr,
            amr=tuple(amr or ()),
            auth_time=auth_time,
            exp=exp,
            iat=iat,
            verified_at=now,
            claims=claims,
            token=token,
        )

    def _confirmed(self, cnf: Any, request: BearerRequest | None) -> bool:
        if self._confirm is None:
            return False
        try:
            return self._confirm(cnf, request) is True
        except Exception as err:
            log.warning("[seamless-auth] The confirmation hook raised (%s).", err)
            return False


def bearer_token(authorization: str | None) -> str | None:
    """The token of a ``Bearer`` authorization header, or ``None`` without exactly
    one."""
    if authorization is None:
        return None
    parts = _WHITESPACE.split(authorization.strip())
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


class Guard:
    """A check on a verified user, run after verification in declaration order."""

    def check(self, user: VerifiedUser) -> None:
        raise NotImplementedError


class _ScopeGuard(Guard):
    def __init__(self, scopes: tuple[str, ...]) -> None:
        self.scopes = scopes

    def check(self, user: VerifiedUser) -> None:
        if not all(s in user.scopes for s in self.scopes):
            scope = " ".join(self.scopes)
            raise BearerError(
                403,
                {"error": "insufficient_scope", "scope": scope},
                f'Bearer error="insufficient_scope", scope="{scope}"',
            )


class _RoleGuard(Guard):
    def __init__(self, roles: tuple[str, ...]) -> None:
        self.roles = roles

    def check(self, user: VerifiedUser) -> None:
        if not any(role_grants_access(g, r) for r in self.roles for g in user.roles):
            raise BearerError(403, {"error": "insufficient_role"}, None)


class _StepUpGuard(Guard):
    def __init__(
        self,
        acr_values: tuple[str, ...] | None,
        max_age: int | None,
        amr: tuple[str, ...] | None,
    ) -> None:
        self.acr_values = acr_values
        self.max_age = max_age
        self.amr = amr
        accepted = set(acr_values or ())
        if "phr" in accepted:
            # A hardware-bound passkey (phrh) is a stronger phishing-resistant one.
            accepted.add("phrh")
        self._accepted = accepted

    def check(self, user: VerifiedUser) -> None:
        level_ok = (self.acr_values is None or user.acr in self._accepted) and (
            self.amr is None or all(m in user.amr for m in self.amr)
        )
        recent = self.max_age is None or (
            user.auth_time is not None and user.verified_at - user.auth_time <= self.max_age
        )
        if level_ok and recent:
            return
        description = (
            "More recent authentication is required"
            if level_ok
            else "A different authentication level is required"
        )
        body: dict[str, Any] = {
            "error": "insufficient_user_authentication",
            "error_description": description,
        }
        header = (
            f'Bearer error="insufficient_user_authentication", error_description="{description}"'
        )
        if self.acr_values is not None:
            body["acr_values"] = " ".join(self.acr_values)
            header += f', acr_values="{body["acr_values"]}"'
        if self.max_age is not None:
            body["max_age"] = self.max_age
            header += f', max_age="{self.max_age}"'
        raise BearerError(401, body, header)


def require_scope(*scopes: str) -> Guard:
    """Every listed scope must be granted, exactly. Otherwise 403
    ``insufficient_scope``."""
    _check_names("require_scope", scopes)
    return _ScopeGuard(tuple(scopes))


def require_role(*roles: str) -> Guard:
    """Any one listed role must be granted, by :func:`role_grants_access`. Otherwise
    403 ``insufficient_role``."""
    _check_names("require_role", roles)
    return _RoleGuard(tuple(roles))


def require_step_up(
    *,
    acr_values: Sequence[str] | None = None,
    max_age: int | None = None,
    amr: Sequence[str] | None = None,
) -> Guard:
    """The authentication behind the token must be strong enough and recent enough
    (RFC 9470). Otherwise 401 ``insufficient_user_authentication`` with the
    challenge the client needs to sign in again.

    ``acr_values``: the token's ``acr`` must be one of them (``phr`` also accepts
    ``phrh``). ``amr``: every listed method must be in the token's ``amr``.
    ``max_age``: at most this many seconds since ``auth_time``.
    """
    if acr_values is None and max_age is None and amr is None:
        raise ValueError("seamless-auth: require_step_up needs acr_values, max_age or amr")
    if max_age is not None and (
        not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0
    ):
        raise ValueError("seamless-auth: max_age must be a non-negative integer")
    if acr_values is not None:
        _check_names("require_step_up acr_values", _as_tuple(acr_values))
    if amr is not None:
        _check_names("require_step_up amr", _as_tuple(amr))
    return _StepUpGuard(
        _as_tuple(acr_values) if acr_values is not None else None,
        max_age,
        _as_tuple(amr) if amr is not None else None,
    )


def role_grants_access(granted_role: str, required_role: str) -> bool:
    """Whether a granted role satisfies a required one, as ``roleGrantsAccess`` in
    ``@seamless-auth/types``: ``x:*`` grants ``x`` and everything under it, an
    unscoped role grants everything beneath it, and ``p:write`` implies ``p:read``."""
    granted = granted_role.strip()
    required = required_role.strip()
    if not granted or not required:
        return False
    if granted == required:
        return True
    if granted.endswith(":*"):
        prefix = granted[:-2]
        return required == prefix or required.startswith(f"{prefix}:")
    if ":" not in required:
        return False
    if ":" not in granted:
        return required.startswith(f"{granted}:")
    granted_parts = granted.split(":")
    required_parts = required.split(":")
    return (
        granted_parts[-1] == "write"
        and required_parts[-1] == "read"
        and granted_parts[:-1] == required_parts[:-1]
    )


def _as_tuple(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError("seamless-auth: pass a list of values, not a string")
    return tuple(values)


def _check_names(what: str, names: tuple[str, ...]) -> None:
    if not names:
        raise ValueError(f"seamless-auth: {what} needs at least one value")
    if not all(isinstance(n, str) and n for n in names):
        raise ValueError(f"seamless-auth: {what} values must be non-empty strings")


def _http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _b64decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as err:
        raise TokenError("bad base64url") from err


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as err:
        raise TokenError("not JSON") from err
    if not isinstance(value, dict):
        raise TokenError("not a JSON object")
    return value


def _is_number(value: Any) -> TypeGuard[float]:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _optional(claims: dict[str, Any], name: str, valid: Callable[[Any], bool]) -> Any:
    if name not in claims:
        return None
    value = claims[name]
    if not valid(value):
        raise TokenError(f"{name} has the wrong type")
    return value
