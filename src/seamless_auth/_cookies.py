"""The adapter's cookies: HS256 tokens bound to their slot by a signed kind."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._http import Headers, ResponseCookie
from ._jwt import Claims, sign_hs256, str_claim, verify_hs256

if TYPE_CHECKING:
    from ._adapter import Config

# Cookie kinds. Every cookie is signed with the same secret, so the kind is signed
# into the payload and checked on read: otherwise a cookie from one slot, such as
# the pre-auth cookie /login issues for any existing account, would pass in another.
KIND_ACCESS = "access"
KIND_REFRESH = "refresh"
KIND_EPHEMERAL = "ephemeral"
KIND_CLAIM = "kind"

# Browsers cap a cookie's lifetime at 400 days (RFC 6265bis).
MAX_COOKIE_AGE = 400 * 24 * 60 * 60


@dataclass
class CookieWrite:
    name: str
    kind: str
    value: Claims
    max_age: int


def set_cookie(config: Config, cookie: CookieWrite) -> ResponseCookie:
    signed = sign_hs256(
        {**cookie.value, KIND_CLAIM: cookie.kind}, config.cookie_secret, cookie.max_age
    )
    return _cookie(config, cookie.name, signed, cookie.max_age)


def clear_cookie(config: Config, name: str) -> ResponseCookie:
    return _cookie(config, name, "", 0)


def _cookie(config: Config, name: str, value: str, max_age: int) -> ResponseCookie:
    return ResponseCookie(
        name=name,
        value=value,
        max_age=max_age,
        domain=config.cookie_domain,
        secure=config.secure_cookies,
        same_site=config.same_site,
    )


def raw_cookie(headers: Headers, name: str) -> str | None:
    """The raw value of the first cookie called ``name``, if the request holds one."""
    for header in headers.get_all("cookie"):
        for pair in header.split(";"):
            key, sep, value = pair.strip().partition("=")
            if sep and key == name:
                return value.strip('"')
    return None


def read_cookie(config: Config, headers: Headers, name: str, kind: str) -> Claims | None:
    """The verified payload of one of the adapter's cookies, if it is the kind
    expected in that slot."""
    raw = raw_cookie(headers, name)
    if not raw:
        return None
    claims = verify_hs256(raw, config.cookie_secret)
    if claims is None or str_claim(claims, KIND_CLAIM) != kind:
        return None
    return claims


def cookie_kind(held: str) -> str:
    """The kind of cookie a held credential lives in."""
    if held == "access":
        return KIND_ACCESS
    if held == "refresh":
        return KIND_REFRESH
    return KIND_EPHEMERAL


def ttl_seconds(value: Any) -> int:
    """Reads a lifetime the auth API sent, which may be a number or a numeric
    string. Anything that is not a positive whole number of seconds is refused: a
    cookie is the session, and one with a lifetime nobody can vouch for is worse
    than refusing the response."""
    ttl: int | None = None
    if isinstance(value, bool):
        ttl = None
    elif isinstance(value, int):
        ttl = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        ttl = int(value)
    if ttl is None or ttl <= 0:
        raise ValueError(f"unusable cookie ttl {value!r}")
    return min(ttl, MAX_COOKIE_AGE)


def session_cookies(
    config: Config, session: Claims, session_id: str, with_refresh: bool
) -> list[CookieWrite]:
    """The cookies for a verified session response: access, and refresh unless the
    response only reissues access."""
    ttl = ttl_seconds(session.get("ttl"))
    access = {
        name: session.get(name)
        for name in ("sub", "token", "roles", "email", "phone", "organizationId")
    }
    if session_id:
        access["sessionId"] = session_id
    cookies = [CookieWrite(config.access_cookie_name, KIND_ACCESS, access, ttl)]
    if with_refresh:
        refresh_ttl = ttl_seconds(session.get("refreshTtl"))
        refresh = {"sub": session.get("sub"), "refreshToken": session.get("refreshToken")}
        cookies.append(CookieWrite(config.refresh_cookie_name, KIND_REFRESH, refresh, refresh_ttl))
    return cookies


def ephemeral_cookie(config: Config, issues: str, session: Claims) -> CookieWrite:
    """The cookie a pre-auth or registration response issues."""
    ttl = ttl_seconds(session.get("ttl"))
    value = {"sub": session.get("sub"), "token": session.get("token")}
    return CookieWrite(config.cookie_name(issues), KIND_EPHEMERAL, value, ttl)
