"""The framework-neutral request and response the core works on."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from email.utils import formatdate


class Headers:
    """Request headers, with case-insensitive names and repeats kept."""

    def __init__(self, items: Iterable[tuple[str, str]] = ()) -> None:
        self._items = [(name.lower(), value) for name, value in items]

    def get(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self._items:
            if key == name:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self._items if key == name]


@dataclass
class AuthRequest:
    """One request to the auth routes or to a guarded route.

    ``path`` is the raw (still percent-encoded) path relative to where the auth
    routes are mounted, and ``peer`` the connecting client's address.
    """

    method: str
    path: str = "/"
    query: str = ""
    headers: Headers = field(default_factory=Headers)
    body: bytes | None = None
    peer: str | None = None
    body_too_large: bool = False


@dataclass(frozen=True)
class ResponseCookie:
    """A cookie the adapter sets or ends. ``max_age`` 0 ends it."""

    name: str
    value: str
    max_age: int
    domain: str | None
    secure: bool
    same_site: str
    path: str = "/"
    http_only: bool = True

    def header(self) -> str:
        """The ``Set-Cookie`` header value."""
        if self.max_age > 0:
            expires = formatdate(time.time() + self.max_age, usegmt=True)
        else:
            expires = "Thu, 01 Jan 1970 00:00:00 GMT"
        parts = [f"{self.name}={self.value}", f"Path={self.path}"]
        if self.domain:
            parts.append(f"Domain={self.domain}")
        parts += [f"Max-Age={self.max_age}", f"Expires={expires}"]
        if self.http_only:
            parts.append("HttpOnly")
        if self.secure:
            parts.append("Secure")
        parts.append(f"SameSite={self.same_site}")
        return "; ".join(parts)


@dataclass
class AuthResponse:
    """What the adapter answers. ``body`` is bytes, or an iterator for a download
    streamed from the auth API, which ``close`` releases."""

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes | Iterator[bytes] = b""
    close: Callable[[], None] | None = None
    #: Cookies to end, then cookies to set, in that order.
    cookies: list[ResponseCookie] = field(default_factory=list)
