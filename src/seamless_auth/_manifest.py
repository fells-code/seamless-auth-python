"""The auth API's adapter manifest: which token each route takes, and which
tokens its response issues or clears."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

import httpx2

from ._jwks import read_limited

log = logging.getLogger("seamless_auth")

MANIFEST_PATH = "/.well-known/seamless-adapter.json"
FETCH_TIMEOUT = 5.0
RETRY_AFTER = 60.0
MAX_MANIFEST_BYTES = 1024 * 1024

KNOWN_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
KNOWN_CREDENTIALS = frozenset({"none", "preAuth", "registration", "access", "refresh"})
KNOWN_ISSUES = frozenset({"preAuth", "registration", "session", "access"})
KNOWN_HELD = frozenset({"preAuth", "registration", "access", "refresh"})

# Go's url.PathEscape leaves these alone in a path segment.
_SEGMENT_SAFE = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~$&+:=@"
)
_HEX = frozenset(b"0123456789abcdefABCDEF")


class ManifestError(ValueError):
    """A manifest this version cannot follow."""


@dataclass(frozen=True)
class ManifestRoute:
    method: str
    path: str
    credential: str
    issues: str | None = None
    clears: tuple[str, ...] = ()
    pick: tuple[str, ...] | None = None
    delivery: bool = False

    def upstream_path(self, params: dict[str, str]) -> str:
        """The upstream path, with each ``{param}`` segment filled and escaped."""
        parts = []
        for part in self.path.split("/"):
            name = _param_name(part)
            parts.append(part if name is None else percent_encode(params.get(name, "")))
        return "/".join(parts)


@dataclass(frozen=True)
class RouteMatch:
    route: ManifestRoute
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    api_version: str
    routes: tuple[ManifestRoute, ...]

    @classmethod
    def parse(cls, data: bytes | str) -> Manifest:
        """Accepts a manifest only if every route is one this package knows how
        to follow. A route with a credential or effect it does not understand
        could be proxied with the wrong token, so such a manifest is refused whole."""
        try:
            raw = json.loads(data)
        except ValueError as err:
            raise ManifestError(str(err)) from err
        if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
            version = raw.get("schemaVersion") if isinstance(raw, dict) else None
            raise ManifestError(f"unsupported manifest schemaVersion {version!r}")

        routes = []
        for item in raw.get("routes") or []:
            routes.append(_parse_route(item))
        return cls(1, str(raw.get("apiVersion") or ""), tuple(routes))

    def find(self, method: str, path: str) -> RouteMatch | None:
        """Finds the route for a request. Static segments compare
        case-insensitively, and a static segment beats a parameter at the same
        position, so /admin/users/import is never read as /admin/users/{userId}."""
        requested = _segments(path)
        best: RouteMatch | None = None
        best_score = -1
        method = method.upper()

        for route in self.routes:
            if route.method != method:
                continue
            pattern = _segments(route.path)
            if len(pattern) != len(requested):
                continue

            params: dict[str, str] = {}
            score = 0
            matched = True
            for part, value in zip(pattern, requested, strict=True):
                name = _param_name(part)
                if name is not None:
                    decoded = percent_decode(value)
                    # Re-encoded, a dot segment survives as a literal ".." that the
                    # HTTP client resolves, sending the held token to another
                    # upstream path.
                    if decoded is None or decoded in (".", ".."):
                        matched = False
                        break
                    params[name] = decoded
                    continue
                if part.lower() != value.lower():
                    matched = False
                    break
                score += 1

            if matched and score > best_score:
                best = RouteMatch(route, params)
                best_score = score
        return best


def _parse_route(item: Any) -> ManifestRoute:
    if not isinstance(item, dict):
        raise ManifestError("unsupported manifest route")
    method = item.get("method")
    path = item.get("path")
    credential = item.get("credential")
    issues = item.get("issues") or None
    clears = item.get("clears") or []
    body = item.get("body")
    pick = body.get("pick") if isinstance(body, dict) else None

    known = (
        method in KNOWN_METHODS
        and isinstance(path, str)
        and path.startswith("/")
        and credential in KNOWN_CREDENTIALS
        and (issues is None or issues in KNOWN_ISSUES)
        and isinstance(clears, list)
        and all(held in KNOWN_HELD for held in clears)
        and (pick is None or (isinstance(pick, list) and all(isinstance(k, str) for k in pick)))
    )
    if not known:
        raise ManifestError(f"unsupported manifest route {method} {path}")
    return ManifestRoute(
        method=str(method),
        path=str(path),
        credential=str(credential),
        issues=issues,
        clears=tuple(clears),
        pick=tuple(pick) if pick is not None else None,
        delivery=bool(item.get("delivery")),
    )


@cache
def bundled_manifest() -> Manifest:
    """The manifest this version of the package was built against."""
    data = resources.files("seamless_auth").joinpath("manifest.json").read_bytes()
    return Manifest.parse(data)


def _param_name(part: str) -> str | None:
    if len(part) >= 2 and part.startswith("{") and part.endswith("}"):
        return part[1:-1]
    return None


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def percent_decode(segment: str) -> str | None:
    """Decodes a path segment, refusing a malformed escape or a result that is
    not UTF-8, as Go's url.PathUnescape does."""
    raw = segment.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == ord("%"):
            pair = raw[i + 1 : i + 3]
            if len(pair) != 2 or not all(b in _HEX for b in pair):
                return None
            out.append(int(pair, 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def percent_encode(value: str) -> str:
    return "".join(chr(b) if b in _SEGMENT_SAFE else f"%{b:02X}" for b in value.encode("utf-8"))


class ManifestSource:
    """Fetches the live manifest once and keeps it, falling back to the bundled
    copy. A failed fetch is retried a minute later, not on every request."""

    def __init__(self, auth_server_url: str, client: httpx2.Client, fetch: bool) -> None:
        self._url = f"{auth_server_url}{MANIFEST_PATH}"
        self._client = client
        self._fetch = fetch
        self._lock = threading.Lock()
        self._loaded: Manifest | None = None
        self._retry_at = 0.0

    def get(self) -> Manifest:
        if not self._fetch:
            return bundled_manifest()
        with self._lock:
            if self._loaded is not None:
                return self._loaded
            if time.monotonic() < self._retry_at:
                return bundled_manifest()
            try:
                self._loaded = self._load()
                return self._loaded
            except Exception as err:
                log.warning(
                    "[seamless-auth] Could not load the adapter manifest (%s). "
                    "Using the bundled copy.",
                    err,
                )
                self._retry_at = time.monotonic() + RETRY_AFTER
                return bundled_manifest()

    def _load(self) -> Manifest:
        headers = {"accept": "application/json"}
        with self._client.stream("GET", self._url, headers=headers, timeout=FETCH_TIMEOUT) as res:
            if res.status_code != 200:
                raise ManifestError(f"HTTP {res.status_code}")
            return Manifest.parse(read_limited(res, MAX_MANIFEST_BYTES))
