"""RS256 verification against the auth API's published key set."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from ._jwt import CLOCK_SKEW_SECONDS, Claims

log = logging.getLogger("seamless_auth")

# A kid the cached key set does not know triggers at most one refetch per this
# interval, so a stream of forged kids cannot turn into a stream of fetches.
REFETCH_INTERVAL = 30.0
# A key set older than this is fetched again, so a key the API retires stops
# verifying.
MAX_AGE = 600.0
# With no key set at all, how long a failed fetch holds off the next.
FAILED_FETCH_BACKOFF = 5.0
FETCH_TIMEOUT = 5.0
MAX_JWKS_BYTES = 256 * 1024


class TokenError(Exception):
    """A token the auth API was supposed to have signed did not verify."""


class JwksCache:
    def __init__(self, auth_server_url: str, client: httpx2.Client) -> None:
        self._url = f"{auth_server_url}/.well-known/jwks.json"
        self._client = client
        self._lock = threading.Lock()
        self._keys: dict[str, Any] | None = None
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None

    def _key(self, kid: str) -> Any:
        with self._lock:
            now = time.monotonic()
            fresh = self._fetched_at is not None and now - self._fetched_at < MAX_AGE
            if fresh and self._keys is not None and kid in self._keys:
                return self._keys[kid]

            backoff = REFETCH_INTERVAL if self._keys is not None else FAILED_FETCH_BACKOFF
            if self._attempted_at is None or now - self._attempted_at >= backoff:
                self._attempted_at = now
                try:
                    self._keys = self._fetch()
                    self._fetched_at = time.monotonic()
                except Exception as err:
                    # A stale key set keeps verifying while the API cannot be
                    # reached, rather than signing every user out.
                    if self._keys is None:
                        raise TokenError(f"jwks: {err}") from err
                    log.warning("[seamless-auth] Could not refresh the JWKS (%s).", err)

            if self._keys is None or kid not in self._keys:
                raise TokenError(f"unknown key id {kid!r}")
            return self._keys[kid]

    def _fetch(self) -> dict[str, Any]:
        with self._client.stream("GET", self._url, timeout=FETCH_TIMEOUT) as res:
            if res.status_code != 200:
                raise TokenError(f"HTTP {res.status_code}")
            body = read_limited(res, MAX_JWKS_BYTES)
        keys: dict[str, Any] = {}
        for jwk in json.loads(body).get("keys", []):
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
                continue
            # One bad key is skipped rather than taking the whole set down, and a key
            # published with its private half is used for its public half only.
            try:
                key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            except (jwt.PyJWTError, ValueError, KeyError, TypeError):
                continue
            if isinstance(key, RSAPrivateKey):
                key = key.public_key()
            if isinstance(key, RSAPublicKey):
                keys[str(jwk.get("kid", ""))] = key
        return keys

    def verify(self, token: str, issuer: str, audience: str) -> Claims:
        """Checks a token the auth API signed: RS256 under a key it publishes,
        issued by ``issuer`` for ``audience``, and in date."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as err:
            raise TokenError(str(err)) from err
        if header.get("alg") != "RS256":
            raise TokenError("unexpected algorithm")
        kid = header.get("kid")
        key = self._key(kid if isinstance(kid, str) else "")
        try:
            claims: Claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=issuer,
                audience=audience,
                leeway=CLOCK_SKEW_SECONDS,
                # As the Go and Rust adapters: exp and nbf bound a token, and an
                # iat from a clock running ahead is not a reason to refuse one.
                options={"require": ["exp", "iss", "aud"], "verify_iat": False},
            )
        except jwt.PyJWTError as err:
            raise TokenError(str(err)) from err
        return claims


class BodyTooLarge(Exception):
    pass


def read_limited(res: httpx2.Response, limit: int) -> bytes:
    """Reads at most ``limit`` bytes of a streamed response, refusing a larger one."""
    length = res.headers.get("content-length")
    if length and length.isdigit() and int(length) > limit:
        raise BodyTooLarge("response body too large")
    out = bytearray()
    for chunk in res.iter_bytes():
        out += chunk
        if len(out) > limit:
            raise BodyTooLarge("response body too large")
    return bytes(out)
