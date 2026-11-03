"""RS256 verification against the auth API's published key set."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Jwk:
    """A published RSA key, with the JWK members that constrain its use."""

    key: RSAPublicKey
    params: dict[str, Any]

    def check_rs256_signing(self) -> None:
        """Refuses a key its JWK publishes for another use or algorithm."""
        if self.params.get("kty") != "RSA":
            raise TokenError("not an RSA key")
        if "use" in self.params and self.params["use"] != "sig":
            raise TokenError("key is not for signatures")
        if "alg" in self.params and self.params["alg"] != "RS256":
            raise TokenError("key is for another algorithm")


class JwksCache:
    """The key set at ``url``, fetched on first use and kept fresh."""

    def __init__(self, url: str, client: httpx2.Client) -> None:
        self._url = url
        self._client = client
        self._lock = threading.Lock()
        self._keys: dict[str, Jwk] | None = None
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        # Set while a fetch is in flight; waiters block on it, never on the lock.
        self._fetching: threading.Event | None = None

    def key(self, kid: str) -> Jwk:
        # The lock guards the cache only and is never held across the network: a
        # slow JWKS endpoint must not queue verifications of keys already known.
        while True:
            with self._lock:
                now = time.monotonic()
                keys = self._keys
                fresh = self._fetched_at is not None and now - self._fetched_at < MAX_AGE
                if keys is not None and kid in keys and (fresh or self._fetching is not None):
                    return keys[kid]
                in_flight = self._fetching
                if in_flight is None:
                    backoff = REFETCH_INTERVAL if keys is not None else FAILED_FETCH_BACKOFF
                    if self._attempted_at is not None and now - self._attempted_at < backoff:
                        if keys is None or kid not in keys:
                            raise TokenError(f"unknown key id {kid!r}")
                        return keys[kid]
                    self._attempted_at = now
                    self._fetching = threading.Event()
            if in_flight is not None:
                # Single flight: wait for the fetch another caller started, then
                # look again (within the backoff, so this cannot start a second).
                in_flight.wait()
                continue
            return self._refresh(kid)

    def _refresh(self, kid: str) -> Jwk:
        fetched: dict[str, Jwk] | None = None
        error: Exception | None = None
        try:
            fetched = self._fetch()
        except Exception as err:
            error = err
        finally:
            # Released whatever happens, or every waiter would block for good.
            with self._lock:
                if fetched is not None:
                    self._keys = fetched
                    self._fetched_at = time.monotonic()
                done, self._fetching = self._fetching, None
                keys = self._keys
            if done is not None:
                done.set()
        if error is not None:
            # A stale key set keeps verifying while the API cannot be reached,
            # rather than signing every user out.
            if keys is None:
                raise TokenError(f"jwks: {error}") from error
            log.warning("[seamless-auth] Could not refresh the JWKS (%s).", error)
        if keys is None or kid not in keys:
            raise TokenError(f"unknown key id {kid!r}")
        return keys[kid]

    def _fetch(self) -> dict[str, Jwk]:
        with self._client.stream(
            "GET", self._url, timeout=FETCH_TIMEOUT, follow_redirects=False
        ) as res:
            if res.status_code != 200:
                raise TokenError(f"HTTP {res.status_code}")
            body = read_limited(res, MAX_JWKS_BYTES)
        keys: dict[str, Jwk] = {}
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
                params = {k: jwk[k] for k in ("kid", "kty", "use", "alg", "key_ops") if k in jwk}
                keys[str(jwk.get("kid", ""))] = Jwk(key, params)
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
        jwk = self.key(kid if isinstance(kid, str) else "")
        jwk.check_rs256_signing()
        try:
            claims: Claims = jwt.decode(
                token,
                jwk.key,
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
