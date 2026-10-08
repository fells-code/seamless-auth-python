"""HS256 tokens this adapter signs: its cookies and its service tokens."""

from __future__ import annotations

import time
from typing import Any

import jwt

Claims = dict[str, Any]

# Tolerated clock difference between this server and the auth API.
CLOCK_SKEW_SECONDS = 5


def sign_hs256(claims: Claims, secret: str, ttl: int, kid: str | None = None) -> str:
    """Issues a compact HS256 JWT. The claims gain ``iat`` and ``exp``."""
    issued = int(time.time())
    body = {**claims, "iat": issued, "exp": issued + ttl}
    headers = {"kid": kid} if kid else None
    return jwt.encode(body, secret, algorithm="HS256", headers=headers)


def verify_hs256(token: str, secret: str) -> Claims | None:
    """The claims of a token this adapter signed, when its signature, algorithm
    and expiry hold."""
    try:
        claims: Claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp"], "verify_aud": False, "verify_iat": False},
        )
    except jwt.PyJWTError:
        return None
    return claims


def unverified_claims(token: str) -> Claims | None:
    """Reads a token's claims without verifying it. Only for a token whose
    signature was verified before it was stored."""
    try:
        claims: Claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    return claims


def str_claim(claims: Claims | None, name: str) -> str:
    value = (claims or {}).get(name)
    return value if isinstance(value, str) else ""
