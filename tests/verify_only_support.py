"""The shared verify-only vectors and a provider that serves their keys.

data/verify_only_vectors.json is copied byte for byte from
fells-code/seamless-auth-server, packages/core/tests/fixtures/verify-only/vectors.json,
so every adapter is held to the same tokens and answers. Do not edit it here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2

from seamless_auth import (
    Guard,
    ResourceServer,
    VerifiedUser,
    require_role,
    require_scope,
    require_step_up,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "data" / "verify_only_vectors.json").read_text()
)
ISSUER: str = VECTORS["issuer"]
AUDIENCE: str = VECTORS["audience"]
NOW: int = VECTORS["now"]
TOKENS: dict[str, str] = VECTORS["tokens"]
JWKS_URI = f"{ISSUER}/jwks"
USER_FIELDS = ("sub", "client_id", "scopes", "roles", "sid", "org_id", "acr", "amr", "auth_time")


@dataclass
class Provider:
    """An OpenID Provider's discovery document and key set, over a mock transport."""

    discovery: Any = field(
        default_factory=lambda: {"issuer": ISSUER, "jwks_uri": JWKS_URI},
    )
    discovery_status: int = 200
    jwks_status: int = 200
    paths: list[str] = field(default_factory=list)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        self.paths.append(request.url.path)
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return httpx2.Response(self.discovery_status, json=self.discovery)
        if url == JWKS_URI:
            return httpx2.Response(self.jwks_status, json=VECTORS["jwks"])
        return httpx2.Response(404)

    def client(self) -> httpx2.Client:
        return httpx2.Client(transport=httpx2.MockTransport(self.handle))

    def server(self, **options: Any) -> ResourceServer:
        settings: dict[str, Any] = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "http_client": self.client(),
            "clock": lambda: float(NOW),
            **options,
        }
        return ResourceServer(**settings)


def user_fields(user: VerifiedUser) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in USER_FIELDS:
        value = getattr(user, name)
        out[name] = list(value) if isinstance(value, tuple) else value
    return out


def guard_of(spec: dict[str, Any] | None) -> list[Guard]:
    if spec is None:
        return []
    if spec["kind"] == "scope":
        return [require_scope(*spec["scopes"])]
    if spec["kind"] == "role":
        return [require_role(*spec["roles"])]
    assert spec["kind"] == "step_up"
    return [
        require_step_up(
            acr_values=spec.get("acr_values"), max_age=spec.get("max_age"), amr=spec.get("amr")
        )
    ]


def request_ids() -> list[str]:
    return [r["name"] for r in VECTORS["requests"]]
