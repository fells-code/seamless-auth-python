"""What both reference apps share: configuration from the environment the
conformance suite sets, the delivery capture, and one trusted proxy hop."""

from __future__ import annotations

import os
import threading
from typing import Any

from seamless_auth import Delivery, Headers

captured: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def capture(delivery: Delivery) -> None:
    entry: dict[str, Any] = {"token": delivery.token or ""}
    if delivery.magic_link_url:
        entry["magicLinkUrl"] = delivery.magic_link_url
    if delivery.sign_in_url:
        entry["inviteUrl"] = delivery.sign_in_url
    with _lock:
        captured[delivery.to] = entry


def captured_for(recipient: str) -> dict[str, Any] | None:
    with _lock:
        return captured.get(recipient)


def one_trusted_hop(headers: Headers, peer: str | None) -> str | None:
    # The harness sends each virtual user with its own X-Forwarded-For. Trusting
    # whatever the immediate peer is would be wrong in a deployment, and is
    # acceptable only because this is a test app.
    hops = [h.strip() for v in headers.get_all("x-forwarded-for") for h in v.split(",")]
    return hops[-1] if hops else peer


def adapter_options() -> dict[str, Any]:
    return {
        "auth_server_url": os.environ.get("AUTH_SERVER_URL", ""),
        "auth_server_issuer": os.environ.get("AUTH_SERVER_ISSUER") or None,
        "cookie_secret": os.environ.get("COOKIE_SIGNING_KEY", ""),
        "service_secret": os.environ.get("API_SERVICE_TOKEN", ""),
        "jwks_kid": os.environ.get("JWKS_KID") or None,
        "deliver": capture,
        "resolve_client_ip": one_trusted_hop,
    }


def port() -> int:
    return int(os.environ.get("PORT") or "8080")
