"""Messages the auth API hands back for the application to send."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Delivery:
    """An OTP code or magic link to send through the application's own transports."""

    #: ``otp_email``, ``otp_sms``, ``magic_link_email`` or ``enrollment_invite_email``.
    kind: str
    #: An email address or phone number.
    to: str
    #: The one-time code, or the magic link's token.
    token: str | None = field(default=None, repr=False)
    magic_link_url: str | None = field(default=None, repr=False)
    sign_in_url: str | None = None


def parse_delivery(raw: Any) -> Delivery:
    if not isinstance(raw, dict):
        raise ValueError("delivery is not an object")

    def text(name: str) -> str | None:
        value = raw.get(name)
        return value if isinstance(value, str) and value else None

    token = raw.get("token")
    # An SMS code can arrive as a number.
    if isinstance(token, bool) or not isinstance(token, str | int):
        token = None
    kind, to = text("kind"), text("to")
    if not kind or not to:
        raise ValueError("delivery has no kind or recipient")
    return Delivery(
        kind=kind,
        to=to,
        token=str(token) if token is not None else None,
        magic_link_url=text("magicLinkUrl"),
        sign_in_url=text("signInUrl"),
    )
