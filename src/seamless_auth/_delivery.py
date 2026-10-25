"""Messages the auth API hands back for the application to send."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: The kinds every ``deliver`` callback receives.
MESSAGE_KINDS = frozenset({"otp_email", "otp_sms", "magic_link_email", "enrollment_invite_email"})
#: Owner notices, received only with ``deliver_account_notices=True``.
NOTICE_KINDS = frozenset({"account_notice_email", "account_notice_sms"})

#: The ``purpose`` of an OTP code that recovers an account rather than signs in.
PURPOSE_ACCOUNT_RECOVERY = "account_recovery"


@dataclass(frozen=True)
class Delivery:
    """A message to send through the application's own transports: an OTP code, a
    magic link, an enrollment invite, or an account notice to the account's owner."""

    #: ``otp_email``, ``otp_sms``, ``magic_link_email``, ``enrollment_invite_email``,
    #: ``account_notice_email`` or ``account_notice_sms``.
    kind: str
    #: An email address or phone number.
    to: str
    #: The one-time code, or the magic link's token.
    token: str | None = field(default=None, repr=False)
    magic_link_url: str | None = field(default=None, repr=False)
    sign_in_url: str | None = None
    #: ``account_recovery`` on an OTP code that recovers the account: word the
    #: message as a recovery warning, not a sign-in code.
    purpose: str | None = None
    #: An account notice's name, such as ``account_recovery_opened``.
    notice: str | None = None
    #: An account notice email's subject.
    subject: str | None = None
    #: An account notice's message, written by the auth API. It can hold the cancel
    #: link, so it is as sensitive as ``cancel_url``.
    text: str | None = field(default=None, repr=False)
    #: Cancels the account recovery the notice reports. It is a credential: send it
    #: only to ``to`` and never log it.
    cancel_url: str | None = field(default=None, repr=False)

    @property
    def is_account_recovery(self) -> bool:
        """An OTP code that recovers the account rather than signs in."""
        return self.purpose == PURPOSE_ACCOUNT_RECOVERY


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
        purpose=text("purpose"),
        notice=text("notice"),
        subject=text("subject"),
        text=text("text"),
        cancel_url=text("cancelUrl"),
    )
