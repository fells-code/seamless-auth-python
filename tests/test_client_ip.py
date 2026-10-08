from __future__ import annotations

import pytest

from seamless_auth import Headers, TrustedProxies


def forwarded(*values: str) -> Headers:
    return Headers(("x-forwarded-for", v) for v in values)


def test_walks_x_forwarded_for_from_the_right() -> None:
    proxies = TrustedProxies(["10.0.0.0/8", "192.0.2.1", "2001:db8::/32"])

    # An untrusted peer is the client, whatever it claims.
    assert proxies(forwarded("1.1.1.1"), "203.0.113.9") == "203.0.113.9"
    # A client-supplied left-most entry is ignored past the first untrusted hop.
    assert proxies(forwarded("6.6.6.6, 203.0.113.50, 10.1.2.3"), "192.0.2.1") == "203.0.113.50"
    # Several headers read as one list.
    assert proxies(forwarded("6.6.6.6", "203.0.113.50"), "10.0.0.1") == "203.0.113.50"
    # Every hop trusted: the left-most.
    assert proxies(forwarded("10.0.0.5, 10.0.0.6"), "10.0.0.1") == "10.0.0.5"
    # A trusted peer with no header.
    assert proxies(Headers(), "10.0.0.1") == "10.0.0.1"
    # A hop that is not an address gives no address rather than a guess.
    assert proxies(forwarded("203.0.113.50, garbage"), "10.0.0.1") is None
    # IPv4-mapped peers match IPv4 proxies.
    assert proxies(forwarded("203.0.113.50"), "::ffff:10.0.0.1") == "203.0.113.50"
    assert proxies(forwarded("2001:db8::1, 2001:db9::7"), "2001:db8::2") == "2001:db9::7"
    assert proxies(forwarded("1.1.1.1"), None) is None


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "not-an-ip", "10.0.0.0/x", "::/129", ""])
def test_refuses_what_it_cannot_read(bad: str) -> None:
    with pytest.raises(ValueError, match="not an address"):
        TrustedProxies([bad])


def test_accepts_everything_when_told_to() -> None:
    assert TrustedProxies(["0.0.0.0/0", "::/0"])
