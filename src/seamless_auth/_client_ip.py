"""The end user's address, behind proxies the application names."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from ._http import Headers

MAX_USER_AGENT_LENGTH = 512

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _canonical(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def parse_ip(value: str | None) -> IPAddress | None:
    if not value:
        return None
    try:
        return _canonical(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


class TrustedProxies:
    """Resolves the end user's address for an app behind proxies with these
    addresses or subnets (``"10.0.0.0/8"``, ``"127.0.0.1"``).

    It walks ``X-Forwarded-For`` from the right, skipping trusted proxies, and
    returns the first address that is not one. There is deliberately no hop
    count: it cannot tell a proxy from a client that sent its own header.
    """

    def __init__(self, proxies: Iterable[str]) -> None:
        networks: list[IPNetwork] = []
        for proxy in proxies:
            try:
                networks.append(ipaddress.ip_network(proxy.strip(), strict=False))
            except ValueError as err:
                raise ValueError(f"{proxy!r} is not an address or CIDR subnet") from err
        self._networks = networks

    def _trusted(self, ip: IPAddress) -> bool:
        return any(ip.version == net.version and ip in net for net in self._networks)

    def __call__(self, headers: Headers, peer: str | None) -> str | None:
        peer_ip = parse_ip(peer)
        if peer_ip is None:
            return None
        if not self._trusted(peer_ip):
            return str(peer_ip)

        hops = [
            hop.strip()
            for value in headers.get_all("x-forwarded-for")
            for hop in value.split(",")
            if hop.strip()
        ]
        for hop in reversed(hops):
            ip = parse_ip(hop)
            # Not an address, so not a trusted proxy either: whoever wrote it is
            # the client, and it has no usable address.
            if ip is None:
                return None
            if not self._trusted(ip):
                return str(ip)
        if hops:
            first = parse_ip(hops[0])
            return str(first) if first else None
        return str(peer_ip)


def client_user_agent(headers: Headers) -> str | None:
    agent = (headers.get("user-agent") or "").strip()[:MAX_USER_AGENT_LENGTH]
    # Forwarded in a header, so it has to be printable ASCII; anything else is dropped
    # rather than failing the request.
    if not agent or not (agent.isascii() and agent.isprintable()):
        return None
    return agent
