"""Parse and validate VPN client IP/CIDR bypass lists."""

from __future__ import annotations

import ipaddress


def parse_vpn_bypass_cidrs(text: str) -> list[str]:
    """Parse a multiline IPv4/CIDR list into normalized network strings.

    Blank lines and ``#`` comments are ignored. Single hosts become ``/32``.
    Raises ``ValueError`` when a non-comment line is not a valid IPv4 address
    or network.
    """
    networks: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as err:
            raise ValueError(f"invalid VPN bypass CIDR: {line!r}") from err
        if network.version != 4:
            raise ValueError(f"invalid VPN bypass CIDR: {line!r}")
        networks.append(str(network))
    return networks
