"""Apply Proton WireGuard credentials to a MikroTik router (tunnel-only)."""

from __future__ import annotations

from typing import Any, Protocol

from .const import DEFAULT_WG_INTERFACE
from .wg_credentials import WireGuardCredential

ENDPOINT_ROUTE_COMMENT = "proton-wg-endpoint"
DEFAULT_KEEPALIVE = "25s"


class RouterOsPath(Protocol):
    """One RouterOS API path (e.g. /interface/wireguard)."""

    def select(self, **kwargs: Any) -> list[dict[str, Any]]:
        ...

    def add(self, **kwargs: Any) -> str:
        ...

    def update(self, **kwargs: Any) -> None:
        ...


class RouterOsClient(Protocol):
    """Minimal injectable RouterOS API surface."""

    def path(self, *parts: str) -> RouterOsPath:
        ...


def _upsert(
    path: RouterOsPath,
    *,
    match: dict[str, Any],
    values: dict[str, Any],
) -> None:
    existing = path.select(**match)
    if existing:
        path.update(**{".id": existing[0][".id"], **values})
    else:
        path.add(**{**match, **values})


def apply_tunnel_only(
    client: RouterOsClient,
    credential: WireGuardCredential,
    *,
    wan_gateway: str,
    interface_name: str = DEFAULT_WG_INTERFACE,
    keepalive: str = DEFAULT_KEEPALIVE,
) -> None:
    """Create or update wg-proton without changing default LAN egress.

    Sets interface, peer, address, and an endpoint /32 pin via WAN.
    Does not add a default route via the tunnel, NAT, kill-switch, or DNS.
    """
    ifaces = client.path("interface", "wireguard")
    _upsert(
        ifaces,
        match={"name": interface_name},
        values={
            "private-key": credential.client_private_key,
            "listen-port": "0",
        },
    )

    peers = client.path("interface", "wireguard", "peers")
    _upsert(
        peers,
        match={"interface": interface_name},
        values={
            "public-key": credential.server_public_key,
            "endpoint-address": credential.endpoint_host,
            "endpoint-port": str(credential.endpoint_port),
            "allowed-address": "0.0.0.0/0",
            "persistent-keepalive": keepalive,
        },
    )

    addresses = client.path("ip", "address")
    _upsert(
        addresses,
        match={"interface": interface_name},
        values={"address": credential.client_address},
    )

    routes = client.path("ip", "route")
    _upsert(
        routes,
        match={"comment": ENDPOINT_ROUTE_COMMENT},
        values={
            "dst-address": f"{credential.endpoint_host}/32",
            "gateway": wan_gateway,
        },
    )
