"""Apply Proton WireGuard credentials to a MikroTik router (tunnel-only)."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .const import (
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_DEVICE_NAME,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_EXPIRATION_TIME,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_SERVER_PUBLIC_KEY,
    DEFAULT_WG_INTERFACE,
)
from .wg_credentials import WireGuardCredential

ENDPOINT_ROUTE_COMMENT = "proton-wg-endpoint"
EGRESS_ROUTE_COMMENT = "proton-wg-egress"
EGRESS_MASQ_COMMENT = "proton-wg-masq"
WAN_LIST_COMMENT = "proton-wg-wan"
DEFAULT_KEEPALIVE = "25s"
PROTON_WG_GATEWAY = "10.2.0.1"
WAN_INTERFACE_LIST = "WAN"

_REQUIRED_WG_FIELDS = (
    CONF_WG_DEVICE_NAME,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_SERVER_PUBLIC_KEY,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_EXPIRATION_TIME,
)


class RouterOsPath(Protocol):
    """One RouterOS API path (e.g. /interface/wireguard)."""

    def select(self, **kwargs: Any) -> list[dict[str, Any]]:
        ...

    def add(self, **kwargs: Any) -> str:
        ...

    def update(self, **kwargs: Any) -> None:
        ...

    def remove(self, *ids: str) -> None:
        ...


class RouterOsClient(Protocol):
    """Minimal injectable RouterOS API surface."""

    def path(self, *parts: str) -> RouterOsPath:
        ...


class LibRouterOsPath:
    """Adapt librouteros Path to RouterOsPath (filter in Python)."""

    def __init__(self, path: Any) -> None:
        self._path = path

    def select(self, **kwargs: Any) -> list[dict[str, Any]]:
        rows = [dict(row) for row in self._path]
        if not kwargs:
            return rows
        return [
            row
            for row in rows
            if all(row.get(key) == value for key, value in kwargs.items())
        ]

    def add(self, **kwargs: Any) -> str:
        return self._path.add(**kwargs)

    def update(self, **kwargs: Any) -> None:
        self._path.update(**kwargs)

    def remove(self, *ids: str) -> None:
        self._path.remove(*ids)


class LibRouterOsClient:
    """Adapt a librouteros API connection to RouterOsClient."""

    def __init__(self, api: Any) -> None:
        self._api = api

    def path(self, *parts: str) -> LibRouterOsPath:
        return LibRouterOsPath(self._api.path(*parts))

    def close(self) -> None:
        close = getattr(self._api, "close", None)
        if callable(close):
            close()


def wireguard_credential_from_entry_data(data: Mapping[str, Any]) -> WireGuardCredential:
    """Rebuild a WireGuardCredential from config entry data."""
    missing = [key for key in _REQUIRED_WG_FIELDS if key not in data]
    if missing:
        raise ValueError(
            "WireGuard credential is not provisioned on this entry "
            f"(missing {', '.join(missing)})"
        )
    return WireGuardCredential(
        device_name=str(data[CONF_WG_DEVICE_NAME]),
        serial_number=str(data[CONF_WG_SERIAL_NUMBER]),
        client_private_key=str(data[CONF_WG_CLIENT_PRIVATE_KEY]),
        client_public_key=str(data[CONF_WG_CLIENT_PUBLIC_KEY]),
        server_public_key=str(data[CONF_WG_SERVER_PUBLIC_KEY]),
        endpoint_host=str(data[CONF_WG_ENDPOINT_HOST]),
        endpoint_port=int(data[CONF_WG_ENDPOINT_PORT]),
        client_address=str(data[CONF_WG_CLIENT_ADDRESS]),
        expiration_time=int(data[CONF_WG_EXPIRATION_TIME]),
        dns=None,
    )


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


def _remove_by_comment(path: RouterOsPath, comment: str) -> None:
    for row in path.select(comment=comment):
        path.remove(row[".id"])


def _set_pppoe_default_route_distance(
    client: RouterOsClient, wan_interface: str, distance: str
) -> None:
    pppoe = client.path("interface", "pppoe-client")
    existing = pppoe.select(name=wan_interface)
    if not existing:
        raise ValueError(
            f"pppoe-client interface {wan_interface!r} not found on MikroTik"
        )
    pppoe.update(
        **{".id": existing[0][".id"], "default-route-distance": distance}
    )


def is_egress_enabled(client: RouterOsClient) -> bool:
    """Return True when the proton-wg-egress default route is present."""
    return bool(client.path("ip", "route").select(comment=EGRESS_ROUTE_COMMENT))


def _ensure_wan_list_member(
    client: RouterOsClient, *, wg_interface: str
) -> None:
    members = client.path("interface", "list", "member")
    existing = members.select(list=WAN_INTERFACE_LIST, interface=wg_interface)
    if existing:
        return
    members.add(
        list=WAN_INTERFACE_LIST,
        interface=wg_interface,
        comment=WAN_LIST_COMMENT,
    )


def _remove_wan_list_member(
    client: RouterOsClient, *, wg_interface: str
) -> None:
    members = client.path("interface", "list", "member")
    for row in members.select(
        list=WAN_INTERFACE_LIST, interface=wg_interface, comment=WAN_LIST_COMMENT
    ):
        members.remove(row[".id"])


def enable_egress(
    client: RouterOsClient,
    *,
    wan_interface: str,
    wg_interface: str = DEFAULT_WG_INTERFACE,
) -> None:
    """Prefer whole-home egress via WireGuard; keep ISP as higher-distance backup."""
    _ensure_wan_list_member(client, wg_interface=wg_interface)
    _upsert(
        client.path("ip", "route"),
        match={"comment": EGRESS_ROUTE_COMMENT},
        values={
            "dst-address": "0.0.0.0/0",
            "gateway": PROTON_WG_GATEWAY,
            "distance": "1",
        },
    )
    _upsert(
        client.path("ip", "firewall", "nat"),
        match={"comment": EGRESS_MASQ_COMMENT},
        values={
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": wg_interface,
        },
    )
    _set_pppoe_default_route_distance(client, wan_interface, "2")


def disable_egress(
    client: RouterOsClient,
    *,
    wan_interface: str,
    wg_interface: str = DEFAULT_WG_INTERFACE,
) -> None:
    """Remove VPN default route/NAT and restore ISP as primary default."""
    _remove_by_comment(client.path("ip", "route"), EGRESS_ROUTE_COMMENT)
    _remove_by_comment(client.path("ip", "firewall", "nat"), EGRESS_MASQ_COMMENT)
    _remove_wan_list_member(client, wg_interface=wg_interface)
    _set_pppoe_default_route_distance(client, wan_interface, "1")


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
        values={
            "address": credential.client_address,
            "network": PROTON_WG_GATEWAY,
        },
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
