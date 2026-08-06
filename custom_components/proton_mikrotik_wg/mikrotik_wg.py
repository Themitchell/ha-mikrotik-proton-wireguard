"""Apply Proton WireGuard credentials to a MikroTik router (tunnel-only)."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from .const import (
    DEFAULT_WG_INTERFACE,
    MAX_TUNNEL_COUNT,
)
from .wg_credentials import WireGuardCredential

ENDPOINT_ROUTE_COMMENT = "proton-wg-endpoint"
EGRESS_ROUTE_COMMENT = "proton-wg-egress"
EGRESS_MASQ_COMMENT = "proton-wg-masq"
WAN_LIST_COMMENT = "proton-wg-wan"
BYPASS_ADDRESS_LIST = "proton-wg-bypass"
BYPASS_MANGLE_COMMENT = "proton-wg-bypass"
BYPASS_ROUTE_COMMENT = "proton-wg-bypass-default"
BYPASS_ROUTING_MARK = "proton-wg-isp"
DEFAULT_KEEPALIVE = "25s"
PROTON_WG_GATEWAY = "10.2.0.1"
WAN_INTERFACE_LIST = "WAN"


def endpoint_route_comment(slot: int) -> str:
    return f"{ENDPOINT_ROUTE_COMMENT}-{slot}"


def egress_route_comment(slot: int) -> str:
    return f"{EGRESS_ROUTE_COMMENT}-{slot}"


def egress_masq_comment(slot: int) -> str:
    return f"{EGRESS_MASQ_COMMENT}-{slot}"


def wan_list_comment(slot: int) -> str:
    return f"{WAN_LIST_COMMENT}-{slot}"


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
    """Rebuild a WireGuardCredential from config entry data (slot 1 / legacy)."""
    from .wg_slots import slots_from_entry_data

    slots = slots_from_entry_data(data)
    if not slots:
        raise ValueError("WireGuard credential is not provisioned on this entry")
    return slots[min(slots)]


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


def _remove_by_comment_prefix(path: RouterOsPath, prefix: str) -> None:
    for row in path.select():
        comment = str(row.get("comment") or "")
        if comment == prefix or comment.startswith(f"{prefix}-"):
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
    """Return True when any proton-wg-egress route is present."""
    for row in client.path("ip", "route").select():
        comment = str(row.get("comment") or "")
        if comment == EGRESS_ROUTE_COMMENT or comment.startswith(
            f"{EGRESS_ROUTE_COMMENT}-"
        ):
            return True
    return False


def _ensure_wan_list_member(
    client: RouterOsClient, *, wg_interface: str, comment: str
) -> None:
    members = client.path("interface", "list", "member")
    existing = members.select(list=WAN_INTERFACE_LIST, interface=wg_interface)
    if existing:
        return
    members.add(
        list=WAN_INTERFACE_LIST,
        interface=wg_interface,
        comment=comment,
    )


def _remove_wan_list_members(client: RouterOsClient) -> None:
    members = client.path("interface", "list", "member")
    for row in members.select(list=WAN_INTERFACE_LIST):
        comment = str(row.get("comment") or "")
        if comment == WAN_LIST_COMMENT or comment.startswith(f"{WAN_LIST_COMMENT}-"):
            members.remove(row[".id"])


def _remove_bypass_artifacts(client: RouterOsClient) -> None:
    """Remove owned ISP-bypass address-list, mangle, and marked default route."""
    address_list = client.path("ip", "firewall", "address-list")
    for row in list(address_list.select(list=BYPASS_ADDRESS_LIST)):
        comment = str(row.get("comment") or "")
        if comment == BYPASS_MANGLE_COMMENT or comment.startswith(
            f"{BYPASS_MANGLE_COMMENT}-"
        ):
            address_list.remove(row[".id"])
    _remove_by_comment_prefix(
        client.path("ip", "firewall", "mangle"), BYPASS_MANGLE_COMMENT
    )
    routes = client.path("ip", "route")
    for row in list(routes.select()):
        if str(row.get("comment") or "") == BYPASS_ROUTE_COMMENT:
            routes.remove(row[".id"])


def sync_vpn_bypass(
    client: RouterOsClient,
    *,
    wan_interface: str,
    bypass_cidrs: Sequence[str],
) -> None:
    """Sync LAN clients that should use ISP while VPN egress is on."""
    _remove_bypass_artifacts(client)
    if not bypass_cidrs:
        return

    address_list = client.path("ip", "firewall", "address-list")
    for cidr in bypass_cidrs:
        address_list.add(
            list=BYPASS_ADDRESS_LIST,
            address=cidr,
            comment=BYPASS_MANGLE_COMMENT,
        )

    _upsert(
        client.path("ip", "firewall", "mangle"),
        match={"comment": BYPASS_MANGLE_COMMENT},
        values={
            "chain": "prerouting",
            "src-address-list": BYPASS_ADDRESS_LIST,
            "action": "mark-routing",
            "new-routing-mark": BYPASS_ROUTING_MARK,
            "passthrough": False,
        },
    )
    _upsert(
        client.path("ip", "route"),
        match={"comment": BYPASS_ROUTE_COMMENT},
        values={
            "dst-address": "0.0.0.0/0",
            "gateway": wan_interface,
            "routing-mark": BYPASS_ROUTING_MARK,
            "distance": "1",
        },
    )


def enable_egress(
    client: RouterOsClient,
    *,
    wan_interface: str,
    slots: Mapping[int, Any],
    bypass_cidrs: Sequence[str] | None = None,
) -> None:
    """Prefer whole-home ECMP egress via all WireGuard slots; ISP as backup."""
    if not slots:
        raise ValueError("no WireGuard slots provisioned for egress")
    for slot in sorted(slots):
        from .wg_slots import wireguard_interface_name

        iface = wireguard_interface_name(slot)
        _ensure_wan_list_member(
            client, wg_interface=iface, comment=wan_list_comment(slot)
        )
        _upsert(
            client.path("ip", "route"),
            match={"comment": egress_route_comment(slot)},
            values={
                "dst-address": "0.0.0.0/0",
                "gateway": f"{PROTON_WG_GATEWAY}%{iface}",
                "distance": "1",
            },
        )
        _upsert(
            client.path("ip", "firewall", "nat"),
            match={"comment": egress_masq_comment(slot)},
            values={
                "chain": "srcnat",
                "action": "masquerade",
                "out-interface": iface,
            },
        )
    _set_pppoe_default_route_distance(client, wan_interface, "2")
    sync_vpn_bypass(
        client,
        wan_interface=wan_interface,
        bypass_cidrs=list(bypass_cidrs or ()),
    )


def disable_egress(
    client: RouterOsClient,
    *,
    wan_interface: str,
) -> None:
    """Remove VPN ECMP routes/NAT and restore ISP as primary default."""
    _remove_bypass_artifacts(client)
    _remove_by_comment_prefix(client.path("ip", "route"), EGRESS_ROUTE_COMMENT)
    _remove_by_comment_prefix(client.path("ip", "firewall", "nat"), EGRESS_MASQ_COMMENT)
    _remove_wan_list_members(client)
    _set_pppoe_default_route_distance(client, wan_interface, "1")


def apply_tunnel_only(
    client: RouterOsClient,
    credential: WireGuardCredential,
    *,
    wan_gateway: str,
    interface_name: str,
    route_comment: str,
    keepalive: str = DEFAULT_KEEPALIVE,
) -> None:
    """Create or update one WireGuard interface without changing LAN egress."""
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
        match={"comment": route_comment},
        values={
            "dst-address": f"{credential.endpoint_host}/32",
            "gateway": wan_gateway,
        },
    )


def _remove_wireguard_interface(client: RouterOsClient, interface_name: str) -> None:
    peers = client.path("interface", "wireguard", "peers")
    for row in peers.select(interface=interface_name):
        peers.remove(row[".id"])
    addresses = client.path("ip", "address")
    for row in addresses.select(interface=interface_name):
        addresses.remove(row[".id"])
    ifaces = client.path("interface", "wireguard")
    for row in ifaces.select(name=interface_name):
        ifaces.remove(row[".id"])


def apply_wireguard_slots(
    client: RouterOsClient,
    slots: Mapping[int, WireGuardCredential],
    *,
    wan_gateway: str,
    tunnel_count: int,
    keepalive: str = DEFAULT_KEEPALIVE,
) -> None:
    """Apply slots 1..tunnel_count; remove owned interfaces above that and legacy."""
    from .wg_slots import wireguard_interface_name

    active = {
        slot: cred
        for slot, cred in slots.items()
        if 1 <= slot <= tunnel_count
    }
    for slot, cred in sorted(active.items()):
        apply_tunnel_only(
            client,
            cred,
            wan_gateway=wan_gateway,
            interface_name=wireguard_interface_name(slot),
            route_comment=endpoint_route_comment(slot),
            keepalive=keepalive,
        )

    # Drop endpoint routes for inactive slots and legacy unscoped comment.
    routes = client.path("ip", "route")
    for row in list(routes.select()):
        comment = str(row.get("comment") or "")
        if comment == ENDPOINT_ROUTE_COMMENT:
            routes.remove(row[".id"])
            continue
        if comment.startswith(f"{ENDPOINT_ROUTE_COMMENT}-"):
            try:
                slot = int(comment.rsplit("-", 1)[-1])
            except ValueError:
                continue
            if slot not in active:
                routes.remove(row[".id"])

    # Remove orphan numbered interfaces and legacy wg-proton.
    _remove_wireguard_interface(client, DEFAULT_WG_INTERFACE)
    for slot in range(1, MAX_TUNNEL_COUNT + 1):
        if slot in active:
            continue
        _remove_wireguard_interface(client, wireguard_interface_name(slot))
