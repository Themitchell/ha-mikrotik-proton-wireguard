"""Tests for tunnel-only MikroTik WireGuard apply and ECMP egress."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from proton_mikrotik_wg.mikrotik_wg import (
    EGRESS_ROUTE_COMMENT,
    apply_tunnel_only,
    apply_wireguard_slots,
    disable_egress,
    egress_masq_comment,
    egress_route_comment,
    enable_egress,
    endpoint_route_comment,
    is_egress_enabled,
)
from proton_mikrotik_wg.wg_credentials import WireGuardCredential
from proton_mikrotik_wg.wg_slots import wireguard_interface_name


def _cred(**overrides) -> WireGuardCredential:
    base = dict(
        device_name="ha-wg-proton-1",
        serial_number="sn-1",
        client_private_key="client-sk==",
        client_public_key="client-pk==",
        server_public_key="server-pk==",
        endpoint_host="1.2.3.4",
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=1_700_000_000,
        dns=None,
    )
    base.update(overrides)
    return WireGuardCredential(**base)


@dataclass
class FakePath:
    store: dict
    path: tuple[str, ...]
    _id_seq: list[int]

    def select(self, **kwargs):
        rows = list(self.store.get(self.path, []))
        if not kwargs:
            return [dict(r) for r in rows]
        out = []
        for row in rows:
            if all(row.get(k) == v for k, v in kwargs.items()):
                out.append(dict(row))
        return out

    def add(self, **kwargs):
        self._id_seq[0] += 1
        row_id = f"*{self._id_seq[0]}"
        row = {".id": row_id, **kwargs}
        self.store.setdefault(self.path, []).append(row)
        return row_id

    def update(self, **kwargs):
        row_id = kwargs.pop(".id")
        for row in self.store.get(self.path, []):
            if row[".id"] == row_id:
                row.update(kwargs)
                return
        raise KeyError(row_id)

    def remove(self, *ids):
        rows = self.store.get(self.path, [])
        self.store[self.path] = [row for row in rows if row[".id"] not in ids]


@dataclass
class FakeRouterOs:
    """In-memory RouterOS API stand-in for unit tests."""

    tables: dict = field(default_factory=dict)
    _id_seq: list = field(default_factory=lambda: [0])

    def path(self, *parts: str) -> FakePath:
        return FakePath(self.tables, parts, self._id_seq)


def test_apply_tunnel_only_creates_iface_peer_address_and_endpoint_route():
    api = FakeRouterOs()
    cred = _cred()
    iface = wireguard_interface_name(1)

    apply_tunnel_only(
        api,
        cred,
        wan_gateway="192.0.2.1",
        interface_name=iface,
        route_comment=endpoint_route_comment(1),
    )

    ifaces = api.path("interface", "wireguard").select(name=iface)
    assert len(ifaces) == 1
    assert ifaces[0]["private-key"] == "client-sk=="
    assert ifaces[0]["listen-port"] == "0"

    peers = api.path("interface", "wireguard", "peers").select(interface=iface)
    assert len(peers) == 1
    assert peers[0]["public-key"] == "server-pk=="
    assert peers[0]["endpoint-address"] == "1.2.3.4"
    assert peers[0]["endpoint-port"] == "51820"
    assert peers[0]["allowed-address"] == "0.0.0.0/0"
    assert peers[0]["persistent-keepalive"] == "25s"

    addrs = api.path("ip", "address").select(interface=iface)
    assert len(addrs) == 1
    assert addrs[0]["address"] == "10.2.0.2/32"
    assert addrs[0]["network"] == "10.2.0.1"

    routes = api.path("ip", "route").select(comment=endpoint_route_comment(1))
    assert len(routes) == 1
    assert routes[0]["dst-address"] == "1.2.3.4/32"
    assert routes[0]["gateway"] == "192.0.2.1"


def test_apply_tunnel_only_is_idempotent_and_updates_existing():
    api = FakeRouterOs()
    iface = wireguard_interface_name(1)
    apply_tunnel_only(
        api,
        _cred(),
        wan_gateway="192.0.2.1",
        interface_name=iface,
        route_comment=endpoint_route_comment(1),
    )
    apply_tunnel_only(
        api,
        _cred(
            client_private_key="new-sk==",
            server_public_key="new-spk==",
            endpoint_host="5.6.7.8",
            endpoint_port=51821,
            client_address="10.2.0.3/32",
        ),
        wan_gateway="192.0.2.2",
        interface_name=iface,
        route_comment=endpoint_route_comment(1),
    )

    ifaces = api.path("interface", "wireguard").select(name=iface)
    assert len(ifaces) == 1
    assert ifaces[0]["private-key"] == "new-sk=="

    peers = api.path("interface", "wireguard", "peers").select(interface=iface)
    assert len(peers) == 1
    assert peers[0]["public-key"] == "new-spk=="
    assert peers[0]["endpoint-address"] == "5.6.7.8"
    assert peers[0]["endpoint-port"] == "51821"

    addrs = api.path("ip", "address").select(interface=iface)
    assert len(addrs) == 1
    assert addrs[0]["address"] == "10.2.0.3/32"

    routes = api.path("ip", "route").select(comment=endpoint_route_comment(1))
    assert len(routes) == 1
    assert routes[0]["dst-address"] == "5.6.7.8/32"
    assert routes[0]["gateway"] == "192.0.2.2"


def test_apply_wireguard_slots_creates_numbered_interfaces():
    api = FakeRouterOs()
    slots = {
        1: _cred(serial_number="sn-1", endpoint_host="1.1.1.1"),
        2: _cred(
            device_name="ha-wg-proton-2",
            serial_number="sn-2",
            endpoint_host="2.2.2.2",
            client_private_key="sk2==",
            server_public_key="spk2==",
        ),
    }
    apply_wireguard_slots(api, slots, wan_gateway="zen", tunnel_count=2)

    assert api.path("interface", "wireguard").select(name="wg-proton-1")
    assert api.path("interface", "wireguard").select(name="wg-proton-2")
    assert api.path("ip", "route").select(comment=endpoint_route_comment(1))[0][
        "dst-address"
    ] == "1.1.1.1/32"
    assert api.path("ip", "route").select(comment=endpoint_route_comment(2))[0][
        "dst-address"
    ] == "2.2.2.2/32"


def test_apply_wireguard_slots_removes_orphan_and_legacy_iface():
    api = FakeRouterOs()
    api.path("interface", "wireguard").add(name="wg-proton", **{"private-key": "old"})
    api.path("interface", "wireguard").add(name="wg-proton-3", **{"private-key": "x"})
    api.path("ip", "route").add(
        comment="proton-wg-endpoint", **{"dst-address": "9.9.9.9/32", "gateway": "zen"}
    )
    api.path("ip", "route").add(
        comment=endpoint_route_comment(3),
        **{"dst-address": "8.8.8.8/32", "gateway": "zen"},
    )

    apply_wireguard_slots(
        api,
        {1: _cred()},
        wan_gateway="zen",
        tunnel_count=1,
    )

    assert not api.path("interface", "wireguard").select(name="wg-proton")
    assert not api.path("interface", "wireguard").select(name="wg-proton-3")
    assert api.path("interface", "wireguard").select(name="wg-proton-1")
    assert not api.path("ip", "route").select(comment="proton-wg-endpoint")
    assert not api.path("ip", "route").select(comment=endpoint_route_comment(3))


def test_apply_wireguard_slots_ignores_unrelated_routes():
    api = FakeRouterOs()
    api.path("ip", "route").add(
        comment="lan-route",
        **{"dst-address": "10.0.0.0/8", "gateway": "bridge"},
    )
    apply_wireguard_slots(api, {1: _cred()}, wan_gateway="zen", tunnel_count=1)
    assert api.path("ip", "route").select(comment="lan-route")


def test_apply_wireguard_slots_removes_peers_and_addresses_on_orphan():
    api = FakeRouterOs()
    api.path("interface", "wireguard").add(name="wg-proton-2", **{"private-key": "x"})
    api.path("interface", "wireguard", "peers").add(
        interface="wg-proton-2", **{"public-key": "p"}
    )
    api.path("ip", "address").add(interface="wg-proton-2", address="10.2.0.2/32")
    api.path("ip", "route").add(
        comment="proton-wg-endpoint-bad",
        **{"dst-address": "8.8.8.8/32", "gateway": "zen"},
    )
    apply_wireguard_slots(api, {1: _cred()}, wan_gateway="zen", tunnel_count=1)
    assert not api.path("interface", "wireguard").select(name="wg-proton-2")
    assert not api.path("interface", "wireguard", "peers").select(interface="wg-proton-2")
    assert not api.path("ip", "address").select(interface="wg-proton-2")


def test_is_egress_enabled_false_when_empty():
    assert is_egress_enabled(FakeRouterOs()) is False


def test_is_egress_enabled_ignores_unrelated_routes():
    api = FakeRouterOs()
    api.path("ip", "route").add(comment="other", **{"dst-address": "0.0.0.0/0"})
    api.path("ip", "route").add(**{"dst-address": "1.1.1.1/32"})  # no comment
    assert is_egress_enabled(api) is False


def test_disable_egress_ignores_unrelated_nat_and_routes():
    api = FakeRouterOs()
    _seed_pppoe(api)
    api.path("ip", "route").add(comment="keep-me", **{"dst-address": "10.0.0.0/8"})
    api.path("ip", "firewall", "nat").add(comment="other-masq", chain="srcnat")
    api.path("interface", "list", "member").add(
        list="WAN", interface="ether1", comment="manual-wan"
    )
    enable_egress(api, wan_interface="zen", slots={1: _cred()})
    disable_egress(api, wan_interface="zen")
    assert api.path("ip", "route").select(comment="keep-me")
    assert api.path("ip", "firewall", "nat").select(comment="other-masq")
    assert api.path("interface", "list", "member").select(
        list="WAN", interface="ether1"
    )


def test_librouteros_adapter_select_add_update_remove_and_close():
    from proton_mikrotik_wg.mikrotik_wg import LibRouterOsClient, LibRouterOsPath

    rows = [
        {"name": "wg-proton-1", ".id": "*1"},
        {"name": "other", ".id": "*2"},
    ]

    class RawPath:
        def __iter__(self):
            return iter(rows)

        def add(self, **kwargs):
            return "*3"

        def update(self, **kwargs):
            self.updated = kwargs

        def remove(self, *ids):
            self.removed = ids

    raw_path = RawPath()
    path = LibRouterOsPath(raw_path)
    assert len(path.select()) == 2
    assert path.select(name="wg-proton-1")[0][".id"] == "*1"
    assert path.add(name="x") == "*3"
    path.update(**{".id": "*1", "private-key": "k"})
    assert raw_path.updated["private-key"] == "k"
    path.remove("*1")
    assert raw_path.removed == ("*1",)

    api = MagicMock()
    api.path.return_value = raw_path
    client = LibRouterOsClient(api)
    assert isinstance(client.path("interface", "wireguard"), LibRouterOsPath)
    client.close()
    api.close.assert_called_once()


def test_librouteros_adapter_close_without_close_method():
    from proton_mikrotik_wg.mikrotik_wg import LibRouterOsClient

    api = MagicMock(spec=[])
    LibRouterOsClient(api).close()


def _seed_pppoe(api: FakeRouterOs, name: str = "zen", distance: int = 1) -> None:
    api.path("interface", "pppoe-client").add(
        name=name, **{"default-route-distance": distance}
    )


def test_enable_egress_adds_ecmp_routes_masq_and_raises_zen_distance():
    api = FakeRouterOs()
    _seed_pppoe(api)
    slots = {1: _cred(), 2: _cred(serial_number="sn-2", endpoint_host="2.2.2.2")}

    enable_egress(api, wan_interface="zen", slots=slots)

    assert is_egress_enabled(api) is True
    r1 = api.path("ip", "route").select(comment=egress_route_comment(1))[0]
    r2 = api.path("ip", "route").select(comment=egress_route_comment(2))[0]
    assert r1["gateway"] == "10.2.0.1%wg-proton-1"
    assert r2["gateway"] == "10.2.0.1%wg-proton-2"
    assert r1["distance"] == "1"
    assert r2["distance"] == "1"

    assert api.path("ip", "firewall", "nat").select(comment=egress_masq_comment(1))
    assert api.path("ip", "firewall", "nat").select(comment=egress_masq_comment(2))

    members = api.path("interface", "list", "member").select(list="WAN")
    assert {m["interface"] for m in members} == {"wg-proton-1", "wg-proton-2"}

    pppoe = api.path("interface", "pppoe-client").select(name="zen")[0]
    assert pppoe["default-route-distance"] == "2"


def test_enable_egress_requires_slots():
    api = FakeRouterOs()
    _seed_pppoe(api)
    with pytest.raises(ValueError, match="no WireGuard slots"):
        enable_egress(api, wan_interface="zen", slots={})


def test_disable_egress_removes_ecmp_and_restores_isp():
    api = FakeRouterOs()
    _seed_pppoe(api, distance=2)
    slots = {1: _cred()}
    enable_egress(api, wan_interface="zen", slots=slots)
    # legacy unscoped comments should also be cleaned
    api.path("ip", "route").add(
        comment=EGRESS_ROUTE_COMMENT,
        **{"dst-address": "0.0.0.0/0", "gateway": "10.2.0.1", "distance": "1"},
    )

    disable_egress(api, wan_interface="zen")

    assert is_egress_enabled(api) is False
    assert not api.path("ip", "route").select(comment=egress_route_comment(1))
    assert not api.path("ip", "firewall", "nat").select(comment=egress_masq_comment(1))
    assert not api.path("interface", "list", "member").select(list="WAN")
    pppoe = api.path("interface", "pppoe-client").select(name="zen")[0]
    assert pppoe["default-route-distance"] == "1"


def test_enable_egress_requires_pppoe_interface():
    api = FakeRouterOs()
    with pytest.raises(ValueError, match="pppoe-client"):
        enable_egress(api, wan_interface="zen", slots={1: _cred()})


def test_wan_list_member_idempotent():
    api = FakeRouterOs()
    _seed_pppoe(api)
    slots = {1: _cred()}
    enable_egress(api, wan_interface="zen", slots=slots)
    enable_egress(api, wan_interface="zen", slots=slots)
    members = api.path("interface", "list", "member").select(
        list="WAN", interface="wg-proton-1"
    )
    assert len(members) == 1
