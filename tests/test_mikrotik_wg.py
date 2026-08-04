"""Tests for tunnel-only MikroTik WireGuard apply."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from proton_mikrotik_wg.const import DEFAULT_WG_INTERFACE
from proton_mikrotik_wg.mikrotik_wg import (
    EGRESS_MASQ_COMMENT,
    EGRESS_ROUTE_COMMENT,
    ENDPOINT_ROUTE_COMMENT,
    apply_tunnel_only,
    disable_egress,
    enable_egress,
    is_egress_enabled,
)
from proton_mikrotik_wg.wg_credentials import WireGuardCredential


def _cred(**overrides) -> WireGuardCredential:
    base = dict(
        device_name="ha-wg-proton",
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

    apply_tunnel_only(api, cred, wan_gateway="192.0.2.1")

    ifaces = api.path("interface", "wireguard").select(name=DEFAULT_WG_INTERFACE)
    assert len(ifaces) == 1
    assert ifaces[0]["private-key"] == "client-sk=="
    assert ifaces[0]["listen-port"] == "0"

    peers = api.path("interface", "wireguard", "peers").select(
        interface=DEFAULT_WG_INTERFACE
    )
    assert len(peers) == 1
    assert peers[0]["public-key"] == "server-pk=="
    assert peers[0]["endpoint-address"] == "1.2.3.4"
    assert peers[0]["endpoint-port"] == "51820"
    assert peers[0]["allowed-address"] == "0.0.0.0/0"
    assert peers[0]["persistent-keepalive"] == "25s"

    addrs = api.path("ip", "address").select(interface=DEFAULT_WG_INTERFACE)
    assert len(addrs) == 1
    assert addrs[0]["address"] == "10.2.0.2/32"

    routes = api.path("ip", "route").select(comment=ENDPOINT_ROUTE_COMMENT)
    assert len(routes) == 1
    assert routes[0]["dst-address"] == "1.2.3.4/32"
    assert routes[0]["gateway"] == "192.0.2.1"


def test_apply_tunnel_only_is_idempotent_and_updates_existing():
    api = FakeRouterOs()
    apply_tunnel_only(api, _cred(), wan_gateway="192.0.2.1")
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
    )

    ifaces = api.path("interface", "wireguard").select(name=DEFAULT_WG_INTERFACE)
    assert len(ifaces) == 1
    assert ifaces[0]["private-key"] == "new-sk=="

    peers = api.path("interface", "wireguard", "peers").select(
        interface=DEFAULT_WG_INTERFACE
    )
    assert len(peers) == 1
    assert peers[0]["public-key"] == "new-spk=="
    assert peers[0]["endpoint-address"] == "5.6.7.8"
    assert peers[0]["endpoint-port"] == "51821"

    addrs = api.path("ip", "address").select(interface=DEFAULT_WG_INTERFACE)
    assert len(addrs) == 1
    assert addrs[0]["address"] == "10.2.0.3/32"

    routes = api.path("ip", "route").select(comment=ENDPOINT_ROUTE_COMMENT)
    assert len(routes) == 1
    assert routes[0]["dst-address"] == "5.6.7.8/32"
    assert routes[0]["gateway"] == "192.0.2.2"


def test_librouteros_adapter_select_add_update_and_close():
    from proton_mikrotik_wg.mikrotik_wg import LibRouterOsClient, LibRouterOsPath

    rows = [
        {"name": "wg-proton", ".id": "*1"},
        {"name": "other", ".id": "*2"},
    ]

    class RawPath:
        def __iter__(self):
            return iter(rows)

        def add(self, **kwargs):
            return "*3"

        def update(self, **kwargs):
            self.updated = kwargs

    raw_path = RawPath()
    path = LibRouterOsPath(raw_path)
    assert len(path.select()) == 2
    assert path.select(name="wg-proton")[0][".id"] == "*1"
    assert path.add(name="x") == "*3"
    path.update(**{".id": "*1", "private-key": "k"})
    assert raw_path.updated["private-key"] == "k"

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


def test_enable_egress_adds_default_route_masq_and_raises_zen_distance():
    api = FakeRouterOs()
    _seed_pppoe(api)

    enable_egress(api, wan_interface="zen")

    assert is_egress_enabled(api) is True
    routes = api.path("ip", "route").select(comment=EGRESS_ROUTE_COMMENT)
    assert len(routes) == 1
    assert routes[0]["dst-address"] == "0.0.0.0/0"
    assert routes[0]["gateway"] == DEFAULT_WG_INTERFACE
    assert routes[0]["distance"] == "1"

    nat = api.path("ip", "firewall", "nat").select(comment=EGRESS_MASQ_COMMENT)
    assert len(nat) == 1
    assert nat[0]["chain"] == "srcnat"
    assert nat[0]["action"] == "masquerade"
    assert nat[0]["out-interface"] == DEFAULT_WG_INTERFACE

    pppoe = api.path("interface", "pppoe-client").select(name="zen")
    assert pppoe[0]["default-route-distance"] == "2"


def test_disable_egress_removes_route_masq_and_restores_zen_distance():
    api = FakeRouterOs()
    _seed_pppoe(api)
    enable_egress(api, wan_interface="zen")
    disable_egress(api, wan_interface="zen")

    assert is_egress_enabled(api) is False
    assert api.path("ip", "route").select(comment=EGRESS_ROUTE_COMMENT) == []
    assert api.path("ip", "firewall", "nat").select(comment=EGRESS_MASQ_COMMENT) == []
    assert (
        api.path("interface", "pppoe-client").select(name="zen")[0][
            "default-route-distance"
        ]
        == "1"
    )


def test_enable_egress_is_idempotent():
    api = FakeRouterOs()
    _seed_pppoe(api)
    enable_egress(api, wan_interface="zen")
    enable_egress(api, wan_interface="zen")
    assert len(api.path("ip", "route").select(comment=EGRESS_ROUTE_COMMENT)) == 1
    assert len(api.path("ip", "firewall", "nat").select(comment=EGRESS_MASQ_COMMENT)) == 1


def test_enable_egress_requires_pppoe_interface():
    api = FakeRouterOs()
    with pytest.raises(ValueError, match="pppoe"):
        enable_egress(api, wan_interface="zen")


def test_librouteros_adapter_remove():
    from proton_mikrotik_wg.mikrotik_wg import LibRouterOsPath

    rows = [{"name": "a", ".id": "*1"}, {"name": "b", ".id": "*2"}]

    class RawPath:
        def __iter__(self):
            return iter(rows)

        def remove(self, *ids):
            self.removed = ids

        def add(self, **kwargs):
            return "*9"

        def update(self, **kwargs):
            return None

    raw = RawPath()
    path = LibRouterOsPath(raw)
    path.remove("*1")
    assert raw.removed == ("*1",)
