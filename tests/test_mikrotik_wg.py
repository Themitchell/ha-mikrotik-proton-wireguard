"""Tests for tunnel-only MikroTik WireGuard apply."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from proton_mikrotik_wg.const import DEFAULT_WG_INTERFACE
from proton_mikrotik_wg.mikrotik_wg import (
    ENDPOINT_ROUTE_COMMENT,
    apply_tunnel_only,
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
