"""Tests for Proton WireGuard credential creation."""

from __future__ import annotations

from unittest.mock import MagicMock

from proton_mikrotik_wg.wg_credentials import (
    ProtonLogicalServer,
    WireGuardCredential,
    WireGuardKeyPair,
    create_wireguard_credential,
)


def test_create_wireguard_credential_registers_certificate():
    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "SerialNumber": "sn-1",
        "DeviceName": "ha-UK-1",
        "ExpirationTime": 1_700_000_000,
        "Features": {
            "peerName": "UK#1",
            "peerIp": "1.2.3.4",
            "peerPublicKey": "server-wg-pk==",
        },
    }
    server = ProtonLogicalServer(
        name="UK#1",
        entry_ip="1.2.3.4",
        x25519_public_key="server-wg-pk==",
    )
    keys = WireGuardKeyPair(
        private_key="client-sk==",
        public_key="client-pk==",
    )

    cred = create_wireguard_credential(
        session,
        server=server,
        keys=keys,
        device_name="ha-UK-1",
    )

    assert isinstance(cred, WireGuardCredential)
    assert cred.device_name == "ha-UK-1"
    assert cred.serial_number == "sn-1"
    assert cred.client_private_key == "client-sk=="
    assert cred.client_public_key == "client-pk=="
    assert cred.server_public_key == "server-wg-pk=="
    assert cred.endpoint_host == "1.2.3.4"
    assert cred.endpoint_port == 51820
    assert cred.client_address == "10.2.0.2/32"
    assert cred.expiration_time == 1_700_000_000
    # DNS must never be Proton's 10.2.0.1 — Pi-hole only on LAN.
    assert cred.dns is None

    session.api_request.assert_called_once_with(
        "/vpn/v1/certificate",
        {
            "ClientPublicKey": "client-pk==",
            "Mode": "persistent",
            "DeviceName": "ha-UK-1",
            "Features": {
                "peerName": "UK#1",
                "peerIp": "1.2.3.4",
                "peerPublicKey": "server-wg-pk==",
                "platform": "Linux",
                "NetShieldLevel": 0,
                "RandomNAT": True,
                "PortForwarding": False,
                "SplitTCP": True,
                "SafeMode": False,
            },
        },
        method="post",
    )


def test_generate_wireguard_keypair_returns_base64_keys():
    from proton_mikrotik_wg.wg_credentials import generate_wireguard_keypair

    keys = generate_wireguard_keypair()
    assert isinstance(keys, WireGuardKeyPair)
    assert keys.private_key != keys.public_key
    # Standard WireGuard keys are 32 raw bytes → 44 chars base64 with padding.
    assert len(keys.private_key) == 44
    assert len(keys.public_key) == 44


def test_list_logical_servers_parses_online_instances():
    from proton_mikrotik_wg.wg_credentials import list_logical_servers

    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "UK#1",
                "Status": 1,
                "Load": 12,
                "Servers": [
                    {
                        "EntryIP": "1.2.3.4",
                        "X25519PublicKey": "server-wg-pk==",
                    }
                ],
            },
            {
                "Name": "UK#2",
                "Status": 0,  # offline
                "Load": 1,
                "Servers": [
                    {
                        "EntryIP": "5.6.7.8",
                        "X25519PublicKey": "other==",
                    }
                ],
            },
            {
                "Name": "UK#3",
                "Status": 1,
                "Load": 40,
                "Servers": [],  # no instances
            },
        ],
    }

    servers = list_logical_servers(session)
    assert len(servers) == 1
    assert servers[0].name == "UK#1"
    assert servers[0].entry_ip == "1.2.3.4"
    assert servers[0].load == 12
    session.api_request.assert_called_once_with("/vpn/logicals", method="get")


def test_pick_least_loaded_server():
    from proton_mikrotik_wg.wg_credentials import pick_least_loaded_server

    servers = [
        ProtonLogicalServer("UK#1", "1.1.1.1", "a==", load=40),
        ProtonLogicalServer("UK#2", "2.2.2.2", "b==", load=8),
        ProtonLogicalServer("UK#3", "3.3.3.3", "c==", load=20),
    ]
    assert pick_least_loaded_server(servers).name == "UK#2"


def test_pick_least_loaded_server_requires_servers():
    import pytest
    from proton_mikrotik_wg.wg_credentials import pick_least_loaded_server

    with pytest.raises(ValueError, match="no Proton servers"):
        pick_least_loaded_server([])


def test_provision_wireguard_credential_generates_keys_and_registers():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 5,
                    "Servers": [
                        {"EntryIP": "1.2.3.4", "X25519PublicKey": "server-wg-pk=="}
                    ],
                }
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-9",
            "DeviceName": "ha-wg-proton",
            "ExpirationTime": 1_800_000_000,
        },
    ]

    cred = provision_wireguard_credential(session, device_name="ha-wg-proton")
    assert cred.serial_number == "sn-9"
    assert cred.endpoint_host == "1.2.3.4"
    assert cred.dns is None
    assert len(cred.client_private_key) == 44
    assert session.api_request.call_count == 2
