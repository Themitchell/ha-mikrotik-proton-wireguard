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
                "Features": 0,
                "Tier": 0,
                "Score": 1.5,
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
                "Features": 0,
                "Tier": 0,
                "Score": 0.1,
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
                "Features": 0,
                "Tier": 0,
                "Score": 2.0,
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


def test_list_logical_servers_skips_secure_core_and_tor():
    """Match Proton UI: (Features & 3) == 0 excludes Secure Core and TOR."""
    from proton_mikrotik_wg.wg_credentials import list_logical_servers

    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "CH-SE#1",
                "Status": 1,
                "Load": 1,
                "Features": 1,  # Secure Core
                "Tier": 2,
                "Score": 0.1,
                "Servers": [
                    {"EntryIP": "9.9.9.9", "X25519PublicKey": "sc=="}
                ],
            },
            {
                "Name": "IS#1",
                "Status": 1,
                "Load": 2,
                "Features": 2,  # TOR
                "Tier": 2,
                "Score": 0.2,
                "Servers": [
                    {"EntryIP": "8.8.8.8", "X25519PublicKey": "tor=="}
                ],
            },
            {
                "Name": "UK#1",
                "Status": 1,
                "Load": 50,
                "Features": 0,
                "Tier": 0,
                "Score": 1.0,
                "Servers": [
                    {"EntryIP": "1.2.3.4", "X25519PublicKey": "ok=="}
                ],
            },
        ],
    }

    servers = list_logical_servers(session)
    assert [s.name for s in servers] == ["UK#1"]


def test_list_logical_servers_respects_max_tier():
    """Only return logicals the account tier is allowed to use."""
    from proton_mikrotik_wg.wg_credentials import list_logical_servers

    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "FREE#1",
                "Status": 1,
                "Load": 10,
                "Features": 0,
                "Tier": 0,
                "Score": 2.0,
                "Servers": [
                    {"EntryIP": "1.1.1.1", "X25519PublicKey": "free=="}
                ],
            },
            {
                "Name": "PLUS#1",
                "Status": 1,
                "Load": 5,
                "Features": 0,
                "Tier": 2,
                "Score": 0.5,
                "Servers": [
                    {"EntryIP": "2.2.2.2", "X25519PublicKey": "plus=="}
                ],
            },
        ],
    }

    servers = list_logical_servers(session, max_tier=0)
    assert [s.name for s in servers] == ["FREE#1"]
    assert servers[0].score == 2.0


def test_pick_least_loaded_server():
    from proton_mikrotik_wg.wg_credentials import pick_least_loaded_server

    servers = [
        ProtonLogicalServer("UK#1", "1.1.1.1", "a==", load=40, score=3.0),
        ProtonLogicalServer("UK#2", "2.2.2.2", "b==", load=8, score=0.5),
        ProtonLogicalServer("UK#3", "3.3.3.3", "c==", load=1, score=2.0),
    ]
    # Prefer Proton Score over raw Load (UK#2 has best score).
    assert pick_least_loaded_server(servers).name == "UK#2"


def test_pick_least_loaded_server_requires_servers():
    import pytest
    from proton_mikrotik_wg.wg_credentials import pick_least_loaded_server

    with pytest.raises(ValueError, match="no Proton servers"):
        pick_least_loaded_server([])


def test_fetch_vpn_max_tier_returns_none_when_vpn_call_fails():
    from proton_mikrotik_wg.wg_credentials import fetch_vpn_max_tier

    session = MagicMock()
    session.api_request.side_effect = RuntimeError("no scope")
    assert fetch_vpn_max_tier(session) is None


def test_list_persistent_certificates_pages_results():
    from proton_mikrotik_wg.wg_credentials import list_persistent_certificates

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "a", "DeviceName": "ha-wg-proton-1"},
            ]
            + [{"SerialNumber": str(i), "DeviceName": f"x-{i}"} for i in range(49)],
        },
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "b", "DeviceName": "ha-wg-proton-2"},
            ],
        },
    ]
    certs = list_persistent_certificates(session)
    assert len(certs) == 51
    assert certs[-1]["SerialNumber"] == "b"
    assert "Mode=persistent" in session.api_request.call_args_list[0].args[0]


def test_cleanup_previous_ha_certificates_deletes_old_prefix_matches():
    from proton_mikrotik_wg.wg_credentials import cleanup_previous_ha_certificates

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "keep", "DeviceName": "ha-wg-proton-20260805-120000"},
                {"SerialNumber": "old1", "DeviceName": "ha-wg-proton-20260801-010101"},
                {"SerialNumber": "other", "DeviceName": "phone-config"},
                {"SerialNumber": "bare", "DeviceName": "ha-wg-proton"},
            ],
        },
        {"Code": 1000},  # delete old1
        {"Code": 1000},  # delete bare
    ]
    deleted, failed = cleanup_previous_ha_certificates(
        session, keep_serial="keep"
    )
    assert deleted == ["old1", "bare"]
    assert failed == []
    delete_calls = [
        c
        for c in session.api_request.call_args_list
        if c.kwargs.get("method") == "delete"
    ]
    assert len(delete_calls) == 2
    assert delete_calls[0].args[1] == {"SerialNumber": "old1"}


def test_cleanup_previous_ha_certificates_records_delete_failures():
    from proton_mikrotik_wg.wg_credentials import cleanup_previous_ha_certificates

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "keep", "DeviceName": "ha-wg-proton-new"},
                {"SerialNumber": "old1", "DeviceName": "ha-wg-proton-old"},
            ],
        },
        RuntimeError("insufficient scope"),
    ]
    deleted, failed = cleanup_previous_ha_certificates(
        session, keep_serial="keep"
    )
    assert deleted == []
    assert failed == ["old1: insufficient scope"]


def test_provision_wireguard_credential_cleans_up_previous_ha_certs():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {"Code": 1000, "VPN": {"MaxTier": 2}},
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.8,
                    "Servers": [
                        {"EntryIP": "1.2.3.4", "X25519PublicKey": "server-wg-pk=="}
                    ],
                }
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-new",
            "DeviceName": "ha-wg-proton-20260805-120000",
            "ExpirationTime": 1_800_000_000,
        },
        {
            "Code": 1000,
            "Certificates": [
                {
                    "SerialNumber": "sn-new",
                    "DeviceName": "ha-wg-proton-20260805-120000",
                },
                {
                    "SerialNumber": "sn-old",
                    "DeviceName": "ha-wg-proton-20260101-000000",
                },
            ],
        },
        {"Code": 1000},  # delete sn-old
    ]

    cred = provision_wireguard_credential(
        session, device_name="ha-wg-proton-20260805-120000"
    )
    assert cred.serial_number == "sn-new"
    delete_calls = [
        c
        for c in session.api_request.call_args_list
        if c.kwargs.get("method") == "delete"
    ]
    assert len(delete_calls) == 1
    assert delete_calls[0].args[1] == {"SerialNumber": "sn-old"}


def test_provision_wireguard_credential_continues_when_cleanup_fails():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "SerialNumber": "sn-new",
            "DeviceName": "ha-wg-proton-new",
            "ExpirationTime": 1_800_000_000,
        },
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "sn-new", "DeviceName": "ha-wg-proton-new"},
                {"SerialNumber": "sn-old", "DeviceName": "ha-wg-proton-old"},
            ],
        },
        RuntimeError("insufficient scope"),
    ]
    server = ProtonLogicalServer(
        name="UK#1",
        entry_ip="1.2.3.4",
        x25519_public_key="pk==",
    )

    cred = provision_wireguard_credential(
        session, device_name="ha-wg-proton-new", server=server
    )
    assert cred.serial_number == "sn-new"


def test_fetch_vpn_max_tier_returns_none_when_max_tiers_missing():
    from proton_mikrotik_wg.wg_credentials import fetch_vpn_max_tier

    session = MagicMock()
    session.api_request.return_value = {"Code": 1000, "VPN": {}}
    assert fetch_vpn_max_tier(session) is None


def test_provision_wireguard_credential_generates_keys_and_registers():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "VPN": {"MaxTier": 2},
        },
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.8,
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
        {"Code": 1000, "Certificates": []},
    ]

    cred = provision_wireguard_credential(session, device_name="ha-wg-proton")
    assert cred.serial_number == "sn-9"
    assert cred.endpoint_host == "1.2.3.4"
    assert cred.dns is None
    assert len(cred.client_private_key) == 44
    assert session.api_request.call_count == 4
    assert session.api_request.call_args_list[0].args == ("/vpn",)
    assert session.api_request.call_args_list[0].kwargs == {"method": "get"}
    assert session.api_request.call_args_list[1].args == ("/vpn/logicals",)
    assert session.api_request.call_args_list[1].kwargs == {"method": "get"}


def test_provision_wireguard_credential_uses_account_max_tier():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {"Code": 1000, "VPN": {"MaxTier": 0}},
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "PLUS#1",
                    "Status": 1,
                    "Load": 1,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.1,
                    "Servers": [
                        {"EntryIP": "9.9.9.9", "X25519PublicKey": "plus=="}
                    ],
                },
                {
                    "Name": "FREE#1",
                    "Status": 1,
                    "Load": 90,
                    "Features": 0,
                    "Tier": 0,
                    "Score": 5.0,
                    "Servers": [
                        {"EntryIP": "1.2.3.4", "X25519PublicKey": "free=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-free",
            "DeviceName": "ha-wg-proton",
            "ExpirationTime": 1_800_000_000,
        },
        {"Code": 1000, "Certificates": []},
    ]

    cred = provision_wireguard_credential(session, device_name="ha-wg-proton")
    assert cred.endpoint_host == "1.2.3.4"
    assert cred.server_public_key == "free=="


def test_provision_wireguard_credential_uses_explicit_server():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_credential

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "SerialNumber": "sn-explicit",
            "DeviceName": "ha-wg-proton",
            "ExpirationTime": 1_800_000_000,
        },
        {"Code": 1000, "Certificates": []},
    ]
    server = ProtonLogicalServer(
        name="UK#9",
        entry_ip="7.7.7.7",
        x25519_public_key="explicit==",
        score=0.1,
        tier=2,
    )

    cred = provision_wireguard_credential(
        session, device_name="ha-wg-proton", server=server
    )
    assert cred.endpoint_host == "7.7.7.7"
    assert cred.server_public_key == "explicit=="
    assert session.api_request.call_count == 2
    assert session.api_request.call_args_list[0].args[0] == "/vpn/v1/certificate"
