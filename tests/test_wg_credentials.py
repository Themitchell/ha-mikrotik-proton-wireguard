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
        # Raw Ed25519 public key (32 bytes) base64 — Proton account UI format.
        api_public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
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
            "ClientPublicKey": keys.api_public_key,
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


def test_generate_wireguard_keypair_returns_wg_and_api_keys():
    import base64

    from proton_mikrotik_wg.wg_credentials import generate_wireguard_keypair

    keys = generate_wireguard_keypair()
    assert isinstance(keys, WireGuardKeyPair)
    assert keys.private_key != keys.public_key
    # Standard WireGuard keys are 32 raw bytes → 44 chars base64 with padding.
    assert len(keys.private_key) == 44
    assert len(keys.public_key) == 44
    # Proton account UI posts raw Ed25519 public (32 bytes), not X25519 or PEM.
    assert len(keys.api_public_key) == 44
    assert len(base64.b64decode(keys.api_public_key)) == 32
    assert not keys.api_public_key.startswith("-----")
    assert keys.api_public_key != keys.public_key


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
    assert servers[0].exit_country == ""
    session.api_request.assert_called_once_with("/vpn/logicals", method="get")


def test_list_logical_servers_parses_and_filters_exit_country():
    from proton_mikrotik_wg.wg_credentials import list_logical_servers

    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "UK#1",
                "Status": 1,
                "Load": 10,
                "Features": 0,
                "Tier": 0,
                "Score": 1.0,
                "ExitCountry": "GB",
                "Servers": [
                    {"EntryIP": "1.1.1.1", "X25519PublicKey": "gb=="}
                ],
            },
            {
                "Name": "NL#1",
                "Status": 1,
                "Load": 10,
                "Features": 0,
                "Tier": 0,
                "Score": 0.5,
                "ExitCountry": "NL",
                "Servers": [
                    {"EntryIP": "2.2.2.2", "X25519PublicKey": "nl=="}
                ],
            },
        ],
    }
    servers = list_logical_servers(session, exit_country="gb")
    assert [s.name for s in servers] == ["UK#1"]
    assert servers[0].exit_country == "GB"


def test_list_exit_countries_returns_sorted_unique_codes():
    from proton_mikrotik_wg.wg_credentials import list_exit_countries

    session = MagicMock()
    session.api_request.return_value = {
        "Code": 1000,
        "LogicalServers": [
            {
                "Name": "NL#1",
                "Status": 1,
                "Load": 1,
                "Features": 0,
                "Tier": 0,
                "Score": 1.0,
                "ExitCountry": "NL",
                "Servers": [
                    {"EntryIP": "2.2.2.2", "X25519PublicKey": "nl=="}
                ],
            },
            {
                "Name": "UK#1",
                "Status": 1,
                "Load": 1,
                "Features": 0,
                "Tier": 0,
                "Score": 1.0,
                "ExitCountry": "GB",
                "Servers": [
                    {"EntryIP": "1.1.1.1", "X25519PublicKey": "gb=="}
                ],
            },
            {
                "Name": "UK#2",
                "Status": 1,
                "Load": 1,
                "Features": 0,
                "Tier": 0,
                "Score": 2.0,
                "ExitCountry": "GB",
                "Servers": [
                    {"EntryIP": "1.1.1.2", "X25519PublicKey": "gb2=="}
                ],
            },
        ],
    }
    assert list_exit_countries(session) == ["GB", "NL"]


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


def test_pick_best_servers_returns_n_distinct_by_score():
    from proton_mikrotik_wg.wg_credentials import pick_best_servers

    servers = [
        ProtonLogicalServer("UK#1", "1.1.1.1", "a==", score=3.0),
        ProtonLogicalServer("UK#2", "2.2.2.2", "b==", score=0.5),
        ProtonLogicalServer("CH#1", "1.1.1.1", "c==", score=0.1),  # same entry IP as UK#1
        ProtonLogicalServer("UK#3", "3.3.3.3", "d==", score=1.0),
        ProtonLogicalServer("UK#2-alt", "2.2.2.2", "e==", score=0.2),  # same IP as UK#2
    ]
    # Best scores with unique name+IP: CH#1 skipped? CH#1 has best score 0.1, then
    # UK#2-alt (0.2) skipped (IP taken by… wait CH#1 uses 1.1.1.1 first).
    # Order: CH#1 (0.1), UK#2-alt (0.2, IP 2.2.2.2), UK#2 (0.5, IP taken), UK#3 (1.0), UK#1 (3.0, IP taken).
    picked = pick_best_servers(servers, count=3)
    assert [s.name for s in picked] == ["CH#1", "UK#2-alt", "UK#3"]
    assert [s.entry_ip for s in picked] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_pick_best_servers_raises_when_not_enough_distinct():
    import pytest
    from proton_mikrotik_wg.wg_credentials import pick_best_servers

    servers = [
        ProtonLogicalServer("UK#1", "1.1.1.1", "a==", score=1.0),
        ProtonLogicalServer("UK#2", "1.1.1.1", "b==", score=2.0),
    ]
    with pytest.raises(ValueError, match="not enough distinct"):
        pick_best_servers(servers, count=2)


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


def test_cleanup_previous_ha_certificates_keeps_multiple_serials():
    from proton_mikrotik_wg.wg_credentials import cleanup_previous_ha_certificates

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "keep1", "DeviceName": "ha-wg-proton-1-a"},
                {"SerialNumber": "keep2", "DeviceName": "ha-wg-proton-2-a"},
                {"SerialNumber": "old", "DeviceName": "ha-wg-proton-old"},
            ],
        },
        {"Code": 1000},
    ]
    deleted, failed = cleanup_previous_ha_certificates(
        session, keep_serials={"keep1", "keep2"}
    )
    assert deleted == ["old"]
    assert failed == []


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


def test_provision_wireguard_slots_creates_distinct_servers():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_slots

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
                    "ExitCountry": "GB",
                    "Servers": [
                        {"EntryIP": "1.1.1.1", "X25519PublicKey": "a=="}
                    ],
                },
                {
                    "Name": "UK#2",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.2,
                    "ExitCountry": "GB",
                    "Servers": [
                        {"EntryIP": "2.2.2.2", "X25519PublicKey": "b=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-1",
            "DeviceName": "ha-wg-proton-1-x",
            "ExpirationTime": 100,
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-2",
            "DeviceName": "ha-wg-proton-2-x",
            "ExpirationTime": 200,
        },
        {"Code": 1000, "Certificates": []},
    ]

    slots = provision_wireguard_slots(session, count=2)
    assert list(slots.keys()) == [1, 2]
    assert slots[1].endpoint_host == "2.2.2.2"  # best score first
    assert slots[2].endpoint_host == "1.1.1.1"
    assert slots[1].device_name.startswith("ha-wg-proton-1-")
    assert slots[2].device_name.startswith("ha-wg-proton-2-")


def test_provision_wireguard_slots_treats_any_as_no_filter():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_slots

    session = MagicMock()
    session.api_request.side_effect = [
        {"Code": 1000, "VPN": {"MaxTier": 2}},
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "NL#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.1,
                    "ExitCountry": "NL",
                    "Servers": [
                        {"EntryIP": "2.2.2.2", "X25519PublicKey": "nl=="}
                    ],
                },
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.2,
                    "ExitCountry": "GB",
                    "Servers": [
                        {"EntryIP": "1.1.1.1", "X25519PublicKey": "gb=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-nl",
            "DeviceName": "ha-wg-proton-1-x",
            "ExpirationTime": 100,
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-gb",
            "DeviceName": "ha-wg-proton-2-x",
            "ExpirationTime": 200,
        },
        {"Code": 1000, "Certificates": []},
    ]
    slots = provision_wireguard_slots(session, count=2, exit_country="any")
    assert slots[1].endpoint_host == "2.2.2.2"
    assert slots[2].endpoint_host == "1.1.1.1"


def test_provision_wireguard_slots_filters_exit_country():
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_slots

    session = MagicMock()
    session.api_request.side_effect = [
        {"Code": 1000, "VPN": {"MaxTier": 2}},
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "NL#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.1,
                    "ExitCountry": "NL",
                    "Servers": [
                        {"EntryIP": "2.2.2.2", "X25519PublicKey": "nl=="}
                    ],
                },
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 5,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.2,
                    "ExitCountry": "GB",
                    "Servers": [
                        {"EntryIP": "1.1.1.1", "X25519PublicKey": "gb=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-gb",
            "DeviceName": "ha-wg-proton-1-x",
            "ExpirationTime": 100,
        },
        {"Code": 1000, "Certificates": []},
    ]
    slots = provision_wireguard_slots(session, count=1, exit_country="GB")
    assert slots[1].endpoint_host == "1.1.1.1"


def test_provision_wireguard_slots_one_slot_keeps_others():
    from proton_mikrotik_wg.wg_credentials import (
        WireGuardCredential,
        provision_wireguard_slots,
    )

    existing = {
        1: WireGuardCredential(
            device_name="ha-wg-proton-1-old",
            serial_number="keep-1",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="1.1.1.1",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
        ),
        2: WireGuardCredential(
            device_name="ha-wg-proton-2-old",
            serial_number="old-2",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="2.2.2.2",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
        ),
    }
    session = MagicMock()
    session.api_request.side_effect = [
        {"Code": 1000, "VPN": {"MaxTier": 2}},
        {
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "UK#3",
                    "Status": 1,
                    "Load": 1,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.1,
                    "Servers": [
                        {"EntryIP": "3.3.3.3", "X25519PublicKey": "c=="}
                    ],
                },
                {
                    "Name": "UK#1",
                    "Status": 1,
                    "Load": 1,
                    "Features": 0,
                    "Tier": 2,
                    "Score": 0.5,
                    "Servers": [
                        {"EntryIP": "1.1.1.1", "X25519PublicKey": "a=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "new-2",
            "DeviceName": "ha-wg-proton-2-new",
            "ExpirationTime": 200,
        },
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "keep-1", "DeviceName": "ha-wg-proton-1-old"},
                {"SerialNumber": "new-2", "DeviceName": "ha-wg-proton-2-new"},
                {"SerialNumber": "old-2", "DeviceName": "ha-wg-proton-2-old"},
            ],
        },
        {"Code": 1000},  # delete old-2
    ]
    slots = provision_wireguard_slots(session, count=2, existing=existing, slot=2)
    assert slots[1].serial_number == "keep-1"
    assert slots[2].serial_number == "new-2"
    assert slots[2].endpoint_host == "3.3.3.3"


def test_provision_wireguard_slots_rejects_bad_count_or_slot():
    import pytest
    from proton_mikrotik_wg.wg_credentials import provision_wireguard_slots

    session = MagicMock()
    with pytest.raises(ValueError, match="at least 1"):
        provision_wireguard_slots(session, count=0)
    with pytest.raises(ValueError, match="between 1 and"):
        provision_wireguard_slots(session, count=2, slot=3)


def test_pick_best_servers_rejects_non_positive_count():
    import pytest
    from proton_mikrotik_wg.wg_credentials import pick_best_servers

    with pytest.raises(ValueError, match="at least 1"):
        pick_best_servers(
            [ProtonLogicalServer("UK#1", "1.1.1.1", "a==")], count=0
        )


def test_provision_wireguard_slots_logs_cleanup_failures(caplog):
    import logging

    from proton_mikrotik_wg.wg_credentials import provision_wireguard_slots

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
                    "Score": 0.1,
                    "Servers": [
                        {"EntryIP": "1.1.1.1", "X25519PublicKey": "a=="}
                    ],
                },
            ],
        },
        {
            "Code": 1000,
            "SerialNumber": "sn-1",
            "DeviceName": "ha-wg-proton-1-x",
            "ExpirationTime": 100,
        },
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "sn-1", "DeviceName": "ha-wg-proton-1-x"},
                {"SerialNumber": "old", "DeviceName": "ha-wg-proton-old"},
            ],
        },
        RuntimeError("insufficient scope"),
    ]
    with caplog.at_level(logging.WARNING):
        provision_wireguard_slots(session, count=1)
    assert "Could not delete" in caplog.text


def test_cleanup_skips_empty_serial_and_non_ha_names():
    from proton_mikrotik_wg.wg_credentials import cleanup_previous_ha_certificates

    session = MagicMock()
    session.api_request.side_effect = [
        {
            "Code": 1000,
            "Certificates": [
                {"SerialNumber": "", "DeviceName": "ha-wg-proton-x"},
                {"SerialNumber": "phone", "DeviceName": "my-phone"},
                {"SerialNumber": "keep", "DeviceName": "ha-wg-proton-keep"},
            ],
        },
    ]
    deleted, failed = cleanup_previous_ha_certificates(
        session, keep_serial="keep"
    )
    assert deleted == []
    assert failed == []


def test_pick_best_servers_requires_servers():
    import pytest
    from proton_mikrotik_wg.wg_credentials import pick_best_servers

    with pytest.raises(ValueError, match="no Proton servers"):
        pick_best_servers([], count=1)


def test_slot_device_name_uses_provided_stamp():
    from proton_mikrotik_wg.wg_credentials import _slot_device_name

    assert _slot_device_name(3, stamp="20260101-020304") == "ha-wg-proton-3-20260101-020304"
