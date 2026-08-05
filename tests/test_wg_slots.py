"""Tests for multi-slot WireGuard credential storage and legacy migration."""

from __future__ import annotations

import pytest

from proton_mikrotik_wg.const import (
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_DEVICE_NAME,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_EXPIRATION_TIME,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_SERVER_PUBLIC_KEY,
    CONF_WG_SLOTS,
)
from proton_mikrotik_wg.wg_credentials import WireGuardCredential
from proton_mikrotik_wg.wg_slots import (
    entry_data_from_slots,
    slots_from_entry_data,
    wireguard_interface_name,
)


def _cred(*, serial: str = "sn-1", host: str = "1.2.3.4") -> WireGuardCredential:
    return WireGuardCredential(
        device_name="ha-wg-proton-1",
        serial_number=serial,
        client_private_key="client-sk==",
        client_public_key="client-pk==",
        server_public_key="server-pk==",
        endpoint_host=host,
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=1_700_000_000,
        dns=None,
    )


def test_slots_from_entry_data_reads_wg_slots_list():
    data = {
        CONF_WG_SLOTS: [
            {
                "slot": 1,
                CONF_WG_DEVICE_NAME: "ha-wg-proton-1",
                CONF_WG_SERIAL_NUMBER: "sn-1",
                CONF_WG_CLIENT_PRIVATE_KEY: "sk1==",
                CONF_WG_CLIENT_PUBLIC_KEY: "pk1==",
                CONF_WG_SERVER_PUBLIC_KEY: "spk1==",
                CONF_WG_ENDPOINT_HOST: "1.1.1.1",
                CONF_WG_ENDPOINT_PORT: 51820,
                CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
                CONF_WG_EXPIRATION_TIME: 100,
            },
            {
                "slot": 2,
                CONF_WG_DEVICE_NAME: "ha-wg-proton-2",
                CONF_WG_SERIAL_NUMBER: "sn-2",
                CONF_WG_CLIENT_PRIVATE_KEY: "sk2==",
                CONF_WG_CLIENT_PUBLIC_KEY: "pk2==",
                CONF_WG_SERVER_PUBLIC_KEY: "spk2==",
                CONF_WG_ENDPOINT_HOST: "2.2.2.2",
                CONF_WG_ENDPOINT_PORT: 51820,
                CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
                CONF_WG_EXPIRATION_TIME: 200,
            },
        ]
    }

    slots = slots_from_entry_data(data)
    assert list(slots.keys()) == [1, 2]
    assert slots[1].serial_number == "sn-1"
    assert slots[2].endpoint_host == "2.2.2.2"


def test_slots_from_entry_data_migrates_legacy_flat_keys_to_slot_1():
    data = {
        CONF_WG_DEVICE_NAME: "ha-wg-proton",
        CONF_WG_SERIAL_NUMBER: "sn-legacy",
        CONF_WG_CLIENT_PRIVATE_KEY: "client-sk==",
        CONF_WG_CLIENT_PUBLIC_KEY: "client-pk==",
        CONF_WG_SERVER_PUBLIC_KEY: "server-pk==",
        CONF_WG_ENDPOINT_HOST: "1.2.3.4",
        CONF_WG_ENDPOINT_PORT: 51820,
        CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
        CONF_WG_EXPIRATION_TIME: 1_700_000_000,
    }

    slots = slots_from_entry_data(data)
    assert list(slots.keys()) == [1]
    assert slots[1].serial_number == "sn-legacy"
    assert slots[1].device_name == "ha-wg-proton"


def test_slots_from_entry_data_prefers_wg_slots_over_legacy():
    data = {
        CONF_WG_SLOTS: [
            {
                "slot": 1,
                CONF_WG_DEVICE_NAME: "ha-wg-proton-1",
                CONF_WG_SERIAL_NUMBER: "sn-new",
                CONF_WG_CLIENT_PRIVATE_KEY: "sk==",
                CONF_WG_CLIENT_PUBLIC_KEY: "pk==",
                CONF_WG_SERVER_PUBLIC_KEY: "spk==",
                CONF_WG_ENDPOINT_HOST: "9.9.9.9",
                CONF_WG_ENDPOINT_PORT: 51820,
                CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
                CONF_WG_EXPIRATION_TIME: 1,
            }
        ],
        CONF_WG_SERIAL_NUMBER: "sn-legacy",
        CONF_WG_DEVICE_NAME: "ha-wg-proton",
        CONF_WG_CLIENT_PRIVATE_KEY: "old==",
        CONF_WG_CLIENT_PUBLIC_KEY: "old==",
        CONF_WG_SERVER_PUBLIC_KEY: "old==",
        CONF_WG_ENDPOINT_HOST: "1.2.3.4",
        CONF_WG_ENDPOINT_PORT: 51820,
        CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
        CONF_WG_EXPIRATION_TIME: 1,
    }

    slots = slots_from_entry_data(data)
    assert slots[1].serial_number == "sn-new"


def test_slots_from_entry_data_empty_when_unprovisioned():
    assert slots_from_entry_data({}) == {}


def test_entry_data_from_slots_round_trip():
    slots = {1: _cred(serial="sn-1", host="1.1.1.1"), 2: _cred(serial="sn-2", host="2.2.2.2")}
    slots[2] = WireGuardCredential(
        device_name="ha-wg-proton-2",
        serial_number="sn-2",
        client_private_key="sk2==",
        client_public_key="pk2==",
        server_public_key="spk2==",
        endpoint_host="2.2.2.2",
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=200,
    )
    payload = entry_data_from_slots(slots)
    assert CONF_WG_SLOTS in payload
    restored = slots_from_entry_data(payload)
    assert restored[1].serial_number == "sn-1"
    assert restored[2].serial_number == "sn-2"
    assert restored[2].device_name == "ha-wg-proton-2"


def test_slots_from_entry_data_skips_non_mapping_rows():
    data = {
        CONF_WG_SLOTS: [
            "bad",
            {
                "slot": 1,
                CONF_WG_DEVICE_NAME: "ha-wg-proton-1",
                CONF_WG_SERIAL_NUMBER: "sn-1",
                CONF_WG_CLIENT_PRIVATE_KEY: "sk==",
                CONF_WG_CLIENT_PUBLIC_KEY: "pk==",
                CONF_WG_SERVER_PUBLIC_KEY: "spk==",
                CONF_WG_ENDPOINT_HOST: "1.1.1.1",
                CONF_WG_ENDPOINT_PORT: 51820,
                CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
                CONF_WG_EXPIRATION_TIME: 100,
            },
        ]
    }
    slots = slots_from_entry_data(data)
    assert list(slots.keys()) == [1]


def test_credential_from_incomplete_slot_raises():
    data = {CONF_WG_SLOTS: [{"slot": 1, CONF_WG_DEVICE_NAME: "ha-only"}]}
    with pytest.raises(ValueError, match="incomplete"):
        slots_from_entry_data(data)


def test_wireguard_interface_name():
    assert wireguard_interface_name(1) == "wg-proton-1"
    assert wireguard_interface_name(8) == "wg-proton-8"
    with pytest.raises(ValueError):
        wireguard_interface_name(0)
    with pytest.raises(ValueError):
        wireguard_interface_name(21)
