"""Multi-slot WireGuard credential storage for config entry data."""

from __future__ import annotations

from typing import Any, Mapping

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
    CONF_WG_SLOTS,
    DEFAULT_WG_INTERFACE,
    MAX_TUNNEL_COUNT,
    MIN_TUNNEL_COUNT,
)
from .wg_credentials import WireGuardCredential

_SLOT_FIELDS = (
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


def wireguard_interface_name(slot: int) -> str:
    """Return MikroTik WireGuard interface name for a 1-based slot."""
    if slot < MIN_TUNNEL_COUNT or slot > MAX_TUNNEL_COUNT:
        raise ValueError(
            f"slot must be between {MIN_TUNNEL_COUNT} and {MAX_TUNNEL_COUNT}, got {slot}"
        )
    return f"{DEFAULT_WG_INTERFACE}-{slot}"


def _credential_from_mapping(row: Mapping[str, Any]) -> WireGuardCredential:
    missing = [key for key in _SLOT_FIELDS if key not in row]
    if missing:
        raise ValueError(
            "WireGuard slot is incomplete "
            f"(missing {', '.join(missing)})"
        )
    return WireGuardCredential(
        device_name=str(row[CONF_WG_DEVICE_NAME]),
        serial_number=str(row[CONF_WG_SERIAL_NUMBER]),
        client_private_key=str(row[CONF_WG_CLIENT_PRIVATE_KEY]),
        client_public_key=str(row[CONF_WG_CLIENT_PUBLIC_KEY]),
        server_public_key=str(row[CONF_WG_SERVER_PUBLIC_KEY]),
        endpoint_host=str(row[CONF_WG_ENDPOINT_HOST]),
        endpoint_port=int(row[CONF_WG_ENDPOINT_PORT]),
        client_address=str(row[CONF_WG_CLIENT_ADDRESS]),
        expiration_time=int(row[CONF_WG_EXPIRATION_TIME]),
        dns=None,
    )


def _slot_dict(slot: int, cred: WireGuardCredential) -> dict[str, Any]:
    return {
        "slot": slot,
        CONF_WG_DEVICE_NAME: cred.device_name,
        CONF_WG_SERIAL_NUMBER: cred.serial_number,
        CONF_WG_CLIENT_PRIVATE_KEY: cred.client_private_key,
        CONF_WG_CLIENT_PUBLIC_KEY: cred.client_public_key,
        CONF_WG_SERVER_PUBLIC_KEY: cred.server_public_key,
        CONF_WG_ENDPOINT_HOST: cred.endpoint_host,
        CONF_WG_ENDPOINT_PORT: cred.endpoint_port,
        CONF_WG_CLIENT_ADDRESS: cred.client_address,
        CONF_WG_EXPIRATION_TIME: cred.expiration_time,
    }


def slots_from_entry_data(
    data: Mapping[str, Any],
) -> dict[int, WireGuardCredential]:
    """Load slot credentials from entry data, migrating legacy flat keys."""
    raw_slots = data.get(CONF_WG_SLOTS)
    if isinstance(raw_slots, list) and raw_slots:
        result: dict[int, WireGuardCredential] = {}
        for row in raw_slots:
            if not isinstance(row, Mapping):
                continue
            slot = int(row["slot"])
            result[slot] = _credential_from_mapping(row)
        return dict(sorted(result.items()))

    if all(key in data for key in _SLOT_FIELDS):
        return {1: _credential_from_mapping(data)}
    return {}


def entry_data_from_slots(
    slots: Mapping[int, WireGuardCredential],
) -> dict[str, Any]:
    """Serialize slot credentials for config entry data."""
    return {
        CONF_WG_SLOTS: [
            _slot_dict(slot, cred) for slot, cred in sorted(slots.items())
        ]
    }
