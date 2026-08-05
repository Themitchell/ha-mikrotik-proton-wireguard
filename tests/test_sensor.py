"""Tests for per-slot WireGuard diagnostic sensors."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from proton_mikrotik_wg.const import (
    CONF_TUNNEL_COUNT,
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_DEVICE_NAME,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_EXPIRATION_TIME,
    CONF_WG_PROVISIONED_AT,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_SERVER_NAME,
    CONF_WG_SERVER_PUBLIC_KEY,
    CONF_WG_SLOTS,
    DOMAIN,
)
from proton_mikrotik_wg.sensor import ProtonWgSlotSensor, async_setup_entry
from proton_mikrotik_wg.session_manager import ProtonSessionManager


def _slot_row(
    slot: int,
    *,
    server_name: str = "",
    provisioned_at: int = 0,
    host: str = "1.1.1.1",
) -> dict:
    row = {
        "slot": slot,
        CONF_WG_DEVICE_NAME: f"ha-wg-proton-{slot}-x",
        CONF_WG_SERIAL_NUMBER: f"sn-{slot}",
        CONF_WG_CLIENT_PRIVATE_KEY: "sk==",
        CONF_WG_CLIENT_PUBLIC_KEY: "pk==",
        CONF_WG_SERVER_PUBLIC_KEY: "spk==",
        CONF_WG_ENDPOINT_HOST: host,
        CONF_WG_ENDPOINT_PORT: 51820,
        CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
        CONF_WG_EXPIRATION_TIME: 100,
    }
    if server_name:
        row[CONF_WG_SERVER_NAME] = server_name
    if provisioned_at:
        row[CONF_WG_PROVISIONED_AT] = provisioned_at
    return row


def _entry(**overrides):
    data = {
        "username": "user@proton.me",
        "uid": "uid-1",
        "access_token": "a",
        "refresh_token": "r",
        "scope": ["full"],
        CONF_WG_SLOTS: [
            _slot_row(1, server_name="UK#1", provisioned_at=1_700_000_000, host="1.1.1.1"),
            _slot_row(2, server_name="NL#9", provisioned_at=1_700_000_100, host="2.2.2.2"),
        ],
    }
    options = {CONF_TUNNEL_COUNT: 2}
    base = dict(
        entry_id="abc",
        data=data,
        options=options,
        _unload=[],
        _listeners=[],
    )
    base.update(overrides)
    entry = SimpleNamespace(**base)

    def add_update_listener(listener):
        entry._listeners.append(listener)

        def _unsub():
            entry._listeners = [item for item in entry._listeners if item is not listener]

        return _unsub

    def async_on_unload(unsub):
        entry._unload.append(unsub)

    entry.add_update_listener = add_update_listener
    entry.async_on_unload = async_on_unload
    return entry


@pytest.fixture
def hass():
    from conftest import FakeHass

    fake = FakeHass()
    fake.data = {}
    return fake


@pytest.mark.asyncio
async def test_sensor_state_and_attributes(hass):
    entry = _entry()
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    sensor = ProtonWgSlotSensor(manager, 1)
    assert sensor.name == "Proton WG tunnel 1"
    assert sensor.unique_id == "abc_wg_slot_1"
    assert sensor.entity_category == "diagnostic"
    assert sensor.available is True
    assert sensor.native_value == "UK#1"
    attrs = sensor.extra_state_attributes
    assert attrs["slot"] == 1
    assert attrs["device_name"] == "ha-wg-proton-1-x"
    assert attrs["endpoint_host"] == "1.1.1.1"
    assert attrs["endpoint_port"] == 51820
    assert attrs["serial_number"] == "sn-1"
    assert attrs["provisioned_at"] == "2023-11-14T22:13:20+00:00"


@pytest.mark.asyncio
async def test_sensor_unknown_without_server_name(hass):
    entry = _entry()
    entry.data[CONF_WG_SLOTS] = [_slot_row(1)]
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    sensor = ProtonWgSlotSensor(manager, 1)
    assert sensor.native_value == "unknown"
    assert "provisioned_at" not in sensor.extra_state_attributes


@pytest.mark.asyncio
async def test_sensor_unavailable_above_tunnel_count(hass):
    entry = _entry()
    entry.options[CONF_TUNNEL_COUNT] = 1
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    sensor = ProtonWgSlotSensor(manager, 2)
    assert sensor.available is False
    assert sensor.native_value == "unknown"


@pytest.mark.asyncio
async def test_async_setup_entry_creates_sensors_and_update_listener(hass):
    entry = _entry()
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    hass.data[DOMAIN] = {entry.entry_id: manager}
    added: list = []

    def add_entities(entities):
        added.extend(entities)

    await async_setup_entry(hass, entry, add_entities)
    assert [s.slot for s in added] == [1, 2]
    assert entry._listeners
    assert entry._unload

    # Simulate renew adding slot 3 under higher tunnel count.
    entry.options[CONF_TUNNEL_COUNT] = 3
    entry.data[CONF_WG_SLOTS].append(
        _slot_row(3, server_name="DE#3", provisioned_at=1_700_000_200)
    )
    await entry._listeners[0](hass, entry)
    assert [s.slot for s in added] == [1, 2, 3]
    assert added[0]._writes >= 1
    writes_before = added[0]._writes
    # Second update with no new slots still refreshes state.
    await entry._listeners[0](hass, entry)
    assert [s.slot for s in added] == [1, 2, 3]
    assert added[0]._writes > writes_before


@pytest.mark.asyncio
async def test_async_setup_entry_awaits_async_add_entities(hass):
    entry = _entry()
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    hass.data[DOMAIN] = {entry.entry_id: manager}
    added: list = []

    async def add_entities(entities):
        added.extend(entities)

    await async_setup_entry(hass, entry, add_entities)
    assert [s.slot for s in added] == [1, 2]


@pytest.mark.asyncio
async def test_sensor_attributes_when_credential_missing(hass):
    entry = _entry()
    entry.data[CONF_WG_SLOTS] = []
    manager = ProtonSessionManager(hass, entry, client=MagicMock())
    sensor = ProtonWgSlotSensor(manager, 1)
    assert sensor.extra_state_attributes == {"slot": 1}
