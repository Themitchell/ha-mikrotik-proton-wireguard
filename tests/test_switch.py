"""Tests for VPN egress switch entity."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from proton_mikrotik_wg.const import DOMAIN
from proton_mikrotik_wg.switch import ProtonVpnEgressSwitch, async_setup_entry


@pytest.mark.asyncio
async def test_async_setup_entry_adds_switch():
    hass = MagicMock()
    manager = MagicMock()
    manager.entry = SimpleNamespace(entry_id="abc", options={})
    hass.data = {DOMAIN: {"abc": manager}}
    added = []

    await async_setup_entry(
        hass, SimpleNamespace(entry_id="abc"), lambda entities: added.extend(entities)
    )
    assert len(added) == 1
    assert isinstance(added[0], ProtonVpnEgressSwitch)


@pytest.mark.asyncio
async def test_switch_turn_on_and_off():
    manager = MagicMock()
    manager.entry = SimpleNamespace(entry_id="abc", options={"egress_enabled": False})
    manager.async_set_egress = AsyncMock()
    switch = ProtonVpnEgressSwitch(manager)

    await switch.async_turn_on()
    manager.async_set_egress.assert_awaited_with(True)
    assert switch.is_on is True

    await switch.async_turn_off()
    manager.async_set_egress.assert_awaited_with(False)
    assert switch.is_on is False


@pytest.mark.asyncio
async def test_switch_added_reads_router_state():
    manager = MagicMock()
    manager.entry = SimpleNamespace(entry_id="abc", options={})
    manager.async_get_egress_enabled = AsyncMock(return_value=True)
    switch = ProtonVpnEgressSwitch(manager)
    await switch.async_added_to_hass()
    assert switch.is_on is True


@pytest.mark.asyncio
async def test_switch_added_without_mikrotik_stays_off():
    manager = MagicMock()
    manager.entry = SimpleNamespace(entry_id="abc", options={})
    manager.async_get_egress_enabled = AsyncMock(
        side_effect=ValueError("MikroTik is not configured")
    )
    switch = ProtonVpnEgressSwitch(manager)
    await switch.async_added_to_hass()
    assert switch.is_on is False
