"""Setup/unload entry coverage with Home Assistant stubs."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from proton_mikrotik_wg import async_setup_entry, async_unload_entry
from proton_mikrotik_wg.const import DOMAIN


@pytest.mark.asyncio
async def test_async_setup_entry_stores_data():
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    entry = SimpleNamespace(entry_id="abc", data={"username": "u"})

    assert await async_setup_entry(hass, entry) is True
    assert hass.data[DOMAIN]["abc"] == {"username": "u"}
    hass.config_entries.async_forward_entry_setups.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_unload_entry_removes_data_when_ok():
    hass = MagicMock()
    hass.data = {DOMAIN: {"abc": {"username": "u"}, "other": {}}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    entry = SimpleNamespace(entry_id="abc")

    assert await async_unload_entry(hass, entry) is True
    assert "abc" not in hass.data[DOMAIN]
    assert "other" in hass.data[DOMAIN]


@pytest.mark.asyncio
async def test_async_unload_entry_keeps_data_when_platforms_fail():
    hass = MagicMock()
    hass.data = {DOMAIN: {"abc": {"username": "u"}}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    entry = SimpleNamespace(entry_id="abc")

    assert await async_unload_entry(hass, entry) is False
    assert "abc" in hass.data[DOMAIN]
