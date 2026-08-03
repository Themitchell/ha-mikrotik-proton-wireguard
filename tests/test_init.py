"""Setup/unload entry coverage with Home Assistant stubs."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proton_mikrotik_wg import async_setup_entry, async_unload_entry
from proton_mikrotik_wg.const import DOMAIN
from proton_mikrotik_wg.proton_auth import ProtonSessionData


def _session(**overrides) -> ProtonSessionData:
    base = dict(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-new",
        refresh_token="refresh-new",
        scope=("full", "self"),
    )
    base.update(overrides)
    return ProtonSessionData(**base)


@pytest.mark.asyncio
async def test_async_setup_entry_creates_session_manager():
    hass = MagicMock()
    hass.data = {}

    async def run_job(fn, *args):
        return fn(*args)

    hass.async_add_executor_job = run_job
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_update_entry = MagicMock()
    hass.services.has_service = MagicMock(return_value=False)
    hass.services.async_register = MagicMock()
    entry = SimpleNamespace(
        entry_id="abc",
        data={
            "username": "user@proton.me",
            "uid": "uid-1",
            "access_token": "access-old",
            "refresh_token": "refresh-old",
            "scope": ["full"],
        },
    )

    client = MagicMock()
    client.refresh.return_value = _session()
    with patch(
        "proton_mikrotik_wg.session_manager.ProtonAuthClient",
        return_value=client,
    ):
        assert await async_setup_entry(hass, entry) is True

    manager = hass.data[DOMAIN]["abc"]
    assert manager.client is client
    hass.config_entries.async_update_entry.assert_called()
    hass.config_entries.async_forward_entry_setups.assert_awaited_once()
    hass.services.async_register.assert_called()


@pytest.mark.asyncio
async def test_async_unload_entry_stops_manager():
    hass = MagicMock()
    manager = MagicMock()
    manager.async_unload = AsyncMock()
    hass.data = {DOMAIN: {"abc": manager}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.services.has_service = MagicMock(return_value=True)
    hass.services.async_remove = MagicMock()
    entry = SimpleNamespace(entry_id="abc")

    assert await async_unload_entry(hass, entry) is True
    manager.async_unload.assert_awaited_once()
    assert "abc" not in hass.data[DOMAIN]
    hass.services.async_remove.assert_called()


@pytest.mark.asyncio
async def test_async_unload_entry_keeps_data_when_platforms_fail():
    hass = MagicMock()
    manager = MagicMock()
    manager.async_unload = AsyncMock()
    hass.data = {DOMAIN: {"abc": manager}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)
    entry = SimpleNamespace(entry_id="abc")

    assert await async_unload_entry(hass, entry) is False
    assert "abc" in hass.data[DOMAIN]


@pytest.mark.asyncio
async def test_async_unload_entry_without_manager():
    hass = MagicMock()
    hass.data = {DOMAIN: {}}
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    entry = SimpleNamespace(entry_id="missing")
    assert await async_unload_entry(hass, entry) is True
