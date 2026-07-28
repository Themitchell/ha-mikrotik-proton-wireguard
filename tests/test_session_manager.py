"""Tests for ProtonSessionManager."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ha_stubs import ConfigEntryAuthFailed
from proton_mikrotik_wg.const import CONF_ACCESS_TOKEN, CONF_REFRESH_TOKEN
from proton_mikrotik_wg.proton_auth import InvalidCredentials, ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager


def _session(**overrides) -> ProtonSessionData:
    base = dict(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-old",
        refresh_token="refresh-old",
        scope=("full", "self"),
    )
    base.update(overrides)
    return ProtonSessionData(**base)


@pytest.fixture
def hass():
    from conftest import FakeHass

    fake = FakeHass()
    fake.data = {}
    fake.config_entries = MagicMock()
    return fake


@pytest.fixture
def entry():
    return SimpleNamespace(
        entry_id="abc",
        data={
            "username": "user@proton.me",
            "uid": "uid-1",
            "access_token": "access-old",
            "refresh_token": "refresh-old",
            "scope": ["full", "self"],
        },
    )


@pytest.mark.asyncio
async def test_async_refresh_persists_new_tokens(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    manager = ProtonSessionManager(hass, entry, client=client)

    updated = await manager.async_refresh()
    assert updated.access_token == "access-new"
    hass.config_entries.async_update_entry.assert_called_once()
    _, kwargs = hass.config_entries.async_update_entry.call_args
    assert kwargs["data"][CONF_ACCESS_TOKEN] == "access-new"
    assert kwargs["data"][CONF_REFRESH_TOKEN] == "refresh-new"


@pytest.mark.asyncio
async def test_async_refresh_raises_auth_failed(hass, entry):
    client = MagicMock()
    client.refresh.side_effect = InvalidCredentials("expired")
    manager = ProtonSessionManager(hass, entry, client=client)
    with pytest.raises(ConfigEntryAuthFailed):
        await manager.async_refresh()


@pytest.mark.asyncio
async def test_async_setup_refreshes_and_schedules(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    client.data = _session(access_token="access-new", refresh_token="refresh-new")
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    await manager.async_setup()
    assert manager.data.access_token == "access-new"
    assert hass.config_entries.async_update_entry.called
    assert len(hass.data["_interval_callbacks"]) == 1
    action, interval = hass.data["_interval_callbacks"][0]
    assert interval == timedelta(hours=1)
    await manager.async_unload()
    assert hass.data["_interval_callbacks"] == []
    await manager.async_unload()  # idempotent when already unloaded


@pytest.mark.asyncio
async def test_scheduled_refresh_invokes_refresh(hass, entry):
    client = MagicMock()
    client.refresh.return_value = _session(
        access_token="access-new", refresh_token="refresh-new"
    )
    manager = ProtonSessionManager(hass, entry, client=client)
    await manager._async_scheduled_refresh()
    client.refresh.assert_called_once()
