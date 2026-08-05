"""Tests for WireGuard provision via session manager."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_TUNNEL_COUNT,
    CONF_UID,
    CONF_USERNAME,
    CONF_WG_SLOTS,
    DEFAULT_WG_DEVICE_NAME,
)
from proton_mikrotik_wg.proton_auth import ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager
from proton_mikrotik_wg.wg_credentials import WireGuardCredential


def _entry(options=None):
    return SimpleNamespace(
        entry_id="abc",
        data={
            CONF_USERNAME: "user@proton.me",
            CONF_UID: "uid-1",
            CONF_ACCESS_TOKEN: "access-1",
            CONF_REFRESH_TOKEN: "refresh-1",
            CONF_SCOPE: ["full"],
        },
        options=options if options is not None else {CONF_TUNNEL_COUNT: 2},
    )


def _cred(**overrides):
    base = dict(
        device_name="ha-wg-proton-1-stamp",
        serial_number="sn-1",
        client_private_key="client-sk==",
        client_public_key="client-pk==",
        server_public_key="server-pk==",
        endpoint_host="1.2.3.4",
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=1_700_000_000,
        dns=None,
    )
    base.update(overrides)
    return WireGuardCredential(**base)


@pytest.mark.asyncio
async def test_async_provision_wireguard_stores_slots(hass):
    entry = _entry()
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
    live = MagicMock()
    client.live_session.return_value = live
    client.data = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full",),
    )
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    slots = {
        1: _cred(),
        2: _cred(
            device_name="ha-wg-proton-2-stamp",
            serial_number="sn-2",
            endpoint_host="2.2.2.2",
        ),
    }

    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ) as provision:
        result = await manager.async_provision_wireguard()

    assert result is slots
    provision.assert_called_once()
    assert provision.call_args.kwargs["count"] == 2
    assert provision.call_args.kwargs["slot"] is None
    data_calls = [
        c.kwargs["data"]
        for c in hass.config_entries.async_update_entry.call_args_list
        if "data" in c.kwargs
    ]
    assert len(data_calls) == 1
    updated = data_calls[0]
    assert CONF_WG_SLOTS in updated
    assert len(updated[CONF_WG_SLOTS]) == 2
    assert updated[CONF_ACCESS_TOKEN] == "access-1"
    options_calls = [
        c.kwargs["options"]
        for c in hass.config_entries.async_update_entry.call_args_list
        if "options" in c.kwargs
    ]
    assert options_calls
    assert "wg_refresh_last_at" in options_calls[-1]


@pytest.mark.asyncio
async def test_async_provision_wireguard_one_slot(hass):
    entry = _entry()
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
    client.live_session.return_value = MagicMock()
    client.data = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full",),
    )
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value={1: _cred()},
    ) as provision:
        await manager.async_provision_wireguard(slot=1)
    assert provision.call_args.kwargs["slot"] == 1
