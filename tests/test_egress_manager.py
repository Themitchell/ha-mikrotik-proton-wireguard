"""Tests for egress enable/disable via session manager."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg.const import (
    CONF_EGRESS_ENABLED,
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
)
from proton_mikrotik_wg.proton_auth import ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager


def _mikrotik_options(**overrides):
    options = {
        CONF_MIKROTIK_HOST: "mikrotik.lan",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_PORT: 8729,
        CONF_MIKROTIK_USE_SSL: True,
        CONF_MIKROTIK_WAN_GATEWAY: "zen",
    }
    options.update(overrides)
    return options


def _entry(options=None, data=None):
    return SimpleNamespace(
        entry_id="abc",
        data=data
        if data is not None
        else {
            "username": "user@proton.me",
            "uid": "uid-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "scope": ["full"],
            "wg_device_name": "ha-wg-proton",
            "wg_serial_number": "sn-1",
            "wg_client_private_key": "sk==",
            "wg_client_public_key": "pk==",
            "wg_server_public_key": "spk==",
            "wg_endpoint_host": "1.2.3.4",
            "wg_endpoint_port": 51820,
            "wg_client_address": "10.2.0.2/32",
            "wg_expiration_time": 1,
        },
        options=options if options is not None else _mikrotik_options(),
    )


@pytest.mark.asyncio
async def test_async_set_egress_enable_and_persist(hass):
    entry = _entry()
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
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
    wrapper = MagicMock()

    with (
        patch(
            "proton_mikrotik_wg.session_manager.open_mikrotik_api",
            return_value=MagicMock(),
        ),
        patch(
            "proton_mikrotik_wg.session_manager.LibRouterOsClient",
            return_value=wrapper,
        ),
        patch("proton_mikrotik_wg.session_manager.enable_egress") as enable,
    ):
        await manager.async_set_egress(True)

    enable.assert_called_once()
    assert enable.call_args.kwargs["wan_interface"] == "zen"
    assert 1 in enable.call_args.kwargs["slots"]
    assert enable.call_args.kwargs["bypass_cidrs"] == []
    wrapper.close.assert_called_once()
    updated = hass.config_entries.async_update_entry.call_args.kwargs["options"]
    assert updated[CONF_EGRESS_ENABLED] is True


@pytest.mark.asyncio
async def test_async_set_egress_passes_parsed_bypass_cidrs(hass):
    from proton_mikrotik_wg.const import CONF_VPN_BYPASS_CIDRS

    entry = _entry(
        options=_mikrotik_options(
            **{CONF_VPN_BYPASS_CIDRS: "10.0.5.50\n# radiators\n10.0.30.0/24"}
        )
    )
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
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

    with (
        patch(
            "proton_mikrotik_wg.session_manager.open_mikrotik_api",
            return_value=MagicMock(),
        ),
        patch(
            "proton_mikrotik_wg.session_manager.LibRouterOsClient",
            return_value=MagicMock(),
        ),
        patch("proton_mikrotik_wg.session_manager.enable_egress") as enable,
    ):
        await manager.async_set_egress(True)

    assert enable.call_args.kwargs["bypass_cidrs"] == [
        "10.0.5.50/32",
        "10.0.30.0/24",
    ]


@pytest.mark.asyncio
async def test_async_set_egress_disable(hass):
    entry = _entry()
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    with (
        patch(
            "proton_mikrotik_wg.session_manager.open_mikrotik_api",
            return_value=MagicMock(),
        ),
        patch(
            "proton_mikrotik_wg.session_manager.LibRouterOsClient",
            return_value=MagicMock(),
        ),
        patch("proton_mikrotik_wg.session_manager.disable_egress") as disable,
    ):
        await manager.async_set_egress(False)
    disable.assert_called_once()


@pytest.mark.asyncio
async def test_async_get_egress_enabled(hass):
    entry = _entry()
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    manager = ProtonSessionManager(
        hass, entry, client=MagicMock(), refresh_interval=timedelta(hours=1)
    )
    with (
        patch(
            "proton_mikrotik_wg.session_manager.open_mikrotik_api",
            return_value=MagicMock(),
        ),
        patch(
            "proton_mikrotik_wg.session_manager.LibRouterOsClient",
            return_value=MagicMock(),
        ),
        patch(
            "proton_mikrotik_wg.session_manager.is_egress_enabled",
            return_value=True,
        ),
    ):
        assert await manager.async_get_egress_enabled() is True


@pytest.mark.asyncio
async def test_async_set_egress_requires_mikrotik(hass):
    entry = _entry(options={})
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    manager = ProtonSessionManager(
        hass, entry, client=MagicMock(), refresh_interval=timedelta(hours=1)
    )
    with pytest.raises(ValueError, match="MikroTik"):
        await manager.async_set_egress(True)


@pytest.mark.asyncio
async def test_async_set_egress_requires_provisioned_slots(hass):
    entry = _entry(
        data={
            "username": "user@proton.me",
            "uid": "uid-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "scope": ["full"],
        }
    )
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    manager = ProtonSessionManager(
        hass, entry, client=MagicMock(), refresh_interval=timedelta(hours=1)
    )
    with pytest.raises(ValueError, match="not provisioned"):
        await manager.async_set_egress(True)


@pytest.mark.asyncio
async def test_async_provision_drops_legacy_flat_keys(hass):
    entry = _entry()
    entry.data = {
        **entry.data,
        "wg_serial_number": "legacy",
        "wg_device_name": "ha-wg-proton",
        "wg_client_private_key": "x",
        "wg_client_public_key": "x",
        "wg_server_public_key": "x",
        "wg_endpoint_host": "1.1.1.1",
        "wg_endpoint_port": 51820,
        "wg_client_address": "10.2.0.2/32",
        "wg_expiration_time": 1,
    }
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
    client.data = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full",),
    )
    client.live_session.return_value = MagicMock()
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    from proton_mikrotik_wg.wg_credentials import WireGuardCredential

    slots = {
        1: WireGuardCredential(
            device_name="ha-wg-proton-1-x",
            serial_number="sn-new",
            client_private_key="sk==",
            client_public_key="pk==",
            server_public_key="spk==",
            endpoint_host="9.9.9.9",
            endpoint_port=51820,
            client_address="10.2.0.2/32",
            expiration_time=1,
        )
    }
    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_slots",
        return_value=slots,
    ):
        await manager.async_provision_wireguard()
    data_calls = [
        c.kwargs["data"]
        for c in hass.config_entries.async_update_entry.call_args_list
        if "data" in c.kwargs
    ]
    updated = data_calls[-1]
    assert "wg_serial_number" not in updated
    assert "wg_slots" in updated


@pytest.mark.asyncio
async def test_async_setup_reapplies_egress_when_option_set(hass):
    entry = _entry(options={**_mikrotik_options(), CONF_EGRESS_ENABLED: True})
    hass.config_entries = SimpleNamespace(async_update_entry=MagicMock())
    client = MagicMock()
    client.refresh.return_value = ProtonSessionData(
        username="user@proton.me",
        uid="uid-1",
        access_token="access-1",
        refresh_token="refresh-1",
        scope=("full",),
    )
    client.data = client.refresh.return_value
    manager = ProtonSessionManager(
        hass, entry, client=client, refresh_interval=timedelta(hours=1)
    )
    with (
        patch.object(manager, "async_set_egress", autospec=True) as set_egress,
        patch(
            "proton_mikrotik_wg.session_manager.async_track_time_interval",
            return_value=lambda: None,
        ),
    ):
        await manager.async_setup()
    set_egress.assert_awaited_once_with(True)
