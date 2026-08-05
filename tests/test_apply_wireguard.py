"""Tests for applying stored WireGuard credentials to MikroTik."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from proton_mikrotik_wg.const import (
    CONF_ACCESS_TOKEN,
    CONF_MIKROTIK_HOST,
    CONF_MIKROTIK_PASSWORD,
    CONF_MIKROTIK_PORT,
    CONF_MIKROTIK_USERNAME,
    CONF_MIKROTIK_USE_SSL,
    CONF_MIKROTIK_WAN_GATEWAY,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_TUNNEL_COUNT,
    CONF_UID,
    CONF_USERNAME,
    CONF_WG_CLIENT_ADDRESS,
    CONF_WG_CLIENT_PRIVATE_KEY,
    CONF_WG_CLIENT_PUBLIC_KEY,
    CONF_WG_DEVICE_NAME,
    CONF_WG_ENDPOINT_HOST,
    CONF_WG_ENDPOINT_PORT,
    CONF_WG_EXPIRATION_TIME,
    CONF_WG_SERIAL_NUMBER,
    CONF_WG_SERVER_PUBLIC_KEY,
)
from proton_mikrotik_wg.mikrotik_wg import wireguard_credential_from_entry_data
from proton_mikrotik_wg.proton_auth import ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager


def _wg_data(**overrides):
    data = {
        CONF_USERNAME: "user@proton.me",
        CONF_UID: "uid-1",
        CONF_ACCESS_TOKEN: "access-1",
        CONF_REFRESH_TOKEN: "refresh-1",
        CONF_SCOPE: ["full"],
        CONF_WG_DEVICE_NAME: "ha-wg-proton",
        CONF_WG_SERIAL_NUMBER: "sn-1",
        CONF_WG_CLIENT_PRIVATE_KEY: "client-sk==",
        CONF_WG_CLIENT_PUBLIC_KEY: "client-pk==",
        CONF_WG_SERVER_PUBLIC_KEY: "server-pk==",
        CONF_WG_ENDPOINT_HOST: "1.2.3.4",
        CONF_WG_ENDPOINT_PORT: 51820,
        CONF_WG_CLIENT_ADDRESS: "10.2.0.2/32",
        CONF_WG_EXPIRATION_TIME: 1_700_000_000,
    }
    data.update(overrides)
    return data


def _mikrotik_options(**overrides):
    options = {
        CONF_MIKROTIK_HOST: "mikrotik.lan",
        CONF_MIKROTIK_USERNAME: "admin",
        CONF_MIKROTIK_PASSWORD: "secret",
        CONF_MIKROTIK_PORT: 8729,
        CONF_MIKROTIK_USE_SSL: True,
        CONF_MIKROTIK_WAN_GATEWAY: "192.0.2.1",
        CONF_TUNNEL_COUNT: 1,
    }
    options.update(overrides)
    return options


def test_wireguard_credential_from_entry_data():
    cred = wireguard_credential_from_entry_data(_wg_data())
    assert cred.device_name == "ha-wg-proton"
    assert cred.client_private_key == "client-sk=="
    assert cred.endpoint_host == "1.2.3.4"
    assert cred.endpoint_port == 51820
    assert cred.dns is None


def test_wireguard_credential_from_entry_data_requires_fields():
    with pytest.raises(ValueError, match="WireGuard credential"):
        wireguard_credential_from_entry_data({CONF_USERNAME: "x"})


@pytest.mark.asyncio
async def test_async_apply_wireguard_calls_slot_apply(hass):
    entry = SimpleNamespace(entry_id="abc", data=_wg_data(), options=_mikrotik_options())
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
    api = MagicMock()
    wrapper = MagicMock()

    with (
        patch(
            "proton_mikrotik_wg.session_manager.open_mikrotik_api",
            return_value=api,
        ) as open_api,
        patch(
            "proton_mikrotik_wg.session_manager.apply_wireguard_slots",
        ) as apply,
        patch(
            "proton_mikrotik_wg.session_manager.LibRouterOsClient",
            return_value=wrapper,
        ),
    ):
        result = await manager.async_apply_wireguard()

    assert list(result.keys()) == [1]
    assert result[1].device_name == "ha-wg-proton"
    open_api.assert_called_once()
    apply.assert_called_once()
    assert apply.call_args.args[0] is wrapper
    assert apply.call_args.kwargs["wan_gateway"] == "192.0.2.1"
    assert apply.call_args.kwargs["tunnel_count"] == 1
    wrapper.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_apply_wireguard_requires_mikrotik_options(hass):
    entry = SimpleNamespace(entry_id="abc", data=_wg_data(), options={})
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
    with pytest.raises(ValueError, match="MikroTik"):
        await manager.async_apply_wireguard()
