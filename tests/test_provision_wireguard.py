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
    DEFAULT_WG_DEVICE_NAME,
)
from proton_mikrotik_wg.proton_auth import ProtonSessionData
from proton_mikrotik_wg.session_manager import ProtonSessionManager
from proton_mikrotik_wg.wg_credentials import WireGuardCredential


def _entry():
    return SimpleNamespace(
        entry_id="abc",
        data={
            CONF_USERNAME: "user@proton.me",
            CONF_UID: "uid-1",
            CONF_ACCESS_TOKEN: "access-1",
            CONF_REFRESH_TOKEN: "refresh-1",
            CONF_SCOPE: ["full"],
        },
    )


def _cred(**overrides):
    base = dict(
        device_name=DEFAULT_WG_DEVICE_NAME,
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
async def test_async_provision_wireguard_uses_ha_device_name(hass):
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
    cred = _cred()

    with patch(
        "proton_mikrotik_wg.session_manager.provision_wireguard_credential",
        return_value=cred,
    ) as provision:
        result = await manager.async_provision_wireguard()

    assert result is cred
    provision.assert_called_once()
    device_name = provision.call_args.kwargs["device_name"]
    assert device_name.startswith("ha-wg-proton-")
    assert device_name != DEFAULT_WG_DEVICE_NAME
    suffix = device_name.removeprefix("ha-wg-proton-")
    assert len(suffix) == 15 and suffix[8] == "-" and suffix.replace("-", "").isdigit()
    hass.config_entries.async_update_entry.assert_called_once()
    updated = hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert updated[CONF_WG_DEVICE_NAME] == DEFAULT_WG_DEVICE_NAME
    assert updated[CONF_WG_SERIAL_NUMBER] == "sn-1"
    assert updated[CONF_WG_CLIENT_PRIVATE_KEY] == "client-sk=="
    assert updated[CONF_WG_ENDPOINT_HOST] == "1.2.3.4"
    assert updated[CONF_WG_ENDPOINT_PORT] == 51820
    assert updated[CONF_WG_SERVER_PUBLIC_KEY] == "server-pk=="
    assert updated[CONF_WG_CLIENT_PUBLIC_KEY] == "client-pk=="
    assert updated[CONF_WG_CLIENT_ADDRESS] == "10.2.0.2/32"
    assert updated[CONF_WG_EXPIRATION_TIME] == 1_700_000_000
    # Session tokens preserved.
    assert updated[CONF_ACCESS_TOKEN] == "access-1"


@pytest.mark.asyncio
async def test_async_provision_wireguard_allows_custom_ha_name(hass):
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
        "proton_mikrotik_wg.session_manager.provision_wireguard_credential",
        return_value=_cred(device_name="ha-router"),
    ) as provision:
        await manager.async_provision_wireguard(device_name="ha-router")

    assert provision.call_args.kwargs["device_name"] == "ha-router"


@pytest.mark.asyncio
async def test_async_provision_wireguard_rejects_non_ha_prefix(hass):
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
    with pytest.raises(ValueError, match="ha-"):
        await manager.async_provision_wireguard(device_name="router-1")
