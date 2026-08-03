"""Tests for provision_wireguard Home Assistant service."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from proton_mikrotik_wg.const import (
    DEFAULT_WG_DEVICE_NAME,
    DOMAIN,
    SERVICE_PROVISION_WIREGUARD,
)
from proton_mikrotik_wg.services import async_setup_services, async_unload_services
from proton_mikrotik_wg.wg_credentials import WireGuardCredential


def _cred():
    return WireGuardCredential(
        device_name=DEFAULT_WG_DEVICE_NAME,
        serial_number="sn-1",
        client_private_key="sk==",
        client_public_key="pk==",
        server_public_key="spk==",
        endpoint_host="1.2.3.4",
        endpoint_port=51820,
        client_address="10.2.0.2/32",
        expiration_time=1,
        dns=None,
    )


@pytest.mark.asyncio
async def test_setup_services_registers_provision_handler():
    hass = MagicMock()
    hass.services.has_service = MagicMock(return_value=False)
    hass.services.async_register = MagicMock()
    await async_setup_services(hass)
    hass.services.async_register.assert_called_once()
    args = hass.services.async_register.call_args.args
    assert args[0] == DOMAIN
    assert args[1] == SERVICE_PROVISION_WIREGUARD


@pytest.mark.asyncio
async def test_setup_services_is_idempotent():
    hass = MagicMock()
    hass.services.has_service = MagicMock(return_value=True)
    hass.services.async_register = MagicMock()
    await async_setup_services(hass)
    hass.services.async_register.assert_not_called()


@pytest.mark.asyncio
async def test_provision_service_calls_manager():
    hass = MagicMock()
    manager = MagicMock()
    manager.async_provision_wireguard = AsyncMock(return_value=_cred())
    hass.data = {DOMAIN: {"abc": manager}}
    hass.services.has_service = MagicMock(return_value=False)

    registered = {}

    def capture(domain, service, handler, schema=None):
        registered["handler"] = handler

    hass.services.async_register = capture
    await async_setup_services(hass)

    call = SimpleNamespace(data={})
    await registered["handler"](call)
    manager.async_provision_wireguard.assert_awaited_once_with(
        device_name=DEFAULT_WG_DEVICE_NAME
    )


@pytest.mark.asyncio
async def test_provision_service_rejects_unknown_entry():
    hass = MagicMock()
    hass.data = {DOMAIN: {}}
    hass.services.has_service = MagicMock(return_value=False)
    registered = {}
    hass.services.async_register = lambda d, s, h, schema=None: registered.update(
        handler=h
    )
    await async_setup_services(hass)
    with pytest.raises(ValueError, match="No Proton"):
        await registered["handler"](SimpleNamespace(data={"entry_id": "missing"}))


@pytest.mark.asyncio
async def test_provision_service_uses_explicit_entry_id():
    hass = MagicMock()
    manager = MagicMock()
    manager.async_provision_wireguard = AsyncMock(return_value=_cred())
    hass.data = {DOMAIN: {"abc": manager, "other": MagicMock()}}
    hass.services.has_service = MagicMock(return_value=False)
    registered = {}
    hass.services.async_register = lambda d, s, h, schema=None: registered.update(
        handler=h
    )
    await async_setup_services(hass)
    await registered["handler"](
        SimpleNamespace(data={"entry_id": "abc", "device_name": "ha-custom"})
    )
    manager.async_provision_wireguard.assert_awaited_once_with(device_name="ha-custom")


@pytest.mark.asyncio
async def test_provision_service_rejects_when_not_configured():
    hass = MagicMock()
    hass.data = {}
    hass.services.has_service = MagicMock(return_value=False)
    registered = {}
    hass.services.async_register = lambda d, s, h, schema=None: registered.update(
        handler=h
    )
    await async_setup_services(hass)
    with pytest.raises(ValueError, match="not configured"):
        await registered["handler"](SimpleNamespace(data={}))


@pytest.mark.asyncio
async def test_unload_services_removes_when_no_entries():
    hass = MagicMock()
    hass.data = {DOMAIN: {}}
    hass.services.has_service = MagicMock(return_value=True)
    hass.services.async_remove = MagicMock()
    await async_unload_services(hass)
    hass.services.async_remove.assert_called_once_with(
        DOMAIN, SERVICE_PROVISION_WIREGUARD
    )


@pytest.mark.asyncio
async def test_unload_services_noop_when_service_missing():
    hass = MagicMock()
    hass.data = {DOMAIN: {}}
    hass.services.has_service = MagicMock(return_value=False)
    hass.services.async_remove = MagicMock()
    await async_unload_services(hass)
    hass.services.async_remove.assert_not_called()


@pytest.mark.asyncio
async def test_unload_services_keeps_service_when_entries_remain():
    hass = MagicMock()
    hass.data = {DOMAIN: {"abc": object()}}
    hass.services.has_service = MagicMock(return_value=True)
    hass.services.async_remove = MagicMock()
    await async_unload_services(hass)
    hass.services.async_remove.assert_not_called()
