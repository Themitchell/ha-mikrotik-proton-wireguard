"""Home Assistant services for Proton MikroTik WireGuard."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall

from .const import (
    DEFAULT_WG_DEVICE_NAME,
    DOMAIN,
    SERVICE_APPLY_WIREGUARD,
    SERVICE_PROVISION_WIREGUARD,
)

_LOGGER = logging.getLogger(__name__)

SERVICE_PROVISION_SCHEMA = vol.Schema(
    {
        vol.Optional("device_name", default=DEFAULT_WG_DEVICE_NAME): str,
        vol.Optional("entry_id"): str,
    }
)

SERVICE_APPLY_SCHEMA = vol.Schema(
    {
        vol.Optional("entry_id"): str,
    }
)


def _manager_from_call(hass: HomeAssistant, call: ServiceCall) -> Any:
    entry_id = call.data.get("entry_id")
    managers: dict[str, Any] = hass.data.get(DOMAIN, {})
    if entry_id:
        manager = managers.get(entry_id)
        if manager is None:
            raise ValueError(f"No Proton MikroTik WG entry id={entry_id}")
        return manager
    if not managers:
        raise ValueError("Proton MikroTik WG is not configured")
    return next(iter(managers.values()))


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register domain services once."""
    if hass.services.has_service(DOMAIN, SERVICE_PROVISION_WIREGUARD):
        return

    async def handle_provision(call: ServiceCall) -> None:
        device_name = call.data.get("device_name", DEFAULT_WG_DEVICE_NAME)
        manager = _manager_from_call(hass, call)
        cred = await manager.async_provision_wireguard(device_name=device_name)
        _LOGGER.info(
            "Provisioned Proton WireGuard device %s (serial %s) endpoint %s:%s",
            cred.device_name,
            cred.serial_number,
            cred.endpoint_host,
            cred.endpoint_port,
        )

    async def handle_apply(call: ServiceCall) -> None:
        manager = _manager_from_call(hass, call)
        cred = await manager.async_apply_wireguard()
        _LOGGER.info(
            "Applied Proton WireGuard tunnel-only config for %s to MikroTik "
            "(endpoint %s:%s)",
            cred.device_name,
            cred.endpoint_host,
            cred.endpoint_port,
        )

    hass.services.async_register(
        DOMAIN,
        SERVICE_PROVISION_WIREGUARD,
        handle_provision,
        schema=SERVICE_PROVISION_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_APPLY_WIREGUARD,
        handle_apply,
        schema=SERVICE_APPLY_SCHEMA,
    )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Remove domain services when the last entry unloads."""
    if hass.data.get(DOMAIN):
        return
    if hass.services.has_service(DOMAIN, SERVICE_PROVISION_WIREGUARD):
        hass.services.async_remove(DOMAIN, SERVICE_PROVISION_WIREGUARD)
    if hass.services.has_service(DOMAIN, SERVICE_APPLY_WIREGUARD):
        hass.services.async_remove(DOMAIN, SERVICE_APPLY_WIREGUARD)
