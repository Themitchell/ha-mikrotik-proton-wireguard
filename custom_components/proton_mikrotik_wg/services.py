"""Home Assistant services for Proton MikroTik WireGuard."""

from __future__ import annotations

import logging
from typing import Any, NoReturn

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError

from .const import (
    DOMAIN,
    MAX_TUNNEL_COUNT,
    MIN_TUNNEL_COUNT,
    SERVICE_APPLY_WIREGUARD,
    SERVICE_PROVISION_WIREGUARD,
)

_LOGGER = logging.getLogger(__name__)

SERVICE_PROVISION_SCHEMA = vol.Schema(
    {
        vol.Optional("slot"): vol.All(
            vol.Coerce(int), vol.Range(min=MIN_TUNNEL_COUNT, max=MAX_TUNNEL_COUNT)
        ),
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
            raise HomeAssistantError(f"No Proton MikroTik WG entry id={entry_id}")
        return manager
    if not managers:
        raise HomeAssistantError("Proton MikroTik WG is not configured")
    return next(iter(managers.values()))


def _reraise_service_error(action: str, err: Exception) -> NoReturn:
    """Log and raise a user-visible Home Assistant error."""
    if isinstance(err, HomeAssistantError):
        raise err
    _LOGGER.exception("%s failed", action)
    raise HomeAssistantError(str(err)) from err


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register domain services once."""
    if hass.services.has_service(DOMAIN, SERVICE_PROVISION_WIREGUARD):
        return

    async def handle_provision(call: ServiceCall) -> None:
        slot = call.data.get("slot")
        try:
            manager = _manager_from_call(hass, call)
            slots = await manager.async_provision_wireguard(slot=slot)
        except Exception as err:  # noqa: BLE001 — surface any Proton/local failure
            _reraise_service_error("provision_wireguard", err)
        _LOGGER.info(
            "Provisioned %s Proton WireGuard slot(s): %s",
            len(slots),
            ", ".join(
                f"{n}={cred.device_name}@{cred.endpoint_host}"
                for n, cred in sorted(slots.items())
            ),
        )

    async def handle_apply(call: ServiceCall) -> None:
        try:
            manager = _manager_from_call(hass, call)
            slots = await manager.async_apply_wireguard()
        except Exception as err:  # noqa: BLE001 — surface any Proton/local failure
            _reraise_service_error("apply_wireguard", err)
        _LOGGER.info(
            "Applied %s Proton WireGuard tunnel(s) to MikroTik: %s",
            len(slots),
            ", ".join(
                f"wg-proton-{n}@{cred.endpoint_host}"
                for n, cred in sorted(slots.items())
            ),
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
