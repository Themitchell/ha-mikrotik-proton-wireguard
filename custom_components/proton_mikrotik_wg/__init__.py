"""Proton MikroTik WireGuard Home Assistant integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .const import DOMAIN
from .services import async_setup_services, async_unload_services
from .session_manager import ProtonSessionManager

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

PLATFORMS: list[str] = ["switch", "sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Proton session management from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    manager = ProtonSessionManager(hass, entry)
    await manager.async_setup()
    hass.data[DOMAIN][entry.entry_id] = manager
    await async_setup_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and stop session refresh."""
    manager = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if manager is not None:
        await manager.async_unload()
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        await async_unload_services(hass)
    return unload_ok
