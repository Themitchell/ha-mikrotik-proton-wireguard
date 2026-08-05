"""Switch platform for whole-home Proton VPN egress."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.components.switch import SwitchEntity

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .session_manager import ProtonSessionManager


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the VPN egress switch for a config entry."""
    manager: ProtonSessionManager = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([ProtonVpnEgressSwitch(manager)])


class ProtonVpnEgressSwitch(SwitchEntity):
    """Turn whole-home Proton WireGuard egress on or off."""

    _attr_name = "Proton VPN egress"
    _attr_has_entity_name = True

    def __init__(self, manager: ProtonSessionManager) -> None:
        self._manager = manager
        self._attr_unique_id = f"{manager.entry.entry_id}_egress"
        self._attr_is_on = bool(manager.entry.options.get("egress_enabled", False))

    async def async_added_to_hass(self) -> None:
        """Refresh on/off state from the router when possible."""
        try:
            self._attr_is_on = await self._manager.async_get_egress_enabled()
        except ValueError:
            # MikroTik not configured yet.
            self._attr_is_on = False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable VPN egress on the MikroTik."""
        await self._manager.async_set_egress(True)
        self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable VPN egress and restore ISP default routing."""
        await self._manager.async_set_egress(False)
        self._attr_is_on = False
        self.async_write_ha_state()
