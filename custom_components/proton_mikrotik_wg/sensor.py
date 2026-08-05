"""Diagnostic sensors for Proton WireGuard tunnel slots."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.entity import EntityCategory

from .const import DOMAIN
from .wg_slots import slots_from_entry_data

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .session_manager import ProtonSessionManager
    from .wg_credentials import WireGuardCredential


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one diagnostic sensor per provisioned WireGuard slot."""
    manager: ProtonSessionManager = hass.data[DOMAIN][entry.entry_id]
    sensors: dict[int, ProtonWgSlotSensor] = {}

    def _desired_slots() -> set[int]:
        count = manager.tunnel_count()
        return {slot for slot in slots_from_entry_data(manager.entry.data) if slot <= count}

    async def _async_sync_sensors() -> None:
        desired = _desired_slots()
        new_entities = [
            ProtonWgSlotSensor(manager, slot)
            for slot in sorted(desired - set(sensors))
        ]
        for entity in new_entities:
            sensors[entity.slot] = entity
        if new_entities:
            result = async_add_entities(new_entities)
            if hasattr(result, "__await__"):
                await result  # type: ignore[misc]
        for entity in sensors.values():
            entity.async_write_ha_state()

    await _async_sync_sensors()

    async def _async_entry_updated(
        _hass: HomeAssistant, _entry: ConfigEntry
    ) -> None:
        await _async_sync_sensors()

    entry.async_on_unload(entry.add_update_listener(_async_entry_updated))


class ProtonWgSlotSensor(SensorEntity):
    """Show Proton logical server name and refresh metadata for one slot."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, manager: ProtonSessionManager, slot: int) -> None:
        self._manager = manager
        self.slot = slot
        self._attr_name = f"Proton WG tunnel {slot}"
        self._attr_unique_id = f"{manager.entry.entry_id}_wg_slot_{slot}"

    def _credential(self) -> WireGuardCredential | None:
        count = self._manager.tunnel_count()
        if self.slot > count:
            return None
        return slots_from_entry_data(self._manager.entry.data).get(self.slot)

    @property
    def available(self) -> bool:
        """Only available while the slot is within count and provisioned."""
        return self._credential() is not None

    @property
    def native_value(self) -> str:
        """Proton logical server name, or unknown until the slot is renewed."""
        cred = self._credential()
        if cred is None or not cred.server_name:
            return "unknown"
        return cred.server_name

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Device label, endpoint, and last refresh metadata."""
        cred = self._credential()
        attrs: dict[str, Any] = {"slot": self.slot}
        if cred is None:
            return attrs
        attrs.update(
            {
                "device_name": cred.device_name,
                "endpoint_host": cred.endpoint_host,
                "endpoint_port": cred.endpoint_port,
                "serial_number": cred.serial_number,
            }
        )
        if cred.provisioned_at:
            attrs["provisioned_at"] = datetime.fromtimestamp(
                cred.provisioned_at, tz=timezone.utc
            ).isoformat()
        return attrs
