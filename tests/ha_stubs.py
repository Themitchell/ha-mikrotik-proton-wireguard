"""Minimal Home Assistant stubs so integration modules import under pytest."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any


class FlowResultType:
    FORM = "form"
    CREATE_ENTRY = "create_entry"
    ABORT = "abort"


class AbortFlow(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConfigEntryAuthFailed(Exception):
    """Raised when stored Proton tokens can no longer be refreshed."""


class HomeAssistantError(Exception):
    """Raised for user-visible service/integration failures."""


class ConfigFlow:
    """Enough of HA ConfigFlow for unit-testing our steps."""

    def __init_subclass__(cls, *, domain: str | None = None, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.domain = domain

    def __init__(self) -> None:
        self.hass: Any = None
        self.unique_id: str | None = None
        self.context: dict[str, Any] = {}
        self._abort_configured = False

    async def async_set_unique_id(self, unique_id: str) -> None:
        self.unique_id = unique_id

    def _abort_if_unique_id_configured(self) -> None:
        if self._abort_configured:
            raise AbortFlow("already_configured")

    def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any = None,
        errors: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return {
            "type": FlowResultType.FORM,
            "step_id": step_id,
            "data_schema": data_schema,
            "errors": errors or {},
        }

    def async_create_entry(
        self, *, title: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "type": FlowResultType.CREATE_ENTRY,
            "title": title,
            "data": data,
        }

    def async_abort(self, *, reason: str) -> dict[str, Any]:
        return {"type": FlowResultType.ABORT, "reason": reason}

    def async_update_reload_and_abort(
        self,
        entry: Any,
        *,
        data: dict[str, Any],
        reason: str = "reauth_successful",
    ) -> dict[str, Any]:
        self.hass.config_entries.async_update_entry(entry, data=data)
        return self.async_abort(reason=reason)


class OptionsFlow:
    """Enough of HA OptionsFlow for unit-testing configure steps.

    Mirrors Home Assistant 2024.11+: ``config_entry`` is a read-only property.
    """

    def __init__(self) -> None:
        self.hass: Any = None
        self._config_entry: Any = None

    @property
    def config_entry(self) -> Any:
        return self._config_entry

    @config_entry.setter
    def config_entry(self, value: Any) -> None:
        raise AttributeError(
            "property 'config_entry' of 'OptionsFlow' object has no setter"
        )

    def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any = None,
        errors: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return {
            "type": FlowResultType.FORM,
            "step_id": step_id,
            "data_schema": data_schema,
            "errors": errors or {},
        }

    def async_create_entry(
        self, *, title: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "type": FlowResultType.CREATE_ENTRY,
            "title": title,
            "data": data,
        }


def install_homeassistant_stubs() -> None:
    """Register stub modules before importing the integration package."""
    ha = ModuleType("homeassistant")
    ha._pmw_stub = True  # type: ignore[attr-defined]

    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigFlow = ConfigFlow
    config_entries.OptionsFlow = OptionsFlow
    config_entries.ConfigEntry = SimpleNamespace

    data_entry_flow = ModuleType("homeassistant.data_entry_flow")
    data_entry_flow.FlowResult = dict
    data_entry_flow.AbortFlow = AbortFlow

    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object
    core.ServiceCall = SimpleNamespace

    exceptions = ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = ConfigEntryAuthFailed
    exceptions.HomeAssistantError = HomeAssistantError

    helpers = ModuleType("homeassistant.helpers")
    event = ModuleType("homeassistant.helpers.event")

    def async_track_time_interval(hass, action, interval):
        hass.data.setdefault("_interval_callbacks", []).append((action, interval))

        def _unsub():
            callbacks = hass.data.get("_interval_callbacks", [])
            hass.data["_interval_callbacks"] = [
                item for item in callbacks if item[0] is not action
            ]

        return _unsub

    event.async_track_time_interval = async_track_time_interval

    sys.modules["homeassistant"] = ha
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.data_entry_flow"] = data_entry_flow
    sys.modules["homeassistant.core"] = core
    sys.modules["homeassistant.exceptions"] = exceptions
    sys.modules["homeassistant.helpers"] = helpers
    sys.modules["homeassistant.helpers.event"] = event

    ha.config_entries = config_entries  # type: ignore[attr-defined]
    ha.data_entry_flow = data_entry_flow  # type: ignore[attr-defined]
    ha.core = core  # type: ignore[attr-defined]
    ha.exceptions = exceptions  # type: ignore[attr-defined]
    ha.helpers = helpers  # type: ignore[attr-defined]
    helpers.event = event  # type: ignore[attr-defined]

    components = ModuleType("homeassistant.components")
    switch_mod = ModuleType("homeassistant.components.switch")

    class SwitchEntity:
        """Minimal SwitchEntity stub."""

        _attr_name: str | None = None
        _attr_unique_id: str | None = None
        _attr_is_on: bool | None = None
        _attr_has_entity_name: bool = False
        hass: Any = None
        _writes: int = 0

        @property
        def name(self) -> str | None:
            return self._attr_name

        @property
        def unique_id(self) -> str | None:
            return self._attr_unique_id

        @property
        def is_on(self) -> bool | None:
            return self._attr_is_on

        def async_write_ha_state(self) -> None:
            self._writes += 1

    switch_mod.SwitchEntity = SwitchEntity
    sys.modules["homeassistant.components"] = components
    sys.modules["homeassistant.components.switch"] = switch_mod

    sensor_mod = ModuleType("homeassistant.components.sensor")

    class SensorEntity:
        """Minimal SensorEntity stub."""

        _attr_name: str | None = None
        _attr_unique_id: str | None = None
        _attr_native_value: Any = None
        _attr_extra_state_attributes: dict[str, Any] | None = None
        _attr_has_entity_name: bool = False
        _attr_entity_category: Any = None
        _attr_available: bool = True
        hass: Any = None
        _writes: int = 0

        @property
        def name(self) -> str | None:
            return self._attr_name

        @property
        def unique_id(self) -> str | None:
            return self._attr_unique_id

        @property
        def native_value(self) -> Any:
            return self._attr_native_value

        @property
        def extra_state_attributes(self) -> dict[str, Any] | None:
            return self._attr_extra_state_attributes

        @property
        def available(self) -> bool:
            return self._attr_available

        @property
        def entity_category(self) -> Any:
            return self._attr_entity_category

        def async_write_ha_state(self) -> None:
            self._writes += 1

    sensor_mod.SensorEntity = SensorEntity
    sys.modules["homeassistant.components.sensor"] = sensor_mod
    components.sensor = sensor_mod  # type: ignore[attr-defined]

    entity_helpers = ModuleType("homeassistant.helpers.entity")

    class EntityCategory:
        DIAGNOSTIC = "diagnostic"
        CONFIG = "config"

    entity_helpers.EntityCategory = EntityCategory
    sys.modules["homeassistant.helpers.entity"] = entity_helpers
    helpers.entity = entity_helpers  # type: ignore[attr-defined]

    ha.components = components  # type: ignore[attr-defined]
    components.switch = switch_mod  # type: ignore[attr-defined]


install_homeassistant_stubs()
