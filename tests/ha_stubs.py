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


def install_homeassistant_stubs() -> None:
    """Register stub modules before importing the integration package."""
    ha = ModuleType("homeassistant")
    ha._pmw_stub = True  # type: ignore[attr-defined]

    config_entries = ModuleType("homeassistant.config_entries")
    config_entries.ConfigFlow = ConfigFlow
    config_entries.ConfigEntry = SimpleNamespace

    data_entry_flow = ModuleType("homeassistant.data_entry_flow")
    data_entry_flow.FlowResult = dict
    data_entry_flow.AbortFlow = AbortFlow

    core = ModuleType("homeassistant.core")
    core.HomeAssistant = object

    exceptions = ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = ConfigEntryAuthFailed

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


install_homeassistant_stubs()
