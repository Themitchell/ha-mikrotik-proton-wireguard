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


class ConfigFlow:
    """Enough of HA ConfigFlow for unit-testing our steps."""

    def __init_subclass__(cls, *, domain: str | None = None, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.domain = domain

    def __init__(self) -> None:
        self.hass: Any = None
        self.unique_id: str | None = None
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


def install_homeassistant_stubs() -> None:
    """Register stub modules before importing the integration package."""
    if "homeassistant" in sys.modules and getattr(
        sys.modules["homeassistant"], "_pmw_stub", False
    ):
        return

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

    sys.modules["homeassistant"] = ha
    sys.modules["homeassistant.config_entries"] = config_entries
    sys.modules["homeassistant.data_entry_flow"] = data_entry_flow
    sys.modules["homeassistant.core"] = core

    ha.config_entries = config_entries  # type: ignore[attr-defined]
    ha.data_entry_flow = data_entry_flow  # type: ignore[attr-defined]
    ha.core = core  # type: ignore[attr-defined]


install_homeassistant_stubs()
