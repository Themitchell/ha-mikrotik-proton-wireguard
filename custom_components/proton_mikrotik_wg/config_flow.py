"""Config flow for Proton MikroTik WireGuard setup."""

from __future__ import annotations

from typing import Any

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_PASSWORD, CONF_USERNAME, DOMAIN
from .schemas import PROTON_CREDENTIALS_SCHEMA


class ProtonMikroTikWgConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the initial setup of the integration."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for Proton VPN account credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_USERNAME].lower())
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=f"Proton VPN ({user_input[CONF_USERNAME]})",
                data={
                    CONF_USERNAME: user_input[CONF_USERNAME],
                    CONF_PASSWORD: user_input[CONF_PASSWORD],
                },
            )

        return self.async_show_form(
            step_id="user",
            data_schema=PROTON_CREDENTIALS_SCHEMA,
            errors=errors,
        )
