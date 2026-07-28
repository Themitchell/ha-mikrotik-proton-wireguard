"""Config flow for Proton MikroTik WireGuard setup."""

from __future__ import annotations

from typing import Any

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    CONF_SCOPE,
    CONF_TOTP,
    CONF_UID,
    CONF_USERNAME,
    DOMAIN,
)
from .proton_auth import (
    InvalidCredentials,
    ProtonSessionData,
    TwoFactorRequired,
    default_session_factory,
    login_with_password,
    submit_two_factor,
)
from .schemas import PROTON_CREDENTIALS_SCHEMA, PROTON_TWO_FACTOR_SCHEMA


def _entry_data(session: ProtonSessionData) -> dict[str, Any]:
    return {
        CONF_USERNAME: session.username,
        CONF_UID: session.uid,
        CONF_ACCESS_TOKEN: session.access_token,
        CONF_REFRESH_TOKEN: session.refresh_token,
        CONF_SCOPE: list(session.scope),
    }


class ProtonMikroTikWgConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle Proton login (and 2FA) during integration setup."""

    VERSION = 1

    def __init__(self) -> None:
        super().__init__()
        self._username: str | None = None
        self._pending_session: Any = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for Proton account credentials and verify login."""
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]
            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            try:
                session_data = await self.hass.async_add_executor_job(
                    lambda: login_with_password(
                        username,
                        password,
                        create_session=default_session_factory,
                    )
                )
            except TwoFactorRequired as err:
                self._username = username
                self._pending_session = err.session
                return await self.async_step_two_factor()
            except InvalidCredentials:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"Proton VPN ({username})",
                    data=_entry_data(session_data),
                )

        return self.async_show_form(
            step_id="user",
            data_schema=PROTON_CREDENTIALS_SCHEMA,
            errors=errors,
        )

    async def async_step_two_factor(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for TOTP after password authentication succeeds."""
        errors: dict[str, str] = {}

        if user_input is not None:
            assert self._pending_session is not None
            assert self._username is not None
            try:
                session_data = await self.hass.async_add_executor_job(
                    lambda: submit_two_factor(
                        self._pending_session,
                        user_input[CONF_TOTP],
                        username=self._username,
                    )
                )
            except InvalidCredentials:
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"Proton VPN ({self._username})",
                    data=_entry_data(session_data),
                )

        return self.async_show_form(
            step_id="two_factor",
            data_schema=PROTON_TWO_FACTOR_SCHEMA,
            errors=errors,
        )
